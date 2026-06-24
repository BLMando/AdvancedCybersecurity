use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::convert::TryInto;
use serde::Serialize;

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(MongoAuthzRoot) });
}

struct MongoAuthzRoot;

impl Context for MongoAuthzRoot {}

impl RootContext for MongoAuthzRoot {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::StreamContext)
    }

    fn create_stream_context(&self, context_id: u32) -> Option<Box<dyn StreamContext>> {
        Some(Box::new(MongoAuthzStream {
            context_id,
            buffer: Vec::new(),
            is_authorized: false,
            opa_token: None,
            session_jti: None,
            pending_user: String::new(),
            pending_command: String::new(),
            pending_collection: String::new(),
            pending_query_preview: String::new(),
        }))
    }

    fn on_vm_start(&mut self, _vm_configuration_size: usize) -> bool {
        log::info!("Mongo OP_MSG Authz VM started (continuous-mediation mode)");
        true
    }
}

struct MongoAuthzStream {
    context_id: u32,
    buffer: Vec<u8>,
    is_authorized: bool,
    opa_token: Option<u32>,
    /// JTI (JWT ID) extracted from the MONGODB-OIDC saslStart message.
    /// Cached for the lifetime of the TCP connection and forwarded to OPA
    /// on every subsequent command so OPA can check the per-token denylist.
    session_jti: Option<String>,
    // Fields cached so the audit log line is complete when OPA responds.
    pending_user: String,
    pending_command: String,
    pending_collection: String,
    pending_query_preview: String,
}

impl Context for MongoAuthzStream {
    fn on_http_call_response(&mut self, token_id: u32, _num_headers: usize, body_size: usize, _num_trailers: usize) {
        if Some(token_id) != self.opa_token {
            return;
        }
        self.opa_token = None;

        let mut allowed = false;

        if let Some(body) = self.get_http_call_response_body(0, body_size) {
            if let Ok(opa_resp) = serde_json::from_slice::<OpaResponse>(&body) {
                log::info!("[ctx={}] OPA decision: {:?}", self.context_id, opa_resp);
                allowed = opa_resp.result;
            } else {
                log::warn!("[ctx={}] OPA response malformed: {:?}", self.context_id, body);
            }
        } else {
            log::warn!("[ctx={}] OPA returned empty body — fail-closed.", self.context_id);
        }

        let decision = if allowed { "ALLOW" } else { "DENY" };

        // ── Structured audit log → Envoy process log → /var/log/envoy/envoy.log
        // The zta-log-forwarder tails this file and ships [WASM_AUDIT] lines to Splunk.
        log::info!(
            "[WASM_AUDIT] {{\"user\":\"{}\",\"command\":\"{}\",\"collection\":\"{}\",\"decision\":\"{}\",\"jti\":\"{}\",\"ctx\":{}}}",
            self.pending_user,
            self.pending_command,
            self.pending_collection,
            decision,
            self.session_jti.as_deref().unwrap_or(""),
            self.context_id,
        );

        // ── Enforce decision ─────────────────────────────────────────────────
        if allowed {
            log::info!("[ctx={}] Query ALLOWED — resuming downstream.", self.context_id);
            if !self.buffer.is_empty() {
                let msg_len = i32::from_le_bytes(self.buffer[0..4].try_into().unwrap()) as usize;
                if self.buffer.len() >= msg_len {
                    self.buffer.drain(0..msg_len);
                }
            }
            self.is_authorized = false;
            self.resume_downstream();
        } else {
            log::warn!(
                "[ctx={}] Query DENIED (cmd={} coll={}) — closing TCP connection.",
                self.context_id,
                self.pending_command,
                self.pending_collection,
            );
            self.close_downstream();
        }
    }
}

impl StreamContext for MongoAuthzStream {
    fn on_downstream_data(&mut self, data_size: usize, _end_of_stream: bool) -> Action {
        log::debug!("[ctx={}] on_downstream_data: size={}", self.context_id, data_size);

        if self.is_authorized {
            return Action::Continue;
        }

        // Accumulate bytes into the reassembly buffer
        if let Some(chunk) = self.get_downstream_data(0, data_size) {
            self.buffer.extend_from_slice(&chunk);
        }

        // Need at least 4-byte length header
        if self.buffer.len() < 4 {
            return Action::Pause;
        }

        let msg_len = i32::from_le_bytes(self.buffer[0..4].try_into().unwrap()) as usize;

        if self.buffer.len() < msg_len {
            log::debug!("[ctx={}] Incomplete packet: have {}/{}", self.context_id, self.buffer.len(), msg_len);
            return Action::Pause;
        }

        let packet = &self.buffer[0..msg_len];

        if let Some((cmd, coll, query_json)) = parse_op_msg(packet) {
            log::info!(
                "[ctx={}] Decoded OP_MSG: cmd='{}' collection='{}' query_preview='{}'",
                self.context_id, cmd, coll,
                truncate_preview(&serde_json::to_string(&query_json).unwrap_or_default(), 120)
            );

            // ── Extract TLS peer identity ────────────────────────────────────
            let client_cert = self.get_property(vec!["connection", "ssl", "peer_certificate"])
                .map(|b| String::from_utf8_lossy(&b).to_string())
                .unwrap_or_default();

            let subject_peer_cert = self.get_property(vec!["connection", "subject_peer_certificate"])
                .map(|b| String::from_utf8_lossy(&b).to_string())
                .unwrap_or_default();

            let uri_san_peer_cert = self.get_property(vec!["connection", "uri_san_peer_certificate"])
                .map(|b| String::from_utf8_lossy(&b).to_string())
                .unwrap_or_default();

            let sha256_peer_cert_digest = self.get_property(vec!["connection", "sha256_peer_certificate_digest"])
                .map(|b| String::from_utf8_lossy(&b).to_string())
                .unwrap_or_default();

            log::info!(
                "[ctx={}] TLS: cert_len={} subject='{}' uri_san='{}' sha256='{}'",
                self.context_id, client_cert.len(), subject_peer_cert, uri_san_peer_cert, sha256_peer_cert_digest
            );

            let (cn, mac) = parse_subject_dn(&subject_peer_cert);
            log::info!("[ctx={}] Parsed DN: cn='{}' mac='{}'", self.context_id, cn, mac);

            let client_ip = self.get_property(vec!["source", "address"])
                .map(|b| String::from_utf8_lossy(&b).to_string())
                .unwrap_or_else(|| "127.0.0.1:0".to_string());
            let ip_only = client_ip.split(':').next().unwrap_or("127.0.0.1").to_string();

            // ── JTI: cache from saslStart, reuse for subsequent commands ─────
            if cmd == "saslStart" {
                if let Some(jti) = extract_jti_from_sasl_start(&query_json) {
                    log::info!("[ctx={}] Cached session JTI from OIDC saslStart: {}", self.context_id, jti);
                    self.session_jti = Some(jti);
                }
            }
            let jti = self.session_jti.clone();

            // ── Cache pending audit fields ────────────────────────────────────
            self.pending_user = cn.clone();
            self.pending_command = cmd.clone();
            self.pending_collection = coll.clone();
            self.pending_query_preview = truncate_preview(
                &serde_json::to_string(&query_json).unwrap_or_default(), 256
            );

            // ── Build OPA payload ─────────────────────────────────────────────
            let opa_payload = OpaRequest {
                input: OpaInput {
                    attributes: OpaAttributes {
                        source: OpaSource {
                            address: OpaAddress {
                                socketAddress: OpaSocketAddress { address: ip_only },
                            },
                            certificate: client_cert,
                            principal: cn.clone(),
                        },
                    },
                    parsed_body: OpaParsedBody {
                        command: cmd,
                        collection: coll,
                        query: query_json,
                        device: if mac.is_empty() { None } else { Some(mac) },
                        user: Some(cn),
                        jti,
                    },
                },
            };

            let payload_bytes = serde_json::to_vec(&opa_payload).unwrap();

            log::info!("[ctx={}] Dispatching OPA authorization call...", self.context_id);
            let token = self.dispatch_http_call(
                "opa_cluster",
                vec![
                    (":method", "POST"),
                    (":path", "/v1/data/envoy/authz/allow"),
                    (":authority", "opa"),
                    ("content-type", "application/json"),
                ],
                Some(&payload_bytes),
                vec![],
                std::time::Duration::from_millis(500),
            );

            match token {
                Ok(t) => {
                    self.opa_token = Some(t);
                    return Action::Pause;
                }
                Err(e) => {
                    log::error!("[ctx={}] Failed to dispatch OPA call: {:?} — fail-closed.", self.context_id, e);
                    log::info!(
                        "[WASM_AUDIT] {{\"user\":\"{}\",\"command\":\"{}\",\"collection\":\"{}\",\"decision\":\"DENY_OPA_ERROR\",\"jti\":\"{}\",\"ctx\":{}}}",
                        self.pending_user, self.pending_command, self.pending_collection,
                        self.session_jti.as_deref().unwrap_or(""), self.context_id,
                    );
                    self.close_downstream();
                    return Action::Pause;
                }
            }
        }

        // Non-OP_MSG packet (legacy wire handshakes, etc.) — let through.
        self.buffer.drain(0..msg_len);
        Action::Continue
    }
}

// ── MongoDB wire protocol parsing ─────────────────────────────────────────────

fn parse_op_msg(packet: &[u8]) -> Option<(String, String, serde_json::Value)> {
    if packet.len() < 21 {
        return None;
    }

    // Opcode at bytes 12..16 (little-endian)
    let opcode = i32::from_le_bytes(packet[12..16].try_into().ok()?);
    if opcode != 2013 {
        return None;
    }

    // Section type byte at offset 20; type 0 = body section
    let section_type = packet[20];
    if section_type != 0 {
        return None;
    }

    // BSON payload begins at offset 21
    let bson_data = &packet[21..];
    let mut cursor = std::io::Cursor::new(bson_data);
    let doc = bson::Document::from_reader(&mut cursor).ok()?;

    // First key is the command name; its value is the collection (string) or 1 (int)
    let mut keys = doc.keys();
    let cmd_name = keys.next()?.clone();

    let coll_name = match doc.get(&cmd_name) {
        Some(bson::Bson::String(s)) => s.clone(),
        _ => "admin".to_string(),
    };

    // Extract the relevant sub-document for L7 inspection
    let filter_val = if cmd_name == "find" {
        doc.get("filter").cloned().unwrap_or_else(|| bson::Bson::Document(bson::Document::new()))
    } else if cmd_name == "update" {
        doc.get("updates").cloned().unwrap_or_else(|| bson::Bson::Document(bson::Document::new()))
    } else if cmd_name == "delete" {
        doc.get("deletes").cloned().unwrap_or_else(|| bson::Bson::Document(bson::Document::new()))
    } else {
        // saslStart, insert, aggregate, etc. — pass full doc for OPA inspection
        bson::Bson::Document(doc.clone())
    };

    let query_json = bson_to_json(&filter_val);
    Some((cmd_name, coll_name, query_json))
}

/// Extract the `jti` claim from a MONGODB-OIDC saslStart BSON payload.
///
/// saslStart doc: { "saslStart": 1, "mechanism": "MONGODB-OIDC", "payload": BinData(0, ...) }
/// Binary data decodes to JSON: {"jwt": "<header>.<claims>.<sig>"}
fn extract_jti_from_sasl_start(query_json: &serde_json::Value) -> Option<String> {
    let mechanism = query_json.get("mechanism")?.as_str()?;
    if mechanism != "MONGODB-OIDC" {
        return None;
    }

    // payload can be a raw base64 string or a BSON $binary object
    let b64_payload = if let Some(s) = query_json.get("payload").and_then(|v| v.as_str()) {
        s.to_string()
    } else if let Some(b64) = query_json
        .get("payload")
        .and_then(|v| v.get("$binary"))
        .and_then(|v| v.get("base64"))
        .and_then(|v| v.as_str())
    {
        b64.to_string()
    } else {
        return None;
    };

    let decoded = base64_decode_flexible(&b64_payload)?;
    let inner: serde_json::Value = serde_json::from_slice(&decoded).ok()?;

    // inner is {"jwt": "eyJ..."}
    let jwt = inner.get("jwt")?.as_str()?;
    let parts: Vec<&str> = jwt.splitn(3, '.').collect();
    if parts.len() < 2 {
        return None;
    }

    // Decode claims segment (index 1), add padding if needed
    let claims_bytes = base64_decode_flexible(parts[1])?;
    let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).ok()?;

    Some(claims.get("jti")?.as_str()?.to_string())
}

/// Flexible base64 decode that handles padded, unpadded, standard and URL-safe encodings.
fn base64_decode_flexible(input: &str) -> Option<Vec<u8>> {
    // Replace URL-safe chars with standard base64
    let normalized = input.replace('-', "+").replace('_', "/");
    // Add padding if missing
    let padded = match normalized.len() % 4 {
        2 => format!("{}==", normalized),
        3 => format!("{}=", normalized),
        _ => normalized,
    };

    // Manual decode to avoid pulling in a base64 crate
    let mut out = Vec::with_capacity((padded.len() / 4) * 3);
    let bytes = padded.as_bytes();
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 { break; }
        let v: Vec<u8> = chunk.iter().map(|&b| match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => 0,
        }).collect();
        out.push((v[0] << 2) | (v[1] >> 4));
        if chunk.len() > 2 && chunk[2] != b'=' { out.push((v[1] << 4) | (v[2] >> 2)); }
        if chunk.len() > 3 && chunk[3] != b'=' { out.push((v[2] << 6) | v[3]); }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn bson_to_json(b: &bson::Bson) -> serde_json::Value {
    match b {
        bson::Bson::Double(f) => serde_json::Value::Number(serde_json::Number::from_f64(*f).unwrap_or_else(|| serde_json::Number::from(0))),
        bson::Bson::String(s) => serde_json::Value::String(s.clone()),
        bson::Bson::Array(arr) => {
            let json_arr: Vec<serde_json::Value> = arr.iter().map(bson_to_json).collect();
            serde_json::Value::Array(json_arr)
        }
        bson::Bson::Document(doc) => {
            let mut map = serde_json::Map::new();
            for (k, v) in doc.iter() {
                map.insert(k.clone(), bson_to_json(v));
            }
            serde_json::Value::Object(map)
        }
        bson::Bson::Boolean(b) => serde_json::Value::Bool(*b),
        bson::Bson::Null => serde_json::Value::Null,
        bson::Bson::Int32(i) => serde_json::Value::Number((*i).into()),
        bson::Bson::Int64(i) => serde_json::Value::Number((*i).into()),
        _ => serde_json::Value::String(b.to_string()),
    }
}

fn parse_subject_dn(dn: &str) -> (String, String) {
    let mut cn = String::new();
    let mut mac = String::new();

    let parts: Vec<&str> = if dn.contains(',') {
        dn.split(',').collect()
    } else {
        dn.split('/').collect()
    };

    for part in parts {
        let part = part.trim();
        if part.to_uppercase().starts_with("CN=") {
            cn = part[3..].to_string();
        } else if part.to_uppercase().starts_with("OU=MAC:") {
            mac = part[7..].to_string();
        } else if part.to_uppercase().starts_with("MAC:") {
            mac = part[4..].to_string();
        }
    }

    (cn, mac)
}

fn truncate_preview(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

// ── Serialization models ───────────────────────────────────────────────────────

#[derive(Serialize)]
struct OpaRequest {
    input: OpaInput,
}

#[derive(Serialize)]
struct OpaInput {
    attributes: OpaAttributes,
    parsed_body: OpaParsedBody,
}

#[derive(Serialize)]
struct OpaAttributes {
    source: OpaSource,
}

#[derive(Serialize)]
struct OpaSource {
    address: OpaAddress,
    certificate: String,
    principal: String,
}

#[derive(Serialize)]
struct OpaAddress {
    #[serde(rename = "socketAddress")]
    socketAddress: OpaSocketAddress,
}

#[derive(Serialize)]
struct OpaSocketAddress {
    address: String,
}

#[derive(Serialize)]
struct OpaParsedBody {
    command: String,
    collection: String,
    query: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    /// JWT ID cached from the OIDC saslStart handshake.
    /// Forwarded to OPA on every command so OPA can check the per-token denylist.
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
struct OpaResponse {
    result: bool,
}
