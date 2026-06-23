# Estrazione identità (utente, dispositivo, rete, ruolo) ed attributi di richiesta. 

package envoy.authz.identity

import future.keywords

# ─── Identity Extraction ──────────────────────────────────────────────────────

user_identity := sanitize_user(raw_user)

raw_user := user if {
	claims := token_claims
	user := claims.sub
	user != ""
} else := user if {
	attrs := object.get(input, "attributes", {})
	source := object.get(attrs, "source", {})
	user := object.get(source, "principal", "")
	user != ""
} else := user if {
	user := object.get(input.parsed_body, "user", "")
	user != ""
} else := user if {
	attrs := object.get(input, "attributes", {})
	request := object.get(attrs, "request", {})
	http := object.get(request, "http", {})
	headers := object.get(http, "headers", {})
	user := object.get(headers, "x-user", "")
	user != ""
} else := "unknown"

sanitize_user(name) := clean if {
	endswith(name, ".internal")
	clean := substring(name, 0, count(name) - 9)
} else := name

device_identity := device if {
	# 1. Cryptographic device verification: check certificate for TPM-bound MAC
	raw_cert_pem := object.get(object.get(object.get(input, "attributes", {}), "source", {}), "certificate", "")
	raw_cert_pem != ""
	cert_pem := cert_pem_decoded(raw_cert_pem)
	certs := crypto.x509.parse_certificates(cert_pem)
	cert := certs[0]
	device := get_cert_mac(cert)
	device != ""
} else := device if {
	# 2. Fallback to payload for tests/non-mTLS bypass
	device := object.get(input.parsed_body, "device", "")
	device != ""
} else := ja3 if {
	# 3. Fallback to JA3
	tls_meta := object.get(object.get(input.attributes, "metadata_context", {}), "filter_metadata", {})
	tls_inspector := object.get(tls_meta, "envoy.filters.listener.tls_inspector", {})
	ja3 := object.get(tls_inspector, "ja3", "")
	ja3 != ""
} else := ja3h if {
	# 4. Fallback to JA3 hash
	tls_meta := object.get(object.get(input.attributes, "metadata_context", {}), "filter_metadata", {})
	tls_inspector := object.get(tls_meta, "envoy.filters.listener.tls_inspector", {})
	ja3h := object.get(tls_inspector, "ja3_hash", "")
	ja3h != ""
} else := "no-tpm"

get_cert_mac(cert) := val if {
	ous := object.get(cert.Subject, "OrganizationalUnit", [])
	ou := ous[_]
	startswith(ou, "MAC:")
	val := substring(ou, 4, -1)
} else := ""

network_identity := ip if {
	ip := object.get(input.parsed_body, "network_ip", "")
	ip != ""
} else := ip if {
	ip := object.get(object.get(input.attributes, "source", {}), "address", "")
	ip != ""
} else := "0.0.0.0"

network_identity_str := ip if {
	is_string(network_identity)
	ip := network_identity
} else := ip if {
	ip := network_identity.socketAddress.address
} else := "0.0.0.0"

is_internal_network if {
	cidr_match := regex.match(`^(172\.20\.|172\.21\.|10\.)`, network_identity_str)
	cidr_match == true
}

# ─── Role Mapping & Matrix ────────────────────────────────────────────────────

current_role := role if {
	claims := token_claims
	is_array(claims.role)
	role := claims.role[0]
	role != ""
} else := role if {
	claims := token_claims
	is_string(claims.role)
	role := claims.role
	role != ""
} else := role if {
	cert_pem_raw := object.get(object.get(object.get(input, "attributes", {}), "source", {}), "certificate", "")
	cert_pem_raw != ""
	cert_pem := urlquery.decode(cert_pem_raw)
	certs := crypto.x509.parse_certificates(cert_pem)
	cert := certs[0]
	role := get_cert_title(cert)
	role != ""
} else := role if {
	role := user_role_map[user_identity]
} else := "unknown"

get_cert_title(cert) := val if {
	titles := object.get(cert.Subject, "Title", [])
	val := titles[0]
	val != ""
} else := val if {
	names := object.get(cert.Subject, "Names", [])
	name := names[_]
	name.Type == [2, 5, 4, 12]
	val := name.Value
	val != ""
}

user_role_map := {
	"mario.rossi":    "doctor",
	"anna.verdi":     "billing_staff",
	"giulia.bianchi": "auditor",
	"luca.ferrari":   "receptionist",
	"admin":          "admin",
	"test.user":      "auditor",
	"paolo.roselli":  "doctor",
	"mattia.mando":   "doctor"
}

known_users := {
	"mario.rossi",
	"anna.verdi",
	"giulia.bianchi", 
	"luca.ferrari",
	"admin",
	"test.user",
	"paolo.roselli",
	"mattia.mando"
}

cert_pem_decoded(raw_pem) := decoded if {
	contains(raw_pem, "%")
	decoded := urlquery.decode(raw_pem)
} else := raw_pem

cert_subject_cn := cn if {
	cert_pem_raw := object.get(object.get(object.get(input, "attributes", {}), "source", {}), "certificate", "")
	cert_pem_raw != ""
	cert_pem := urlquery.decode(cert_pem_raw)
	certs := crypto.x509.parse_certificates(cert_pem)
	cert := certs[0]
	cn := get_cert_cn(cert)
}

get_cert_cn(cert) := val if {
	cns := object.get(cert.Subject, "CommonName", [])
	val := cns[0]
	val != ""
} else := val if {
	names := object.get(cert.Subject, "Names", [])
	name := names[_]
	name.Type == [2, 5, 4, 3]
	val := name.Value
	val != ""
}

# ─── OIDC Federated mTLS & RFC 8705 Token Binding ─────────────────────────────

is_mongodb_oidc if {
	input.parsed_body.query.mechanism == "MONGODB-OIDC"
} else if {
	input.parsed_body.mechanism == "MONGODB-OIDC"
}

oidc_payload_field := val if {
	val := input.parsed_body.query.payload
	val != ""
} else := val if {
	val := input.parsed_body.payload
	val != ""
} else := ""

cert_der_bytes(pem_str) := der if {
	clean1 := replace(pem_str, "-----BEGIN CERTIFICATE-----", "")
	clean2 := replace(clean1, "-----END CERTIFICATE-----", "")
	clean3 := replace(clean2, "\n", "")
	clean_pem := replace(clean3, "\r", "")
	der := base64.decode(clean_pem)
}

trusted_proxies := {
	"envoy",
	"identity-pki"
}

valid_oidc_token if {
	payload_val := oidc_payload_field
	payload_val != ""
	
	token := extract_jwt_from_payload(payload_val)
	token != "unknown"
	
	claims := verify_oidc_jwt(token)
	
	# Verify expiration
	claims.exp > time.now_ns() / 1000000000
	
	is_valid_token_binding(claims, cert_subject_cn)
}

extract_jwt_from_payload(payload_val) := token if {
	is_string(payload_val)
	regex.match(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`, payload_val)
	token := payload_val
} else := token if {
	is_string(payload_val)
	decoded := base64.decode(payload_val)
	json.is_valid(decoded)
	parsed := json.unmarshal(decoded)
	token := parsed.jwt
} else := token if {
	is_string(payload_val)
	decoded := base64.decode(payload_val)
	regex.match(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`, decoded)
	token := decoded
} else := token if {
	is_object(payload_val)
	base64_data := payload_val["$binary"].base64
	decoded := base64.decode(base64_data)
	json.is_valid(decoded)
	parsed := json.unmarshal(decoded)
	token := parsed.jwt
} else := token if {
	is_object(payload_val)
	base64_data := payload_val["$binary"].base64
	decoded := base64.decode(base64_data)
	regex.match(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`, decoded)
	token := decoded
} else := "unknown"

verify_oidc_jwt(token) := claims if {
	jwks_resp := http.send({
		"method": "get",
		"url": "https://identity-pki:8080/.well-known/jwks.json",
		"tls_insecure_skip_verify": true,
		"timeout": 1000000000
	})
	jwks_resp.status_code == 200
	jwks := json.marshal(jwks_resp.body)
	
	io.jwt.verify_rs256(token, jwks)
	[_, claims, _] := io.jwt.decode(token)
}

# Helpers for Step-Up Authentication status
token_claims := claims if {
	payload_val := oidc_payload_field
	payload_val != ""
	token := extract_jwt_from_payload(payload_val)
	token != "unknown"
	claims := verify_oidc_jwt(token)
}

token_has_step_up if {
	claims := token_claims
	claims.step_up == true
}

token_step_up_fresh if {
	claims := token_claims
	claims.step_up == true
	now_seconds := time.now_ns() / 1000000000
	now_seconds - claims.step_up_time < 120
}


is_valid_token_binding(claims, cert_subject_cn) if {
	# Direct client: CN matches sub, cert fingerprint matches cnf
	cert_subject_cn == claims.sub
	
	cert_pem := object.get(object.get(object.get(input, "attributes", {}), "source", {}), "certificate", "")
	cert_pem != ""
	
	cert_der := cert_der_bytes(cert_pem)
	client_cert_hex := crypto.sha256(cert_der)
	
	claims.cnf["x5t#S256_hex"] == client_cert_hex
}

is_valid_token_binding(claims, cert_subject_cn) if {
	# Trusted proxy: connection is from a trusted gateway or service
	cert_subject_cn in trusted_proxies
}

# ─── Request Attributes extraction ───────────────────────────────────────────

# Estrazione dei metadati di MongoDB da envoy.filters.network.mongo_proxy
extracted_mongo_ops contains info if {
	mongo_meta := object.get(object.get(object.get(input, "attributes", {}), "metadata_context", {}), "filter_metadata", {})["envoy.filters.network.mongo_proxy"]
	some db_coll, op_details in mongo_meta
	contains(db_coll, ".")
	parts := split(db_coll, ".")
	coll := parts[1]
	some cmd_name, cmd_details in op_details
	query := object.get(cmd_details, "query", object.get(cmd_details, "filter", {}))
	info := {
		"command": cmd_name,
		"collection": coll,
		"query": query
	}
}

extracted_mongo_ops contains info if {
	mongo_meta := object.get(object.get(object.get(input, "attributes", {}), "metadata_context", {}), "filter_metadata", {})["envoy.filters.network.mongo_proxy"]
	req := mongo_meta.request
	cmd := req.command
	coll := req.collection
	query := object.get(req, "query", object.get(req, "filter", {}))
	info := {
		"command": cmd,
		"collection": coll,
		"query": query
	}
}

extracted_mongo_op := val if {
	count(extracted_mongo_ops) > 0
	val := any_val(extracted_mongo_ops)
} else := {
	"command": "unknown",
	"collection": "unknown",
	"query": {}
}

any_val(s) := v if {
	v := s[_]
}

action_name := cmd if {
	extracted_mongo_op.command != "unknown"
	cmd := extracted_mongo_op.command
} else := cmd if {
	cmd := object.get(input.parsed_body, "command", "")
	cmd != ""
} else := "find" if {
	attrs := object.get(input, "attributes", {})
	request := object.get(attrs, "request", {})
	http := object.get(request, "http", {})
	method := object.get(http, "method", "")
	method == "GET"
} else := "insert" if {
	attrs := object.get(input, "attributes", {})
	request := object.get(attrs, "request", {})
	http := object.get(request, "http", {})
	method := object.get(http, "method", "")
	method == "POST"
} else := "update" if {
	attrs := object.get(input, "attributes", {})
	request := object.get(attrs, "request", {})
	http := object.get(request, "http", {})
	method := object.get(http, "method", "")
	method == "PUT"
} else := "delete" if {
	attrs := object.get(input, "attributes", {})
	request := object.get(attrs, "request", {})
	http := object.get(request, "http", {})
	method := object.get(http, "method", "")
	method == "DELETE"
} else := "unknown"

collection_name := coll if {
	extracted_mongo_op.collection != "unknown"
	coll := extracted_mongo_op.collection
} else := coll if {
	coll := object.get(input.parsed_body, "collection", "")
	coll != ""
} else := coll if {
	attrs := object.get(input, "attributes", {})
	request := object.get(attrs, "request", {})
	http := object.get(request, "http", {})
	path := object.get(http, "path", "")
	path != ""
	path_parts := split(path, "/")
	coll := path_parts[1]
	coll != ""
} else := "unknown"

normalized_collection_name := name if {
	startswith(collection_name, "v_patients_")
	name := "patients"
} else := name if {
	startswith(collection_name, "v_admissions_")
	name := "admissions"
} else := name if {
	startswith(collection_name, "v_clinical_")
	name := "clinical_records"
} else := name if {
	startswith(collection_name, "v_billing_")
	name := "billing"
} else := name if {
	collection_name == "v_providers_all"
	name := "providers"
} else := collection_name

query_raw := q if {
	q := object.get(input.parsed_body, "query", "")
} else := "{}"

query_doc := parsed if {
	extracted_mongo_op.command != "unknown"
	parsed := extracted_mongo_op.query
} else := parsed if {
	json.is_valid(query_raw)
	parsed := json.unmarshal(query_raw)
} else := parsed if {
	object.keys(query_raw)
	parsed := query_raw
} else := {}

query_has_field(field) if {
	query_doc[field]
}

is_empty_query := count(object.keys(query_doc)) == 0

is_http_request if {
	attrs := object.get(input, "attributes", {})
	request := object.get(attrs, "request", {})
	object.get(request, "http", "") != ""
}
