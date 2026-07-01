# Estrazione identità (utente, dispositivo, rete, ruolo) ed attributi di richiesta.
package envoy.authz.identity

import future.keywords

# ─── Identity Extraction ──────────────────────────────────────────────────────

user_identity := sanitize_user(raw_user)

raw_user := user if {
	user := token_claims.sub
} else := user if {
	user := input.attributes.source.principal
} else := user if {
	user := input.parsed_body.user
} else := user if {
	user := input.attributes.request.http.headers["x-zta-user"]
} else := "unknown"

sanitize_user(name) := clean if {
	endswith(name, ".internal")
	clean := substring(name, 0, count(name) - 9)
} else := name

device_identity := device if {
	cert := parsed_client_cert
	device := get_cert_mac(cert)
} else := device if {
	device := input.parsed_body.device
} else := "no-tpm"

get_cert_mac(cert) := val if {
	ou := cert.Subject.OrganizationalUnit[_]
	startswith(ou, "MAC:")
	val := substring(ou, 4, -1)
}

network_identity_str := ip if {
	ip := input.parsed_body.network_ip
} else := ip if {
	ip := input.attributes.source.address
	is_string(ip)
} else := ip if {
	ip := input.attributes.source.address.socketAddress.address
} else := "0.0.0.0"

is_internal_network if {
	regex.match(`^(172\.19\.|172\.20\.|172\.21\.|10\.)`, network_identity_str)
}

# ─── Role Mapping & Matrix ────────────────────────────────────────────────────

current_role := role if {
	r := token_claims.role
	is_array(r)
	role := r[0]
} else := role if {
	role := token_claims.role
} else := role if {
	cert := parsed_client_cert
	role := get_cert_title(cert)
} else := role if {
	role := input.parsed_body.role
} else := role if {
	role := input.attributes.request.http.headers["x-zta-role"]
} else := role if {
	role := user_role_map[user_identity]
} else := "unknown"

user_role_map := {
	"test.doctor":    "doctor",
	"test.auditor":   "auditor",
	"test.billing":   "billing_staff",
	"test.reception": "receptionist",
	"test.receptionist": "receptionist",
	"admin":          "admin"
}

get_cert_title(cert) := val if {
	val := cert.Subject.Title[0]
} else := val if {
	name := cert.Subject.Names[_]
	name.Type == [2, 5, 4, 12] # Title OID
	val := name.Value
}

cert_pem_decoded(raw_pem) := decoded if {
	contains(raw_pem, "%")
	decoded := urlquery.decode(raw_pem)
} else := raw_pem

cert_subject_cn := cn if {
	cert := parsed_client_cert
	cn := get_cert_cn(cert)
}

get_cert_cn(cert) := val if {
	val := cert.Subject.CommonName[0]
} else := val if {
	name := cert.Subject.Names[_]
	name.Type == [2, 5, 4, 3] # CommonName OID
	val := name.Value
}

parsed_client_cert := cert if {
	raw_cert := input.attributes.source.certificate
	raw_cert != ""
	cert_pem := cert_pem_decoded(raw_cert)
	certs := crypto.x509.parse_certificates(cert_pem)
	cert := certs[0]
}

# ─── OIDC Federated mTLS & RFC 8705 Token Binding ─────────────────────────────

is_mongodb_oidc if {
	input.parsed_body.query.mechanism == "MONGODB-OIDC"
} else if {
	input.parsed_body.mechanism == "MONGODB-OIDC"
}

oidc_payload_field := val if {
	val := input.parsed_body.query.payload
} else := val if {
	val := input.parsed_body.payload
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
	regex.match(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`, decoded)
	token := decoded
} else := token if {
	is_string(payload_val)
	decoded := base64.decode(payload_val)
	json.is_valid(decoded)
	parsed := json.unmarshal(decoded)
	token := parsed.jwt
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
		"tls_ca_cert_file": "/etc/certs/ca/ca.crt",
		"tls_server_name": "identity-pki",
		"timeout": 1000000000
	})
	jwks_resp.status_code == 200
	io.jwt.verify_rs256(token, jwks_resp.body)
	[_, claims, _] := io.jwt.decode(token)
}

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
	cert_subject_cn == claims.sub
	
	raw_cert_pem := input.attributes.source.certificate
	raw_cert_pem != ""
	cert_pem := cert_pem_decoded(raw_cert_pem)
	
	cert_der := cert_der_bytes(cert_pem)
	client_cert_hex := crypto.sha256(cert_der)
	
	claims.cnf["x5t#S256_hex"] == client_cert_hex
}

is_valid_token_binding(claims, cert_subject_cn) if {
	cert_subject_cn in trusted_proxies
}

# ─── Request Attributes extraction ───────────────────────────────────────────

action_name := cmd if {
	cmd := input.parsed_body.command
} else := "find" if {
	input.attributes.request.http.method == "GET"
} else := "insert" if {
	input.attributes.request.http.method == "POST"
} else := "update" if {
	input.attributes.request.http.method == "PUT"
} else := "delete" if {
	input.attributes.request.http.method == "DELETE"
} else := "unknown"

collection_name := coll if {
	coll := input.parsed_body.collection
} else := coll if {
	path := input.attributes.request.http.path
	path_parts := split(path, "/")
	coll := path_parts[1]
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

query_doc := parsed if {
	q := input.parsed_body.query
	is_string(q)
	json.is_valid(q)
	parsed := json.unmarshal(q)
} else := parsed if {
	parsed := input.parsed_body.query
	is_object(parsed)
} else := {}

query_has_field(field) if {
	query_doc[field]
}

is_empty_query := count(object.keys(query_doc)) == 0

is_db_query if {
	input.attributes.request.http.path == "/query"
} else if {
	not is_non_db_http_request
}

is_non_db_http_request if {
	path := input.attributes.request.http.path
	path != ""
	path != "/query"
}
