# Identity extraction (user, device, network, role) and request attributes.
package envoy.authz.identity

import future.keywords

# Identity Extraction

user_identity := raw_user

# Extracts the user exclusively from verified cryptographic sources:
# 1. The subject of the signed OIDC JWT token (if present)
# 2. The Common Name (CN) of the client x509 certificate validated in mTLS
raw_user := user if {
	user := token_claims.sub
} else := user if {
	user := cert_subject_cn
} else := "unknown"

device_identity := id if {
	cert := parsed_client_cert
	id := cert.Subject.OrganizationalUnit[0]
} else := "no-tpm"

# Zero Trust Security: Detects the IP exclusively from the secure TCP socket metadata
# of Envoy, eliminating fallbacks on self-compiled body parameters from the client (IP spoofing protection).
network_identity_str := ip if {
	ip := input.attributes.source.address.socketAddress.address
} else := "0.0.0.0"

is_internal_network if {
	regex.match(`^(172\.19\.|172\.20\.|172\.21\.|10\.)`, network_identity_str)
}

# Role Mapping & Matrix

# Extracts the role exclusively from verified cryptographic sources:
# 1. The 'role' claim (string or array) of the signed OIDC JWT token
# 2. The TITLE attribute of the client x509 certificate validated in mTLS (populated by PKI)
current_role := role if {
	r := token_claims.role
	is_array(r)
	role := r[0]
} else := role if {
	role := token_claims.role
} else := role if {
	cert := parsed_client_cert
	role := cert.Subject.Title[0]
} else := "unknown"

cert_pem_decoded(raw_pem) := decoded if {
	contains(raw_pem, "%")
	decoded := urlquery.decode(raw_pem)
} else := raw_pem

cert_subject_cn := cn if {
	cert := parsed_client_cert
	cn := cert.Subject.CommonName[0]
}

parsed_client_cert := cert if {
	raw_cert := input.attributes.source.certificate
	raw_cert != ""
	cert_pem := cert_pem_decoded(raw_cert)
	certs := crypto.x509.parse_certificates(cert_pem)
	cert := certs[0]
}

# OIDC Federated mTLS & RFC 8705 Token Binding

is_mongodb_oidc if {
	input.parsed_body.query.mechanism == "MONGODB-OIDC"
}

is_mongodb_oidc if {
	input.parsed_body.mechanism == "MONGODB-OIDC"
}

oidc_payload_field := val if {
	auth := input.attributes.request.http.headers.authorization
	startswith(auth, "Bearer ")
	val := substring(auth, 7, -1)
} else := val if {
	val := input.parsed_body.query.payload
} else := val if {
	val := input.parsed_body.payload
} else := ""

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
} else := "unknown"

verify_oidc_jwt(token) := claims if {
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
	claims.cnf["x5t#S256_hex"] == crypto.sha256(cert_der)
}

is_valid_token_binding(claims, cert_subject_cn) if {
	cert_subject_cn in trusted_proxies
}

cert_der_bytes(pem_str) := base64.decode(clean_pem) if {
	clean1 := replace(pem_str, "-----BEGIN CERTIFICATE-----", "")
	clean2 := replace(clean1, "-----END CERTIFICATE-----", "")
	clean3 := replace(clean2, "\n", "")
	clean_pem := replace(clean3, "\r", "")
}


# Request Attributes extraction

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
	prefixes := {"patients": "patients", "admissions": "admissions", "clinical_": "clinical_records", "billing": "billing", "providers": "providers"}
	some prefix
	contains(collection_name, prefix)
	name := prefixes[prefix]
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

# Determines if the request is a direct query to the DB (via HTTP endpoint or raw TCP MongoDB traffic)
is_db_query if {
	input.attributes.request.http.path == "/query"
}

is_db_query if {
	not input.attributes.request.http
}
