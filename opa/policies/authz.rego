package envoy.authz

import future.keywords

# ──────────────────────────────────────────────────────────────────────────────
# Merged Authorization Policy
#
# Combines:
#   - Risk-score based access control (from original authz.rego)
#   - Role-based + collection-level access (from healthcare_rls.rego)
#
# Final allow requires:
#   1. Valid action (not destructive)
#   2. risk_score <= threshold
#   3. role_action_allowed (role × collection × command matrix)
#   4. No hard-deny rules triggered
# ──────────────────────────────────────────────────────────────────────────────

default allow := false

allow if {
	valid_action
	risk_score <= threshold
	action_allowed
	role_action_allowed
	not hard_deny
	not inspection_violation
}

# Risk is the sum of identity dimensions plus a dynamic boost obtained
# from Splunk statistics for the current request context.
risk_score := total_risk if {
	total_risk := base_risk_score + splunk_risk_boost
}

base_risk_score := total_risk if {
	total_risk := user_risk + device_risk + network_risk + collection_risk_boost
}

# OPA asks the forwarder for Splunk-backed statistics.
# If stats are unavailable, fail soft with a zero boost.
splunk_risk_boost := boost if {
	resp := http.send({
		"method": "post",
		"url": "http://opa-splunk-forwarder:5000/api/stats",
		"headers": {"Content-Type": "application/json"},
		"body": {
			"user": user_identity,
			"network_ip": network_identity,
			"device": device_identity,
			"resource": collection_name,
			"command": action_name
		},
		"timeout": 1000000000
	})
	resp.status_code == 200
	boost := object.get(resp.body, "risk_boost", 0)
} else := 0

# Known users are trusted; unknown users add risk.
user_risk := 0 if {
	known_users[user_identity]
} else := 30

# A hardware-bound device is lower risk than a generic fingerprint.
device_risk := 0 if {
	device_identity != "no-tpm"
} else := 20

# Internal networks are treated as lower risk than external ones.
network_risk := 0 if {
	is_internal_network
} else := 15

threshold := t if {
	action_name == "find"
	t := 60
} else := t if {
	action_name == "insert"
	t := 40
} else := t if {
	action_name == "update"
	t := 30
} else := t if {
	action_name == "delete"
	t := 20
}

# ─── Action Validation (from original authz.rego) ────────────────────────────────

action_allowed if {
	valid_action
	not is_destructive_operation
	not collection_is_sensitive
}

action_allowed if {
	valid_action
	collection_is_sensitive
	risk_score < threshold / 2
	not is_destructive_operation
}

valid_action if {
	action_name in {"find", "insert", "update", "delete", "aggregate"}
}

# MongoDB handshake / auth / admin commands — always allowed
allow if {
	action_name in {"hello", "isMaster", "saslContinue", "buildinfo", "buildInfo"}
}

allow if {
	action_name in {"ping", "getLog", "getCmdLineOpts", "serverStatus"}
}

allow if {
	action_name == "saslStart"
	not is_mongodb_oidc
}

allow if {
	action_name == "saslStart"
	is_mongodb_oidc
	valid_oidc_token
}

# Allow connection establishment when the MongoDB command has not been parsed yet.
# Once allowed, actual queries (like find, insert, drop) will be evaluated if they are
# parsed, but since L4 ext_authz evaluates only once per connection, we ensure the client
# is at least authorized with a valid client certificate and a registered role.
allow if {
	action_name == "unknown"
	current_role in {"admin", "doctor", "billing_staff", "auditor", "receptionist"}
}

allow if {
	action_name == "unknown"
	cert_subject_cn in trusted_proxies
}


is_destructive_operation if {
	action_name in ["drop", "delete_database"]
}

collection_is_sensitive if {
	normalized_collection_name in sensitive_collections
}

sensitive_collections := {
	"clinical_records", 
    "billing"
}



collection_risk_boost := boost if {
	normalized_collection_name in {"clinical_records", "billing"}
	boost := 15
} else := 0

# ─── Identity Extraction ───────────────────────

user_identity := user if {
	user := object.get(
		object.get(input, "attributes", {}),
		"source",
		{}
	)
	user != {}
	user = input.attributes.source.principal
} else := user if {
	user := input.parsed_body.user
	user != ""
} else := "unknown"

# Device identity is provided by Envoy when available; otherwise the policy
# falls back to the no-tpm marker used in the lab.
device_identity := device if {
	device := input.parsed_body.device
	device != ""

} else := ja3 if {
	tls_meta := object.get(object.get(input.attributes, "metadata_context", {}), "filter_metadata", {})
	tls_inspector := object.get(tls_meta, "envoy.filters.listener.tls_inspector", {})
	ja3 := object.get(tls_inspector, "ja3", "")
	ja3 != ""

} else := ja3h if {
	tls_meta := object.get(object.get(input.attributes, "metadata_context", {}), "filter_metadata", {})
	tls_inspector := object.get(tls_meta, "envoy.filters.listener.tls_inspector", {})
	ja3h := object.get(tls_inspector, "ja3_hash", "")
	ja3h != ""

} else := "no-tpm"

network_identity := ip if {
	ip := input.parsed_body.network_ip
	ip != ""

} else := ip if {
	ip := object.get(object.get(input.attributes, "source", {}), "address", "")
	ip != ""

} else := "0.0.0.0"

# The command and collection tell us whether the operation is read-only,
# write-oriented or destructive.
action_name := cmd if {
	cmd := input.parsed_body.command
	cmd != ""
} else := "unknown"

collection_name := coll if {
	coll := input.parsed_body.collection
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

known_users := {
	"mario.rossi",
	"anna.verdi",
	"giulia.bianchi", 
	"luca.ferrari",
	"admin",
	"test.user",
	"paolo.roselli"
}

is_internal_network if {
	cidr_match := regex.match(`^(172\.20\.|10\.)`, network_identity)
	cidr_match == true
}

# ─── Role Mapping (from healthcare_rls.rego) ────────────────────────────────

user_role_map := {
	"mario.rossi":    "doctor",
	"anna.verdi":     "billing_staff",
	"giulia.bianchi": "auditor",
	"luca.ferrari":   "receptionist",
	"admin":         "admin",
	"test.user":      "auditor",
	"paolo.roselli":  "doctor"
}

# Helper to extract the Title field (OID 2.5.4.12) from Subject Names or directly
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

current_role := role if {
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

debug_cert_pem := val if {
	cert_pem_raw := object.get(object.get(object.get(input, "attributes", {}), "source", {}), "certificate", "")
	val := urlquery.decode(cert_pem_raw)
}
debug_parsed_certs := val if {
	val := crypto.x509.parse_certificates(debug_cert_pem)
}
debug_cert_title := val if {
	val := get_cert_title(debug_parsed_certs[0])
}

# ─── Permission Matrix (from healthcare_rls.rego) ────────────────────────────

permissions := {
	"admin": {
		"patients":         {"find", "insert", "update", "delete"},
		"providers":        {"find", "insert", "update", "delete"},
		"admissions":       {"find", "insert", "update", "delete"},
		"clinical_records": {"find", "insert", "update", "delete"},
"billing":          {"find", "insert", "update", "delete"}
	},
	"doctor": {
		"patients":         {"find"},
		"providers":        {"find"},
		"admissions":       {"find", "insert", "update"},
		"clinical_records": {"find", "insert", "update"},
		"billing":          {}
	},
	"billing_staff": {
		"patients":         {"find"},
		"providers":        {"find"},
		"admissions":       {"find"},
		"clinical_records": {},
		"billing":          {"find", "insert", "update"}
	},
	"auditor": {
		"patients":         {"find"},
		"providers":        {"find"},
		"admissions":       {"find"},
		"clinical_records": {"find"},
		"billing":          {"find"}
	},
	"receptionist": {
		"patients":         {"find", "insert", "update"},
		"providers":        {"find"},
		"admissions":       {"find", "insert", "update"},
		"clinical_records": {},
		"billing":          {}
	},
	"unknown": {}
}

role_action_allowed if {
	allowed_cmds := permissions[current_role][normalized_collection_name]
	action_name in allowed_cmds
}

role_action_denied if {
	not permissions[current_role][normalized_collection_name]
}

role_action_denied if {
	allowed_cmds := permissions[current_role][normalized_collection_name]
	not action_name in allowed_cmds
}

# ─── Content Inspection (L7 Firewall) ───────────────────────────────────────
# Validates MongoDB query content for sensitive collections.
# Runs after the RBAC check to enforce query-level constraints.

query_raw := q if {
    q := object.get(input.parsed_body, "query", "")
} else := "{}"

# Try to parse as JSON if it's a string; otherwise use as-is
query_doc := parsed if {
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

# clinical_records queries MUST contain patient_id field
inspection_violation if {
    normalized_collection_name == "clinical_records"
    action_name in {"find", "update"}
    not query_has_field("patient_id")
}

# billing queries MUST NOT use JavaScript operators
inspection_violation if {
    normalized_collection_name == "billing"
    query_has_field("$where")
}

inspection_violation if {
    normalized_collection_name == "billing"
    query_has_field("$function")
}

# patients queries must not be empty for non-admin roles
inspection_violation if {
    normalized_collection_name == "patients"
    current_role != "admin"
    action_name == "find"
    is_empty_query
}

# ─── Hard-Deny Rules (from healthcare_rls.rego) ──────────────────────────────

hard_deny if {
	current_role == "unknown"
}

hard_deny if {
	current_role == "billing_staff"
	normalized_collection_name == "clinical_records"
}

hard_deny if {
	current_role == "receptionist"
	normalized_collection_name in {"billing", "clinical_records"}
}

hard_deny if {
	current_role == "doctor"
	normalized_collection_name == "billing"
}

# ─── Denial Rules (from original authz.rego) ───────────────────────────────────────

deny if {
	risk_score > threshold
}

deny if {
	is_destructive_operation
}

deny if {
	not valid_action
}

deny if {
	hard_deny
}

deny if {
	inspection_violation
}

deny if {
	role_action_denied
}

# ─── Response Headers ─────────────────────────────────────────────────────────────

response_headers := object.union_n([
	{"x-zta-user": user_identity},
	{"x-zta-device": device_identity},
	{"x-zta-network": network_identity},
	{"x-zta-action": action_name},
	{"x-zta-collection": collection_name},
	{"x-zta-risk-score": sprintf("%d", [risk_score])},
	{"x-zta-decision": decision_label},
	{"x-zta-role": current_role},
	{"x-zta-eff-risk": sprintf("%d", [risk_score])},
	{"x-zta-command": action_name}
])

decision_label := "ALLOW" if {
	allow
} else := "DENY"

# ─── Tests ─────────────────────────────────────────────────────────────────

test_legitimate_user if {
	allow with input as {
		"attributes": {"source": {"principal": "mario.rossi"}},
		"parsed_body": {
			"user": "mario.rossi",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "patients",
			"query": "{\"patient_id\": \"P001\"}"
		}
	}
}

test_unknown_user_denied if {
	not allow with input as {
		"parsed_body": {
			"user": "attacker.evil",
			"device": "no-tpm",
			"network_ip": "192.168.1.100",
			"command": "find",
			"collection": "payments"
		}
	}
}

test_destructive_denied if {
	deny with input as {
		"parsed_body": {
			"user": "mario.rossi",
			"command": "drop",
			"collection": "utenti"
		}
	}
}

test_doctor_clinical_find if {
	allow with input as {
		"attributes": {"source": {"principal": "mario.rossi"}},
		"parsed_body": {
			"user": "mario.rossi",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "clinical_records",
			"query": "{\"patient_id\": \"P001\"}"
		}
	}
}

test_doctor_billing_denied if {
	deny with input as {
		"parsed_body": {
			"user": "mario.rossi",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "billing"
		}
	}
}

test_billing_staff_clinical_denied if {
	deny with input as {
		"parsed_body": {
			"user": "anna.verdi",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "clinical_records"
		}
	}
}

test_auditor_read_all if {
	allow with input as {
		"parsed_body": {
			"user": "giulia.bianchi",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "billing"
		}
	}
}

test_auditor_no_write if {
	deny with input as {
		"parsed_body": {
			"user": "giulia.bianchi",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "insert",
			"collection": "patients"
		}
	}
}

test_unknown_role_denied if {
	deny with input as {
		"parsed_body": {
			"user": "attacker.external",
			"device": "no-tpm",
			"network_ip": "8.8.8.8",
			"command": "find",
			"collection": "patients"
		}
	}
}

test_receptionist_no_clinical if {
	deny with input as {
		"parsed_body": {
			"user": "luca.ferrari",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "clinical_records"
		}
	}
}

# ─── Content Inspection Tests ─────────────────────────────────────────

test_clinical_no_patient_id_denied if {
	deny with input as {
		"attributes": {"source": {"principal": "mario.rossi"}},
		"parsed_body": {
			"user": "mario.rossi",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "clinical_records",
			"query": "{}"
		}
	}
}

test_clinical_with_patient_id_allowed if {
	allow with input as {
		"attributes": {"source": {"principal": "mario.rossi"}},
		"parsed_body": {
			"user": "mario.rossi",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "clinical_records",
			"query": "{\"patient_id\": \"P001\"}"
		}
	}
}

test_billing_where_operator_denied if {
	deny with input as {
		"attributes": {"source": {"principal": "anna.verdi"}},
		"parsed_body": {
			"user": "anna.verdi",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "billing",
			"query": "{\"$where\": \"this.amount > 1000\"}"
		}
	}
}

test_patients_empty_query_denied_receptionist if {
	deny with input as {
		"attributes": {"source": {"principal": "luca.ferrari"}},
		"parsed_body": {
			"user": "luca.ferrari",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "patients",
			"query": "{}"
		}
	}
}

test_admin_empty_query_allowed if {
	allow with input as {
		"attributes": {"source": {"principal": "admin"}},
		"parsed_body": {
			"user": "admin",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "patients",
			"query": "{}"
		}
	}
}

# ─── View query authorization tests ──────────────────────────────────────────

test_doctor_clinical_view_allowed if {
	allow with input as {
		"attributes": {"source": {"principal": "mario.rossi"}},
		"parsed_body": {
			"user": "mario.rossi",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "v_clinical_doctor",
			"query": "{\"patient_id\": \"P001\"}"
		}
	}
}

test_doctor_clinical_view_no_patient_id_denied if {
	deny with input as {
		"attributes": {"source": {"principal": "mario.rossi"}},
		"parsed_body": {
			"user": "mario.rossi",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "v_clinical_doctor",
			"query": "{}"
		}
	}
}

test_doctor_billing_view_denied if {
	deny with input as {
		"attributes": {"source": {"principal": "mario.rossi"}},
		"parsed_body": {
			"user": "mario.rossi",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "v_billing_staff",
			"query": "{}"
		}
	}
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

cert_subject_cn := cn if {
	cert_pem_raw := object.get(object.get(object.get(input, "attributes", {}), "source", {}), "certificate", "")
	cert_pem_raw != ""
	cert_pem := urlquery.decode(cert_pem_raw)
	certs := crypto.x509.parse_certificates(cert_pem)
	cert := certs[0]
	cn := get_cert_cn(cert)
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


# ─── OIDC Verification Tests ──────────────────────────────────────────────

test_oidc_valid if {
	allow with input as {
		"attributes": {
			"source": {
				"principal": "paolo.roselli",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "saslStart",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with verify_oidc_jwt as {"sub": "paolo.roselli", "role": "doctor", "exp": 9999999999, "cnf": {"x5t#S256_hex": "mock-fingerprint"}}
	with cert_subject_cn as "paolo.roselli"
	with cert_der_bytes as "mock-der"
	with crypto.sha256 as "mock-fingerprint"
}

test_oidc_invalid_cert_denied if {
	not allow with input as {
		"attributes": {
			"source": {
				"principal": "paolo.roselli",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "saslStart",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with verify_oidc_jwt as {"sub": "paolo.roselli", "role": "doctor", "exp": 9999999999, "cnf": {"x5t#S256_hex": "different-fingerprint"}}
	with cert_subject_cn as "paolo.roselli"
	with cert_der_bytes as "mock-der"
	with crypto.sha256 as "mock-fingerprint"
}

test_oidc_expired_token_denied if {
	not allow with input as {
		"attributes": {
			"source": {
				"principal": "paolo.roselli",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "saslStart",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with verify_oidc_jwt as {"sub": "paolo.roselli", "role": "doctor", "exp": 100000, "cnf": {"x5t#S256_hex": "mock-fingerprint"}}
	with cert_subject_cn as "paolo.roselli"
	with cert_der_bytes as "mock-der"
	with crypto.sha256 as "mock-fingerprint"
}

test_oidc_wrong_cn_denied if {
	not allow with input as {
		"attributes": {
			"source": {
				"principal": "paolo.roselli",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "saslStart",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with verify_oidc_jwt as {"sub": "attacker.name", "role": "doctor", "exp": 9999999999, "cnf": {"x5t#S256_hex": "mock-fingerprint"}}
	with cert_subject_cn as "paolo.roselli"
	with cert_der_bytes as "mock-der"
	with crypto.sha256 as "mock-fingerprint"
}

test_oidc_trusted_proxy_valid if {
	allow with input as {
		"attributes": {
			"source": {
				"principal": "envoy",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "saslStart",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with verify_oidc_jwt as {"sub": "paolo.roselli", "role": "doctor", "exp": 9999999999, "cnf": {"x5t#S256_hex": "different-fingerprint"}}
	with cert_subject_cn as "envoy"
}

test_unknown_action_allowed_for_valid_role if {
	allow with input as {
		"attributes": {
			"source": {
				"principal": "paolo.roselli",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "unknown"
		}
	}
	with current_role as "doctor"
}

test_unknown_action_denied_for_invalid_role if {
	not allow with input as {
		"attributes": {
			"source": {
				"principal": "attacker.evil",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "unknown"
		}
	}
	with current_role as "unknown"
}

test_unknown_action_allowed_for_trusted_proxy if {
	allow with input as {
		"attributes": {
			"source": {
				"principal": "envoy",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "unknown"
		}
	}
	with cert_subject_cn as "envoy"
}