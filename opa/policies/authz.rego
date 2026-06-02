package envoy.authz

import future.keywords

# ──────────────────────────────────────────────────────────────────────────────
# Merged & Corrected ZTA Hybrid Policy
#
# Combines:
#   - Hard Criteria (RBAC permissions, no destructive ops, content validation)
#   - Dynamic Contextual Risk scoring (Identity, Behavior, Content, Splunk Anomaly)
#
# Final allow requires:
#   1. criteria_allow (Hard boundaries satisfied)
#   2. risk_score_allow (Risk score <= adaptive_threshold)
# ──────────────────────────────────────────────────────────────────────────────

default allow := false

# Hybrid ZTA Decision Rule
allow if {
	criteria_allow
	risk_score_allow
}

main := {
	"allowed": allow,
	"response_headers_to_add": response_headers,
	"denied_response_headers_to_add": response_headers
}

# OPA Bypass Rules for database system commands
allow if {
	action_name in {"hello", "isMaster", "saslStart", "saslContinue", "buildinfo", "buildInfo"}
}

allow if {
	action_name in {"ping", "getLog", "getCmdLineOpts", "serverStatus"}
}

# Allow unknown collections for decoding errors (only if non-sensitive)
allow if {
	action_name == "unknown"
	not normalized_collection_name in {"clinical_records", "billing", "patients", "admissions", "providers"}
}

# ─── 1. HARD CRITERIA GATEKEEPER ──────────────────────────────────────────────

default criteria_allow := false

criteria_allow if {
	valid_action
	role_action_allowed
	not hard_deny
	not inspection_violation
}

valid_action if {
	action_name in {"find", "insert", "update", "delete", "aggregate"}
}

role_action_allowed if {
	allowed_cmds := permissions[current_role][normalized_collection_name]
	action_name in allowed_cmds
}

# ─── 2. SOFT CONTEXTUAL RISK SCORING ──────────────────────────────────────────

default risk_score_allow := false

risk_score_allow if {
	risk_score <= adaptive_threshold
}

# Punteggio totale di rischio (arrotondato a intero per uniformità di log)
risk_score := round(total_risk_score)

total_risk_score := (
	identity_risk * 30 +
	behavior_risk * 30 +
	content_risk  * 20 +
	anomaly_risk  * 20
) / 100

# Identity Risk Dimension (30% weight)
identity_risk := user_risk_val + device_risk_val + network_risk_val

user_risk_val := 0 if { known_users[user_identity] } else := 30

device_risk_val := 0 if { device_identity != "no-tpm" } else := 20

network_risk_val := 0 if { is_internal_network } else := 15

# Behavior Risk Dimension (30% weight)
behavior_risk := action_risk_val + collection_sensitivity_val

action_risk_val := 0 if {
	action_name == "find"
} else := 20 if {
	action_name == "insert"
} else := 30 if {
	action_name == "update"
} else := 50 if {
	action_name == "delete"
} else := 10 if {
	action_name == "aggregate"
} else := 100 if {
	action_name in {"drop", "delete_database"}
} else := 0

collection_sensitivity_val := 15 if {
	normalized_collection_name in {"clinical_records", "billing"}
} else := 0

# Content Risk Dimension (20% weight) - checks queries for MongoDB
content_risk := 0 if {
	is_http_request
} else := 100 if {
	normalized_collection_name == "clinical_records"
	action_name in {"find", "update"}
	not query_has_field("patient_id")
} else := 100 if {
	normalized_collection_name == "billing"
	query_has_field("$where")
} else := 100 if {
	normalized_collection_name == "billing"
	query_has_field("$function")
} else := 100 if {
	normalized_collection_name == "patients"
	current_role != "admin"
	action_name == "find"
	is_empty_query
} else := 0

# Anomaly Risk Dimension (20% weight) - Splunk sidecar statistics (Asynchronous In-Memory)
anomaly_risk := boost if {
	# If we have a trust registry in OPA and the user is present in it
	user_history := data.splunk.trust_registry[user_identity]
	
	# If the current device was never used by this user in the last 24h
	not user_history[device_identity]
	
	boost := 100
} else := boost if {
	# If the user is present, and the device is known, but the network IP's /24 prefix is unseen for this device
	user_history := data.splunk.trust_registry[user_identity]
	ips := user_history[device_identity]
	
	allowed_prefixes := { p | ip := ips[_]; p := subnet_24(ip) }
	not subnet_24(network_identity_str) in allowed_prefixes
	
	boost := 60
} else := boost if {
	# Fallback to standard rate/volume anomalies if there are any
	boost := data.splunk.anomalies[user_identity].risk_boost
} else := 0

subnet_24(ip) := prefix if {
	parts := split(ip, ".")
	count(parts) == 4
	prefix := concat(".", [parts[0], parts[1], parts[2]])
} else := ip


# ─── 3. ADAPTIVE THRESHOLDS ───────────────────────────────────────────────────

adaptive_threshold := t if {
	current_role == "admin"
	t := 60
} else := t if {
	action_name == "find"
	t := 30
} else := t if {
	action_name == "insert"
	t := 20
} else := t if {
	action_name == "update"
	t := 15
} else := t if {
	action_name == "delete"
	t := 10
} else := 15

# ─── Identity Extraction (extended for HTTP) ──────────────────────────────────

user_identity := sanitize_user(raw_user)

raw_user := user if {
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

action_name := cmd if {
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

is_internal_network if {
	cidr_match := regex.match(`^(172\.20\.|172\.21\.|10\.)`, network_identity)
	cidr_match == true
}

# ─── Role Mapping & Matrix ──────────────────────────────────────────────────

user_role_map := {
	"mario.rossi":    "doctor",
	"anna.verdi":     "billing_staff",
	"giulia.bianchi": "auditor",
	"luca.ferrari":   "receptionist",
	"admin":         "admin",
	"test.user":      "auditor",
	"paolo.roselli":  "doctor",
	"mattia.mando":   "doctor"
}

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
	raw_cert_pem := object.get(object.get(object.get(input, "attributes", {}), "source", {}), "certificate", "")
	raw_cert_pem != ""
	cert_pem := cert_pem_decoded(raw_cert_pem)
	certs := crypto.x509.parse_certificates(cert_pem)
	cert := certs[0]
	role := get_cert_title(cert)
	role != ""
} else := role if {
	role := user_role_map[user_identity]
} else := "unknown"

cert_pem_decoded(raw_pem) := decoded if {
	contains(raw_pem, "%")
	decoded := urlquery.decode(raw_pem)
} else := raw_pem

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

# ─── Content Inspection (L7 WAF queries) ──────────────────────────────────────

query_raw := q if {
	q := object.get(input.parsed_body, "query", "")
} else := "{}"

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

is_http_request if {
	attrs := object.get(input, "attributes", {})
	request := object.get(attrs, "request", {})
	object.get(request, "http", "") != ""
}

inspection_violation if {
	not is_http_request
	normalized_collection_name == "clinical_records"
	action_name in {"find", "update"}
	not query_has_field("patient_id")
}

inspection_violation if {
	not is_http_request
	normalized_collection_name == "billing"
	query_has_field("$where")
}

inspection_violation if {
	not is_http_request
	normalized_collection_name == "billing"
	query_has_field("$function")
}

inspection_violation if {
	not is_http_request
	normalized_collection_name == "patients"
	current_role != "admin"
	action_name == "find"
	is_empty_query
}

# ─── Hard-Deny Rules ──────────────────────────────────────────────────────────

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

# ─── Default Deny ─────────────────────────────────────────────────────────────

default deny := false

deny if {
	not allow
}

# ─── Response Headers ─────────────────────────────────────────────────────────

network_identity_str := ip if {
	is_string(network_identity)
	ip := network_identity
} else := ip if {
	ip := network_identity.socketAddress.address
} else := "0.0.0.0"

response_headers := object.union_n([
	{"x-zta-user": user_identity},
	{"x-zta-device": device_identity},
	{"x-zta-network": network_identity_str},
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

# ─── HTTP Specific Tests ──────────────────────────────────────────

test_http_get_patients_allowed if {
	allow with input as {
		"attributes": {
			"source": {"principal": "mario.rossi"},
			"request": {
				"http": {
					"method": "GET",
					"path": "/patients",
					"headers": {"x-user": "mario.rossi"}
				}
			}
		}
	}
}

test_http_post_clinical_records_allowed if {
	allow with input as {
		"attributes": {
			"source": {
				"principal": "mario.rossi",
				"address": "172.20.0.5"
			},
			"request": {
				"http": {
					"method": "POST",
					"path": "/clinical_records",
					"headers": {"x-user": "mario.rossi"}
				}
			}
		}
	}
}

test_http_get_billing_denied_doctor if {
	deny with input as {
		"attributes": {
			"source": {"principal": "mario.rossi"},
			"request": {
				"http": {
					"method": "GET",
					"path": "/billing",
					"headers": {"x-user": "mario.rossi"}
				}
			}
		}
	}
}

test_http_non_existent_role_denied if {
	deny with input as {
		"attributes": {
			"source": {"principal": "attacker.external"},
			"request": {
				"http": {
					"method": "GET",
					"path": "/patients",
					"headers": {"x-user": "attacker.external"}
				}
			}
		}
	}
}

# ─── Hybrid ZTA Risk Score & Threshold Tests ────────────────────────────────────────

test_risk_threshold_deny_under_high_risk if {
	# Mario Rossi (known, role=doctor) attempts find on patients
	# Rischio base = 0 (known) + 0 (TPM) + 15 (external network) = 15
	# Behavior risk = 0 (find) + 0 (patients sensitivity) = 0
	# Total Risk Score = (15 * 30 + 0 * 30 + 0 * 20 + 0 * 20)/100 = 4.5 -> 5
	# Adaptive threshold for find = 30
	# 5 <= 30 is true, so should allow under normal conditions
	allow with input as {
		"attributes": {
			"source": {"principal": "mario.rossi"},
			"address": "8.8.8.8" # external network
		},
		"parsed_body": {
			"user": "mario.rossi",
			"device": "device-laptop-001",
			"network_ip": "8.8.8.8",
			"command": "find",
			"collection": "patients",
			"query": "{\"name\": \"Pippo\"}"
		}
	}
}

# ─── Trust Registry Unit Tests ──────────────────────────────────────────

test_trust_registry_match_allowed if {
	# Mario Rossi connects with known device and known IP
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
	} with data.splunk.trust_registry as {
		"mario.rossi": {
			"device-laptop-001": ["172.20.0.5"]
		}
	}
}

test_trust_registry_unseen_device_denied if {
	# Mario Rossi connects with unseen device.
	# anomaly_risk = 100
	# total_risk = (0 * 30 + 30 * 30 + 0 * 20 + 100 * 20)/100 = 29
	# Threshold for update = 15
	# 29 <= 15 is FALSE -> DENIED
	deny with input as {
		"attributes": {"source": {"principal": "mario.rossi"}},
		"parsed_body": {
			"user": "mario.rossi",
			"device": "device-attacker-pc",
			"network_ip": "172.20.0.5",
			"command": "update",
			"collection": "patients",
			"query": "{\"patient_id\": \"P001\"}"
		}
	} with data.splunk.trust_registry as {
		"mario.rossi": {
			"device-laptop-001": ["172.20.0.5"]
		}
	}
}

test_trust_registry_unseen_ip_denied if {
	# Mario Rossi connects with seen device but unseen IP.
	# anomaly_risk = 60
	# total_risk = (0 * 30 + 30 * 30 + 0 * 20 + 60 * 20)/100 = 21
	# Threshold for update = 15
	# 21 <= 15 is FALSE -> DENIED
	deny with input as {
		"attributes": {"source": {"principal": "mario.rossi"}},
		"parsed_body": {
			"user": "mario.rossi",
			"device": "device-laptop-001",
			"network_ip": "192.168.1.50",
			"command": "update",
			"collection": "patients",
			"query": "{\"patient_id\": \"P001\"}"
		}
	} with data.splunk.trust_registry as {
		"mario.rossi": {
			"device-laptop-001": ["172.20.0.5"]
		}
	}
}

# ─── Dynamic subnet (/24 prefix) IP Matching tests ───────────────────────

test_trust_registry_dhcp_subnet_match_allowed if {
	# Mario Rossi connects with device-laptop-001 from 172.20.0.99
	# Since 172.20.0.5 is trusted, the /24 subnet is 172.20.0.
	# 172.20.0.99 matches 172.20.0, so this should be ALLOWED!
	allow with input as {
		"attributes": {"source": {"principal": "mario.rossi"}},
		"parsed_body": {
			"user": "mario.rossi",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.99",
			"command": "find",
			"collection": "patients",
			"query": "{\"patient_id\": \"P001\"}"
		}
	} with data.splunk.trust_registry as {
		"mario.rossi": {
			"device-laptop-001": ["172.20.0.5"]
		}
	}
}

# ─── Anti-Spoofing Certificate MAC Verification tests ────────────────────

test_device_identity_from_certificate if {
	# Validate that device_identity is extracted from Certificate OU attribute
	device_identity == "AA-BB-CC-DD-EE-FF" with input as {
		"attributes": {
			"source": {
				"principal": "mario.rossi",
				"certificate": "---BEGIN CERTIFICATE---\n---END CERTIFICATE---"
			}
		}
	} with crypto.x509.parse_certificates as [{
		"Subject": {
			"CommonName": "mario.rossi",
			"OrganizationalUnit": ["MAC:AA-BB-CC-DD-EE-FF"]
		}
	}]
}