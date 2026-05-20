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

# Risk is the sum of the three identity dimensions.
risk_score := total_risk if {
	total_risk := user_risk + device_risk + network_risk + collection_risk_boost
}

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
	action_name in {"hello", "isMaster", "saslStart", "saslContinue", "buildinfo", "buildInfo"}
}

allow if {
	action_name in {"ping", "getLog", "getCmdLineOpts", "serverStatus"}
}

# When mongo_proxy can't decode the wire protocol (e.g. OP_MSG), the
# parsed_body is empty and action_name becomes "unknown". Allow these
# connections — they're initial handshakes from modern MongoDB drivers.
allow if {
	action_name == "unknown"
}

is_destructive_operation if {
	action_name in ["drop", "delete_database"]
}

collection_is_sensitive if {
	collection_name in sensitive_collections
}

sensitive_collections := {
	"clinical_records", 
    "billing"
}

# ─── Collection Risk Boost (from healthcare_rls.rego) ────────────────────────

collection_risk_boost := boost if {
	collection_name in {"clinical_records", "billing"}
	boost := 15
} else := 0

# ─── Identity Extraction (from original authz.rego) ───────────────────────────

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

current_role := role if {
	role := user_role_map[user_identity]
} else := "unknown"

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
	allowed_cmds := permissions[current_role][collection_name]
	action_name in allowed_cmds
}

role_action_denied if {
	not permissions[current_role][collection_name]
}

role_action_denied if {
	allowed_cmds := permissions[current_role][collection_name]
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
    collection_name == "clinical_records"
    action_name in {"find", "update"}
    not query_has_field("patient_id")
}

# billing queries MUST NOT use JavaScript operators
inspection_violation if {
    collection_name == "billing"
    query_has_field("$where")
}

inspection_violation if {
    collection_name == "billing"
    query_has_field("$function")
}

# patients queries must not be empty for non-admin roles
inspection_violation if {
    collection_name == "patients"
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
	collection_name == "clinical_records"
}

hard_deny if {
	current_role == "receptionist"
	collection_name in {"billing", "clinical_records"}
}

hard_deny if {
	current_role == "doctor"
	collection_name == "billing"
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
			"collection": "utenti"
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