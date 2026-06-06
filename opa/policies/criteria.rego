# Regole RBAC, restrizioni hard-deny e ispezione query L7.

package envoy.authz.criteria

import future.keywords
import data.envoy.authz.identity

default criteria_allow := false

criteria_allow if {
	valid_action
	role_action_allowed
	not hard_deny
	not inspection_violation
}

valid_action if {
	identity.action_name in {"find", "insert", "update", "delete", "aggregate"}
}

role_action_allowed if {
	allowed_cmds := permissions[identity.current_role][identity.normalized_collection_name]
	identity.action_name in allowed_cmds
}

# ─── Hard-Deny Rules ──────────────────────────────────────────────────────────

hard_deny if {
	identity.current_role == "unknown"
}

hard_deny if {
	identity.current_role == "billing_staff"
	identity.normalized_collection_name == "clinical_records"
}

hard_deny if {
	identity.current_role == "receptionist"
	identity.normalized_collection_name in {"billing", "clinical_records"}
}

hard_deny if {
	identity.current_role == "doctor"
	identity.normalized_collection_name == "billing"
}

# ─── Content Inspection (L7 WAF queries) ──────────────────────────────────────

inspection_violation if {
	not identity.is_http_request
	identity.normalized_collection_name == "clinical_records"
	identity.action_name in {"find", "update"}
	not identity.query_has_field("patient_id")
}

inspection_violation if {
	not identity.is_http_request
	identity.normalized_collection_name == "billing"
	identity.query_has_field("$where")
}

inspection_violation if {
	not identity.is_http_request
	identity.normalized_collection_name == "billing"
	identity.query_has_field("$function")
}

inspection_violation if {
	not identity.is_http_request
	identity.normalized_collection_name == "patients"
	identity.current_role != "admin"
	identity.action_name == "find"
	identity.is_empty_query
}

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
