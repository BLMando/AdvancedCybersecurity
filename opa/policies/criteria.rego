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

# Hard-Deny Rules

# Sensitive actions (write/delete) require biometric step-up
is_sensitive_action if {
	identity.action_name in {"update", "delete"}
}

# Intercept billing transactions
# with amounts greater than 5000 (considered high-risk operations requiring step-up)
is_sensitive_action if {
	identity.normalized_collection_name == "billing"
	walk(identity.query_doc, [path, value])
	some segment in path
	is_string(segment)
	segment in {"billing_amount", "billing_amount_approx"}
	is_number(value)
	value > 5000
}

# Block sensitive actions if a valid and fresh biometric step-up token is not present
hard_deny if {
	is_sensitive_action
	not identity.token_step_up_fresh
}

# Immediately block unauthenticated clients or those without a valid role
hard_deny if {
	identity.current_role == "unknown"
}

# Content Inspection

# Clinical Compliance Rule: Doctors can update clinical records
# only if they specify a targeted filter for the individual patient
inspection_violation if {
	identity.is_db_query
	identity.normalized_collection_name == "clinical_records"
	identity.action_name == "update"
	not identity.query_has_field("patient_id")
}

# Privacy Compliance Rule: Prevents empty queries (e.g. {}) on the patients table
# for non-admin roles to prevent massive dumping of registry data
inspection_violation if {
	identity.is_db_query
	identity.normalized_collection_name == "patients"
	identity.current_role != "admin"
	identity.action_name == "find"
	identity.is_empty_query
}

# Permission Matrix (Zero Trust Default Deny for empty fields {})
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
		"admissions":       {"find", "insert", "update", "delete"},
		"clinical_records": {"find", "insert", "update", "delete"},
		"billing":          {}
	},
	"billing_staff": {
		"patients":         {"find"},
		"providers":        {"find"},
		"admissions":       {"find"},
		"clinical_records": {},
		"billing":          {"find", "insert", "update", "delete"}
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
		"admissions":       {"find", "insert", "update", "delete"},
		"clinical_records": {},
		"billing":          {}
	},
	"unknown": {}
}
