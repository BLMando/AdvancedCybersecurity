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

# Le azioni sensitive (scrittura/cancellazione) richiedono step-up biometrico
is_sensitive_action if {
	identity.action_name in {"update", "delete"}
}

# Intercettare transazioni di fatturazione
# con importi superiori a 5000 (ritenute operazioni a rischio che richiedono step-up)
is_sensitive_action if {
	identity.normalized_collection_name == "billing"
	walk(identity.query_doc, [path, value])
	some segment in path
	is_string(segment)
	segment in {"billing_amount", "billing_amount_approx"}
	is_number(value)
	value > 5000
}

# Blocca le azioni sensibili se non è presente un token step-up biometrico valido e fresco
hard_deny if {
	is_sensitive_action
	not identity.token_step_up_fresh
}

# Blocca immediatamente i client non autenticati o sprovvisti di ruolo valido
hard_deny if {
	identity.current_role == "unknown"
}

# ─── Content Inspection ──────────────────────────────────────

# Regola di Compliance Clinica: I medici possono aggiornare le cartelle cliniche
# solo se specificano un filtro mirato per il singolo paziente
inspection_violation if {
	identity.is_db_query
	identity.normalized_collection_name == "clinical_records"
	identity.action_name == "update"
	not identity.query_has_field("patient_id")
}

# Regola di Compliance Privacy: Impedisce query vuote (es. {}) sulla tabella pazienti
# a ruoli non amministratori per prevenire il dump massivo dell'anagrafica
inspection_violation if {
	identity.is_db_query
	identity.normalized_collection_name == "patients"
	identity.current_role != "admin"
	identity.action_name == "find"
	identity.is_empty_query
}

# Matrix dei permessi (Zero Trust Default Deny per i campi vuoti {})
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
