package envoy.authz

import future.keywords
import data.envoy.authz.identity
import data.envoy.authz.criteria
import data.envoy.authz.risk


# Risposta OPA strutturata per ext_authz di Envoy
main := {
	"allowed": allow,
	"http_status": 403,
	"body": denied_body,
	"response_headers_to_add": response_headers,
	"denied_response_headers_to_add": response_headers,
	"dynamic_metadata": response_headers,
	"response_metadata": response_metadata
}

default allow := false

# Regola di autorizzazione principale
allow if {
	criteria.criteria_allow
	risk.risk_score_allow
	is_valid_oidc_if_present
}

default deny := false

deny if {
	not allow
}


# Valida il Token OIDC solo se il protocollo in uso è MONGODB-OIDC
is_valid_oidc_if_present if {
	not identity.is_mongodb_oidc
}

is_valid_oidc_if_present if {
	identity.valid_oidc_token
}


# Determina il codice d'errore specifico in base alla regola violata
deny_reason := reason if {
	identity.is_mongodb_oidc
	not identity.valid_oidc_token
	reason := "OIDC_TOKEN_INVALID"
} else := reason if {
	not risk.risk_score_allow
	reason := "RISK_THRESHOLD_EXCEEDED"
} else := reason if {
	not criteria.valid_action
	reason := "INVALID_ACTION"
} else := reason if {
	not criteria.role_action_allowed
	reason := "RBAC_DENIED"
} else := reason if {
	criteria.is_sensitive_action
	not identity.token_has_step_up
	reason := "STEP_UP_REQUIRED"
} else := reason if {
	criteria.is_sensitive_action
	identity.token_has_step_up
	not identity.token_step_up_fresh
	reason := "STEP_UP_STALE"
} else := reason if {
	identity.current_role == "unknown"
	reason := "UNAUTHENTICATED"
} else := reason if {
	criteria.inspection_violation
	reason := "INSPECTION_VIOLATION"
} else := "POLICY_DENIED"


deny_message := msg if {
	deny_reason == "OIDC_TOKEN_INVALID"
	msg := "Sessione di autenticazione non valida o scaduta. Effettua nuovamente il login hardware."
} else := msg if {
	deny_reason == "RISK_THRESHOLD_EXCEEDED"
	msg := sprintf("Accesso negato: il livello di rischio calcolato (%d) supera la soglia di sicurezza consentita.", [risk.risk_score])
} else := msg if {
	deny_reason == "INVALID_ACTION"
	msg := "Operazione database non valida o non supportata."
} else := msg if {
	deny_reason == "RBAC_DENIED"
	msg := sprintf("Il tuo ruolo (%s) non dispone dei permessi necessari per eseguire l'azione '%s' sulla collezione '%s'.", [identity.current_role, identity.action_name, identity.collection_name])
} else := msg if {
	deny_reason == "STEP_UP_REQUIRED"
	msg := "Autenticazione secondaria (Step-up) richiesta. Effettua la verifica Touch ID / Windows Hello per procedere con questa operazione sensibile."
} else := msg if {
	deny_reason == "STEP_UP_STALE"
	msg := "Sessione di verifica biometrica scaduta. Si prega di rieffettuare la verifica sul dispositivo."
} else := msg if {
	deny_reason == "UNAUTHENTICATED"
	msg := "Utente non identificato o certificato non registrato."
} else := msg if {
	deny_reason == "INSPECTION_VIOLATION"
	identity.current_role == "doctor"
	identity.normalized_collection_name == "clinical_records"
	identity.action_name == "update"
	not identity.query_has_field("patient_id")
	msg := "I medici sono tenuti a specificare il filtro patient_id durante l'aggiornamento delle cartelle cliniche."
} else := msg if {
	deny_reason == "INSPECTION_VIOLATION"
	msg := "Richiesta non conforme: controlli di sicurezza a livello applicativo (L7) hanno bloccato la query."
} else := "Richiesta respinta dalle politiche di sicurezza Zero Trust."


denied_body := json.marshal({
	"status": "error",
	"error_type": "policy_denied",
	"reason": deny_reason,
	"message": deny_message,
	"role": identity.current_role,
	"translated_collection": identity.collection_name
})

# ─── SECTION 4: RESPONSE HEADERS & METADATA ──────────────────────────────────

# Header HTTP iniettati da Envoy verso Splunk per telemetria
response_headers := {
	"x-zta-user": identity.user_identity,
	"x-zta-device": identity.device_identity,
	"x-zta-network": identity.network_identity_str,
	"x-zta-action": identity.action_name,
	"x-zta-collection": identity.collection_name,
	"x-zta-risk-score": sprintf("%d", [risk.risk_score]),
	"x-zta-decision": decision_label,
	"x-zta-role": identity.current_role,
	"x-zta-eff-risk": sprintf("%d", [risk.risk_score]),
	"x-zta-command": identity.action_name,
	"x-zta-block-reason": final_block_reason
}

response_metadata := {
	"x-zta-user": identity.user_identity,
	"x-zta-device": identity.device_identity,
	"x-zta-command": identity.action_name,
	"x-zta-collection": identity.collection_name,
	"x-zta-decision": decision_label
}

final_block_reason := deny_reason if {
	deny
} else := "none"

decision_label := "ALLOW" if {
	allow
} else := "DENY"
