package envoy.authz

import future.keywords
import data.envoy.authz.identity
import data.envoy.authz.criteria
import data.envoy.authz.risk


# Structured OPA response for Envoy ext_authz
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

# Main authorization rule
allow if {
	criteria.criteria_allow
	risk.risk_score_allow
	is_valid_oidc_if_present
}

default deny := false

deny if {
	not allow
}


# Validate OIDC Token only if the protocol in use is MONGODB-OIDC
is_valid_oidc_if_present if {
	not identity.is_mongodb_oidc
}

is_valid_oidc_if_present if {
	identity.valid_oidc_token
}


# Determines the specific error code based on the violated rule
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
	msg := "Invalid or expired authentication session. Please perform hardware login again."
} else := msg if {
	deny_reason == "RISK_THRESHOLD_EXCEEDED"
	msg := sprintf("Access denied: calculated risk level (%d) exceeds the allowed security threshold.", [risk.risk_score])
} else := msg if {
	deny_reason == "INVALID_ACTION"
	msg := "Invalid or unsupported database operation."
} else := msg if {
	deny_reason == "RBAC_DENIED"
	msg := sprintf("Your role (%s) does not have the necessary permissions to perform the action '%s' on collection '%s'.", [identity.current_role, identity.action_name, identity.collection_name])
} else := msg if {
	deny_reason == "STEP_UP_REQUIRED"
	msg := "Secondary authentication (Step-up) required. Perform Touch ID / Windows Hello verification to proceed with this sensitive operation."
} else := msg if {
	deny_reason == "STEP_UP_STALE"
	msg := "Biometric verification session expired. Please re-verify on the device."
} else := msg if {
	deny_reason == "UNAUTHENTICATED"
	msg := "Unidentified user or unregistered certificate."
} else := msg if {
	deny_reason == "INSPECTION_VIOLATION"
	identity.current_role == "doctor"
	identity.normalized_collection_name == "clinical_records"
	identity.action_name == "update"
	not identity.query_has_field("patient_id")
	msg := "Doctors are required to specify the patient_id filter when updating clinical records."
} else := msg if {
	deny_reason == "INSPECTION_VIOLATION"
	msg := "Non-compliant request: application-level security controls (L7) blocked the query."
} else := "Request rejected by Zero Trust security policies."


denied_body := json.marshal({
	"status": "error",
	"error_type": "policy_denied",
	"reason": deny_reason,
	"message": deny_message,
	"role": identity.current_role,
	"translated_collection": identity.collection_name
})

# SECTION 4: RESPONSE HEADERS & METADATA

# HTTP headers injected by Envoy towards Splunk for telemetry
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
