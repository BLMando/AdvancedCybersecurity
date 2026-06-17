# Entrypoint principale per Envoy, bypass e mapping degli header di risposta.

package envoy.authz

import future.keywords
import data.envoy.authz.identity
import data.envoy.authz.criteria
import data.envoy.authz.risk

# ─── Hybrid ZTA Decision Rule ─────────────────────────────────────────────────

default allow := false

allow if {
	criteria.criteria_allow
	risk.risk_score_allow
}

main := {
	"allowed": allow,
	"response_headers_to_add": response_headers,
	"denied_response_headers_to_add": response_headers,
	"dynamic_metadata": response_headers
}

# OPA Bypass Rules for database system commands
allow if {
	identity.action_name in {"hello", "isMaster", "saslContinue", "buildinfo", "buildInfo"}
}

allow if {
	identity.action_name in {"ping", "getLog", "getCmdLineOpts", "serverStatus"}
}

allow if {
	identity.action_name == "saslStart"
	not identity.is_mongodb_oidc
}

allow if {
	identity.action_name == "saslStart"
	identity.is_mongodb_oidc
	identity.valid_oidc_token
}

# Allow connection establishment when the MongoDB command has not been parsed yet.
allow if {
	identity.action_name == "unknown"
	identity.current_role in {"admin", "doctor", "billing_staff", "auditor", "receptionist"}
	risk.risk_score_allow
}

allow if {
	identity.action_name == "unknown"
	identity.cert_subject_cn in identity.trusted_proxies
}

# ─── Default Deny ─────────────────────────────────────────────────────────────

default deny := false

deny if {
	not allow
}

# ─── Response Headers ─────────────────────────────────────────────────────────

response_headers := object.union_n([
	{"x-zta-user": identity.user_identity},
	{"x-zta-device": identity.device_identity},
	{"x-zta-network": identity.network_identity_str},
	{"x-zta-action": identity.action_name},
	{"x-zta-collection": identity.collection_name},
	{"x-zta-risk-score": sprintf("%d", [risk.risk_score])},
	{"x-zta-decision": decision_label},
	{"x-zta-role": identity.current_role},
	{"x-zta-eff-risk": sprintf("%d", [risk.risk_score])},
	{"x-zta-command": identity.action_name}
])

decision_label := "ALLOW" if {
	allow
} else := "DENY"
