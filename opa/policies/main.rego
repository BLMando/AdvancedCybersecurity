# Entrypoint principale per Envoy, bypass e mapping degli header di risposta.

package envoy.authz

import future.keywords
import data.envoy.authz.identity
import data.envoy.authz.criteria
import data.envoy.authz.risk
import data.envoy.authz.policy

# ─── Real-time Revocation Helpers (TTL cache: 2 seconds) ──────────────────────
# Called by OPA on EVERY MongoDB message that passes through the Wasm filter.
# Short TTL ensures revocation takes effect within 2 seconds of issuance.
# These rules are SAFE: if the PKI endpoint is unreachable, they return false
# (not-revoked), so the connection degrades gracefully instead of blocking all
# traffic when the identity service is temporarily down.

cert_is_revoked(cn) if {
	cn != ""
	cn != "unknown"
	resp := http.send({
		"method": "GET",
		"url": sprintf("https://identity-pki:8080/api/revocation/%s", [cn]),
		"tls_insecure_skip_verify": true,
		"cache": true,
		"force_cache_duration_seconds": 2,
		"timeout": "500000000"
	})
	resp.status_code == 200
	resp.body.revoked == true
}

jwt_is_revoked(jti) if {
	jti != ""
	resp := http.send({
		"method": "GET",
		"url": sprintf("https://identity-pki:8080/api/jwt/revocation/%s", [jti]),
		"tls_insecure_skip_verify": true,
		"cache": true,
		"force_cache_duration_seconds": 2,
		"timeout": "500000000"
	})
	resp.status_code == 200
	resp.body.revoked == true
}

# ─── Hybrid ZTA Decision Rule ─────────────────────────────────────────────────

default allow := false

# Main rule: evaluates on every MongoDB query message.
allow if {
	not cert_is_revoked(identity.user_identity)
	not jwt_is_revoked(identity.jti)
	criteria.criteria_allow
	risk.risk_score_allow
	not policy.is_malicious
}

main := {
	"allowed": allow,
	"response_headers_to_add": response_headers,
	"denied_response_headers_to_add": response_headers,
	"dynamic_metadata": response_headers,
	"response_metadata": response_metadata
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
	not cert_is_revoked(identity.user_identity)
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

response_metadata := {
	"x-zta-user": identity.user_identity,
	"x-zta-device": identity.device_identity,
	"x-zta-command": identity.action_name,
	"x-zta-collection": identity.collection_name,
	"x-zta-decision": decision_label
}

decision_label := "ALLOW" if {
	allow
} else := "DENY"
