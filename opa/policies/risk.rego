# Calcolo dinamico del punteggio di rischio e integrazione delle tabelle Splunk.

package envoy.authz.risk

import future.keywords
import data.envoy.authz.identity

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

user_risk_val := 0 if { identity.known_users[identity.user_identity] } else := 30

device_risk_val := 0 if { identity.device_identity != "no-tpm" } else := 20

network_risk_val := 0 if { identity.is_internal_network } else := 15

# Behavior Risk Dimension (30% weight)
behavior_risk := action_risk_val + collection_sensitivity_val

action_risk_val := 0 if {
	identity.action_name == "find"
} else := 20 if {
	identity.action_name == "insert"
} else := 30 if {
	identity.action_name == "update"
} else := 50 if {
	identity.action_name == "delete"
} else := 10 if {
	identity.action_name == "aggregate"
} else := 100 if {
	identity.action_name in {"drop", "delete_database"}
} else := 0

collection_sensitivity_val := 15 if {
	identity.normalized_collection_name in {"clinical_records", "billing"}
} else := 0

# Content Risk Dimension (20% weight) - checks queries for MongoDB
content_risk := 0 if {
	identity.is_http_request
} else := 100 if {
	identity.normalized_collection_name == "clinical_records"
	identity.action_name in {"find", "update"}
	not identity.query_has_field("patient_id")
} else := 100 if {
	identity.normalized_collection_name == "billing"
	identity.query_has_field("$where")
} else := 100 if {
	identity.normalized_collection_name == "billing"
	identity.query_has_field("$function")
} else := 100 if {
	identity.normalized_collection_name == "patients"
	identity.current_role != "admin"
	identity.action_name == "find"
	identity.is_empty_query
} else := 0

# Anomaly Risk Dimension (20% weight) - Splunk sidecar statistics (Asynchronous In-Memory)
anomaly_risk := boost if {
	# If we have a trust registry in OPA and the user is present in it
	user_history := data.splunk.trust_registry[identity.user_identity]
	
	# If the current device was never used by this user in the last 24h
	not user_history[identity.device_identity]
	
	boost := 100
} else := boost if {
	# If the user is present, and the device is known, but the network IP's /24 prefix is unseen for this device
	user_history := data.splunk.trust_registry[identity.user_identity]
	ips := user_history[identity.device_identity]
	
	allowed_prefixes := { p | ip := ips[_]; p := subnet_24(ip) }
	not subnet_24(identity.network_identity_str) in allowed_prefixes
	
	boost := 60
} else := boost if {
	# Combine standard anomalies with Snort alerts, nftables drops, and MongoDB failed logins
	boosts := [
		object.get(data.splunk.anomalies, [identity.user_identity, "risk_boost"], 0),
		object.get(data.splunk.snort_alerts, [identity.network_identity_str, "risk_boost"], 0),
		object.get(data.splunk.nftables_alerts, [identity.network_identity_str, "risk_boost"], 0),
		object.get(data.splunk.mongo_failures, [identity.user_identity, "risk_boost"], 0)
	]
	max_boost := max(boosts)
	max_boost > 0
	boost := max_boost
} else := 0

subnet_24(ip) := prefix if {
	parts := split(ip, ".")
	count(parts) == 4
	prefix := concat(".", [parts[0], parts[1], parts[2]])
} else := ip

# ─── Adaptive Thresholds ──────────────────────────────────────────────────────

adaptive_threshold := t if {
	identity.current_role == "admin"
	t := 60
} else := t if {
	identity.action_name == "find"
	t := 30
} else := t if {
	identity.action_name == "insert"
	t := 20
} else := t if {
	identity.action_name == "update"
	t := 15
} else := t if {
	identity.action_name == "delete"
	t := 10
} else := 15
