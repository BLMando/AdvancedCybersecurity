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

user_risk_val := 0 if { identity.current_role != "unknown" } else := 30

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
content_risk := 100 if {
	identity.is_db_query
	identity.normalized_collection_name == "clinical_records"
	identity.action_name == "update"
	not identity.query_has_field("patient_id")
} else := 100 if {
	identity.is_db_query
	identity.normalized_collection_name == "billing"
	identity.query_has_field("$where")
} else := 100 if {
	identity.is_db_query
	identity.normalized_collection_name == "billing"
	identity.query_has_field("$function")
} else := 100 if {
	identity.is_db_query
	identity.normalized_collection_name == "patients"
	identity.current_role != "admin"
	identity.action_name == "find"
	identity.is_empty_query
} else := 0

# Anomaly Risk Dimension (20% weight) - Query sincrona diretta a Splunk via REST API (oneshot)
anomaly_risk := boost if {
	# Evitiamo chiamate esterne per i comandi di sistema esclusi (bypass)
	not identity.action_name in {"hello", "isMaster", "saslContinue", "buildinfo", "buildInfo", "ping", "getLog", "getCmdLineOpts", "serverStatus"}

	resp := http.send({
		"method": "POST",
		"url": "https://splunk:8089/servicesNS/admin/zta/search/jobs",
		"headers": {
			"Content-Type": "application/x-www-form-urlencoded",
			"Authorization": "Basic YWRtaW46U3BsdW5rUGFzc3dvcmQxMjMh"
		},
		"body": sprintf("search=%%7C+savedsearch+Calcolo_Rischio_Contestuale_ZTA+user%%3D%%22%v%%22+client_ip%%3D%%22%v%%22&exec_mode=oneshot&output_mode=json", [identity.user_identity, identity.network_identity_str]),
		"tls_ca_cert_file": "/etc/certs/ca/ca.crt", # Convalida crittografica tramite la CA di progetto
		"timeout": "400000000" # 400ms in nanosecondi
	})

	resp.status_code == 200
	score_str := resp.body.results[0].anomaly_risk
	boost := to_number(score_str)
} else := 0

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
	t := 20
} else := t if {
	identity.action_name == "delete"
	t := 20
} else := 15
