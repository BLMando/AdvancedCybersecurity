# Dynamic calculation of the risk score and integration with Splunk tables.

package envoy.authz.risk

import future.keywords
import data.envoy.authz.identity
import data.envoy.authz.criteria

default risk_score_allow := false

risk_score_allow if {
	risk_score <= adaptive_threshold
}

risk_score := round(total_risk_score)

total_risk_score := (
	identity_risk * 40 +
	behavior_risk * 20 +
	anomaly_risk  * 40
) / 100

# Identity Risk Dimension
identity_risk := user_risk_val + device_risk_val + network_risk_val

user_risk_val := 0 if { identity.current_role != "unknown" } else := 30

device_risk_val := 0 if { identity.device_identity != "no-tpm" } else := 20

network_risk_val := 0 if { identity.is_internal_network } else := 15

# Behavior Risk Dimension
behavior_risk := action_risk_val + collection_sensitivity_val

action_risk_val := val if {
	risk_map := {"find": 0, "aggregate": 10, "insert": 20, "update": 30, "delete": 50, "drop": 100, "delete_database": 100}
	val := risk_map[identity.action_name]
} else := 0

collection_sensitivity_val := 15 if {
	identity.normalized_collection_name in {"clinical_records", "billing"}
} else := 0

# Anomaly Risk Dimension
anomaly_risk := boost if {
	criteria.criteria_allow
	# Avoid external calls for excluded system commands (bypass)
	not identity.action_name in {"hello", "isMaster", "saslContinue", "buildinfo", "buildInfo", "ping", "getLog", "getCmdLineOpts", "serverStatus"}

	resp := http.send({
		"method": "POST",
		"url": "https://splunk:8089/servicesNS/admin/zta/search/jobs",
		"headers": {
			"Content-Type": "application/x-www-form-urlencoded",
			"Authorization": "Basic YWRtaW46U3BsdW5rUGFzc3dvcmQxMjMh"
		},
		"raw_body": sprintf("search=%%7C+savedsearch+Calcolo_Rischio_Contestuale_ZTA+user%%3D%%22%v%%22+client_ip%%3D%%22%v%%22&exec_mode=oneshot&output_mode=json", [identity.user_identity, identity.network_identity_str]),
		"tls_ca_cert_file": "/etc/certs/ca/ca.crt", # Cryptographic validation via the project CA
		"timeout": "400000000" # 400ms in nanoseconds
	})

	resp.status_code == 200
	score_str := resp.body.results[0].anomaly_risk
	boost := to_number(score_str)
} else := 0

# Adaptive Thresholds

adaptive_threshold := t if {
	identity.current_role == "admin"
	t := 60
} else := t if {
	thresholds := {"find": 40, "insert": 30, "update": 30, "delete": 30}
	t := thresholds[identity.action_name]
} else := 20
