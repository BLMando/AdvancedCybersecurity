package envoy.authz

import future.keywords

# Default to deny. A request must prove it is safe.
default allow := false

# Final decision: risk must stay under the threshold and the action must be
# permitted for the current collection.
allow if {
	valid_action
	risk_score <= threshold
	action_allowed
}

# Risk is the sum of the three identity dimensions.
risk_score := total_risk if {
	total_risk := user_risk + device_risk + network_risk
}

# Known users are trusted; unknown users add risk.
user_risk := 0 if {
	known_users[user_identity]
} else := 30

# A hardware-bound device is lower risk than a generic fingerprint.
device_risk := 0 if {
	device_identity != "no-tpm"
} else := 20

# Internal networks are treated as lower risk than external ones.
network_risk := 0 if {
	is_internal_network
} else := 15

# Each MongoDB command has its own tolerance level.
threshold := t if {
	action_name == "find"
	t := 60
} else := t if {
	action_name == "insert"
	t := 40
} else := t if {
	action_name == "update"
	t := 30
} else := t if {
	action_name == "delete"
	t := 20
}

# Some actions are always suspicious, especially destructive ones.
action_allowed if {
	valid_action
	not is_destructive_operation
	not collection_is_sensitive
}

action_allowed if {
	valid_action
	collection_is_sensitive
	risk_score < threshold / 2
	not is_destructive_operation
}

# The policy accepts both Envoy-shaped input and direct test payloads.
user_identity := user if {
	user := object.get(
		object.get(input, "attributes", {}),
		"source",
		{}
	)
	user != {}
	user = input.attributes.source.principal
} else := user if {
	user := input.parsed_body.user
	user != ""
} else := "unknown"

# Device identity is provided by Envoy when available; otherwise the policy
# falls back to the no-tpm marker used in the lab.
device_identity := device if {
	device := input.parsed_body.device
	device != ""

} else := ja3 if {
	tls_meta := object.get(object.get(object.get(input, "attributes", {}), "metadata_context", {}), "filter_metadata", {})
	tls_inspector := object.get(tls_meta, "envoy.filters.listener.tls_inspector", {})
	ja3 := object.get(tls_inspector, "ja3", "")
	ja3 != ""

} else := ja3h if {
	tls_meta := object.get(object.get(object.get(input, "attributes", {}), "metadata_context", {}), "filter_metadata", {})
	tls_inspector := object.get(tls_meta, "envoy.filters.listener.tls_inspector", {})
	ja3h := object.get(tls_inspector, "ja3_hash", "")
	ja3h != ""

} else := "no-tpm"

# Network identity is simply the source IP used for subnet checks.
network_identity := ip if {
	ip := input.parsed_body.network_ip
	ip != ""

} else := ip if {
	ip := object.get(object.get(object.get(input, "attributes", {}), "source", {}), "address", "")
	ip != ""

} else := "0.0.0.0"

# The command and collection tell us whether the operation is read-only,
# write-oriented or destructive.
action_name := cmd if {
	cmd := input.parsed_body.command
	cmd in ["find", "insert", "update", "delete", "drop"]
} else := "unknown"

collection_name := coll if {
	coll := input.parsed_body.collection
	coll != ""
} else := "unknown"

# Users explicitly trusted in the current test scenario.
known_users := {
	"mario.rossi",
	"anna.verdi",
	"admin",
	"test.user"
}

# Collections that deserve stricter handling because they contain more
# valuable or sensitive data.
sensitive_collections := {
	"payments",
	"credentials",
	"audit_logs",
	"security_events"
}

collection_is_sensitive if {
	collection_name in sensitive_collections
}

valid_action if {
	action_name in {"find", "insert", "update", "delete"}
}

# Simple subnet matching is enough for this phase.
is_internal_network if {
	cidr_match := regex.match(`^(172\.20\.|10\.)`, network_identity)
	cidr_match == true
}

# Drop and database-destroying actions are never acceptable.
is_destructive_operation if {
	action_name in ["drop", "delete_database"]
}

# These headers summarize the evaluation context for debugging and audit.
response_headers := object.union_n([
	{"x-zta-user": user_identity},
	{"x-zta-device": device_identity},
	{"x-zta-network": network_identity},
	{"x-zta-action": action_name},
	{"x-zta-collection": collection_name},
	{"x-zta-risk-score": sprintf("%d", [risk_score])},
	{"x-zta-decision": decision_label}
])

decision_label := "ALLOW" if {
	allow
} else := "DENY"

# Explicit deny rules help with clarity in tests and with non-recoverable cases.
deny if {
	risk_score > threshold
}

deny if {
	is_destructive_operation
}

deny if {
	not valid_action
}

# ─── Test Helpers ─────────────────────────────────
test_legitimate_user if {
	allow with input as {
		"attributes": {"source": {"principal": "mario.rossi"}},
		"parsed_body": {
			"user": "mario.rossi",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "utenti"
		}
	}
}

test_unknown_user_denied if {
	not allow with input as {
		"parsed_body": {
			"user": "attacker.evil",
			"device": "no-tpm",
			"network_ip": "192.168.1.100",
			"command": "find",
			"collection": "payments"
		}
	}
}

test_destructive_denied if {
	deny with input as {
		"parsed_body": {
			"user": "mario.rossi",
			"command": "drop",
			"collection": "utenti"
		}
	}
}

