# Unit test suite for validating OPA policies (Zero Trust PDP).

package envoy.authz

import future.keywords

# Helper to simulate legitimate HTTP requests (mTLS)
mock_input_mtls(role, collection, action) := {
	"attributes": {
		"source": {
			"principal": sprintf("test.%v", [role]),
			"address": {
				"socketAddress": {
					"address": "172.20.0.5"
				}
			},
			"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
		}
	},
	"parsed_body": {
		"user": sprintf("test.%v", [role]),
		"device": "device-laptop-001",
		"network_ip": "172.20.0.5",
		"command": action,
		"collection": collection,
		"query": "{\"patient_id\": \"P001\"}"
	}
}

# Helper to simulate OIDC requests (mTLS + JWT Token)
mock_input_oidc(role, user, action, collection) := {
	"attributes": {
		"source": {
			"principal": user,
			"address": {
				"socketAddress": {
					"address": "172.20.0.5"
				}
			},
			"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
		}
	},
	"parsed_body": {
		"command": action,
		"collection": collection,
		"mechanism": "MONGODB-OIDC",
		"query": {
			"payload": "a.b.c"
		}
	}
}

# 1. RBAC Authorization Tests (Permission Matrix)

test_rbac_allowed_admin_all if {
	allow with input as mock_input_mtls("admin", "billing", "insert")
		with data.envoy.authz.identity.parsed_client_cert as {"Subject": {"Title": ["admin"], "CommonName": ["test.admin"]}}
}

test_rbac_allowed_doctor_patients if {
	allow with input as mock_input_mtls("doctor", "patients", "find")
		with data.envoy.authz.identity.parsed_client_cert as {"Subject": {"Title": ["doctor"], "CommonName": ["test.doctor"]}}
}

test_rbac_denied_doctor_billing if {
	deny with input as mock_input_mtls("doctor", "billing", "find")
		with data.envoy.authz.identity.parsed_client_cert as {"Subject": {"Title": ["doctor"], "CommonName": ["test.doctor"]}}
}

test_rbac_denied_receptionist_billing if {
	deny with input as mock_input_mtls("receptionist", "billing", "find")
		with data.envoy.authz.identity.parsed_client_cert as {"Subject": {"Title": ["receptionist"], "CommonName": ["test.receptionist"]}}
}

# 2. Biometric Step-Up Tests (Sensitive Actions)

test_step_up_allowed_with_fresh_token if {
	input_req := mock_input_oidc("doctor", "test.doctor", "delete", "admissions")
	allow with input as input_req
		with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "step_up": true, "step_up_time": 9999999999, "exp": 9999999999}
		with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
		with data.envoy.authz.identity.device_identity as "mock-device"
		with data.envoy.authz.identity.is_valid_token_binding as true
}

test_step_up_denied_without_token if {
	input_req := mock_input_oidc("doctor", "test.doctor", "delete", "admissions")
	deny with input as input_req
		with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "step_up": false, "exp": 9999999999}
		with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
		with data.envoy.authz.identity.is_valid_token_binding as true
}

# 3. OIDC Token Binding Tests (Token-Certificate Linking)

test_oidc_binding_allowed_matching_cn if {
	input_req := mock_input_oidc("doctor", "test.doctor", "find", "patients")
	allow with input as input_req
		with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "exp": 9999999999, "cnf": {"x5t#S256_hex": "mock-fingerprint"}}
		with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
		with data.envoy.authz.identity.cert_der_bytes as "mock-der"
		with crypto.sha256 as "mock-fingerprint"
}

test_oidc_binding_denied_mismatch_cn if {
	input_req := mock_input_oidc("doctor", "test.doctor", "find", "patients")
	deny with input as input_req
		with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "exp": 9999999999, "cnf": {"x5t#S256_hex": "mock-fingerprint"}}
		with data.envoy.authz.identity.cert_subject_cn as "attacker.name"
		with data.envoy.authz.identity.cert_der_bytes as "mock-der"
		with crypto.sha256 as "mock-fingerprint"
}

test_oidc_binding_denied_mismatch_fingerprint if {
	input_req := mock_input_oidc("doctor", "test.doctor", "find", "patients")
	deny with input as input_req
		with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "exp": 9999999999, "cnf": {"x5t#S256_hex": "different-fingerprint"}}
		with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
		with data.envoy.authz.identity.cert_der_bytes as "mock-der"
		with crypto.sha256 as "mock-fingerprint"
}

# 4. L7 Query Content Inspection Tests

test_query_inspection_clinical_records_needs_patient_id if {
	input_invalid := {
		"attributes": {
			"source": {
				"principal": "test.doctor",
				"address": {
					"socketAddress": {
						"address": "172.20.0.5"
					}
				}
			}
		},
		"parsed_body": {
			"command": "update",
			"collection": "clinical_records",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	deny with input as input_invalid
		with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "step_up": true, "step_up_time": 9999999999, "exp": 9999999999}
		with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
		with data.envoy.authz.identity.device_identity as "mock-device"
		with data.envoy.authz.identity.is_valid_token_binding as true
	
	deny_reason == "INSPECTION_VIOLATION" with input as input_invalid
		with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "step_up": true, "step_up_time": 9999999999, "exp": 9999999999}
		with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
		with data.envoy.authz.identity.device_identity as "mock-device"
		with data.envoy.authz.identity.is_valid_token_binding as true
}

test_query_inspection_clinical_records_allowed_with_patient_id if {
	input_valid := {
		"attributes": {
			"source": {
				"principal": "test.doctor",
				"address": {
					"socketAddress": {
						"address": "172.20.0.5"
					}
				}
			}
		},
		"parsed_body": {
			"command": "update",
			"collection": "clinical_records",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c",
				"patient_id": "P001",
				"notes": "updated"
			}
		}
	}
	allow with input as input_valid
		with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "step_up": true, "step_up_time": 9999999999, "exp": 9999999999}
		with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
		with data.envoy.authz.identity.device_identity as "mock-device"
		with data.envoy.authz.identity.is_valid_token_binding as true
}

test_query_inspection_patients_find_empty_denied if {
	input_invalid := {
		"attributes": {
			"source": {
				"principal": "test.doctor",
				"address": {
					"socketAddress": {
						"address": "172.20.0.5"
					}
				}
			}
		},
		"parsed_body": {
			"command": "find",
			"collection": "patients",
			"query": "{}"
		}
	}
	deny with input as input_invalid
		with data.envoy.authz.identity.parsed_client_cert as {"Subject": {"Title": ["doctor"], "CommonName": ["test.doctor"]}}
}

# 5. Dynamic Risk Calculation Tests (Adaptive Threshold)

test_risk_denied_if_exceeds_threshold if {
	# Force a high risk score by simulating an external network and a delete action
	input_unsafe := {
		"attributes": {
			"source": {
				"principal": "test.doctor",
				"address": {
					"socketAddress": {
						"address": "8.8.8.8"
					}
				}
			}
		},
		"parsed_body": {
			"user": "test.doctor",
			"device": "no-tpm",
			"network_ip": "8.8.8.8",
			"command": "delete",
			"collection": "admissions",
			"query": "{\"admission_id\": \"A001\"}"
		}
	}
	deny with input as input_unsafe
		with data.envoy.authz.identity.parsed_client_cert as {"Subject": {"Title": ["unknown"], "CommonName": ["unknown"]}}
	deny_reason == "RISK_THRESHOLD_EXCEEDED" with input as input_unsafe
		with data.envoy.authz.identity.parsed_client_cert as {"Subject": {"Title": ["unknown"], "CommonName": ["unknown"]}}
}
