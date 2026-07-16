# Suite di test unitari per la validazione delle politiche OPA (Zero Trust PDP).

package envoy.authz

import future.keywords

# Helper per simulare richieste HTTP legittime (mTLS)
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

# Helper per simulare richieste OIDC (mTLS + Token JWT)
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

# ─── 1. Test di Autorizzazione RBAC (Matrice Permessi) ────────────────────────

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

# ─── 2. Test Biometric Step-Up (Azioni Sensitive) ─────────────────────────────

test_step_up_allowed_with_fresh_token if {
	input_req := mock_input_oidc("doctor", "test.doctor", "delete", "admissions")
	allow with input as input_req
		with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "step_up": true, "step_up_time": 9999999999, "exp": 9999999999}
		with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
		with data.envoy.authz.identity.device_identity as "mock-device"
}

test_step_up_denied_without_token if {
	input_req := mock_input_oidc("doctor", "test.doctor", "delete", "admissions")
	deny with input as input_req
		with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "step_up": false, "exp": 9999999999}
		with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
}

# ─── 3. Test OIDC Token Binding (Collegamento Token-Certificato) ──────────────

test_oidc_binding_allowed_matching_cn if {
	input_req := mock_input_oidc("doctor", "test.doctor", "find", "patients")
	allow with input as input_req
		with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "exp": 9999999999}
		with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
}

test_oidc_binding_denied_mismatch_cn if {
	input_req := mock_input_oidc("doctor", "test.doctor", "find", "patients")
	deny with input as input_req
		with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "exp": 9999999999}
		with data.envoy.authz.identity.cert_subject_cn as "attacker.name"
}

# ─── 4. Test L7 Query Content Inspection ──────────────────────────────────────

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
	
	deny_reason == "INSPECTION_VIOLATION" with input as input_invalid
		with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "step_up": true, "step_up_time": 9999999999, "exp": 9999999999}
		with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
		with data.envoy.authz.identity.device_identity as "mock-device"
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

# ─── 5. Test Calcolo Dinamico del Rischio (Adaptive Threshold) ────────────────

test_risk_denied_if_exceeds_threshold if {
	# Forza un punteggio di rischio alto simulando una rete esterna ed un'azione di delete
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
		with data.envoy.authz.identity.parsed_client_cert as {"Subject": {"Title": ["doctor"], "CommonName": ["test.doctor"]}}
	deny_reason == "RISK_THRESHOLD_EXCEEDED" with input as input_unsafe
		with data.envoy.authz.identity.parsed_client_cert as {"Subject": {"Title": ["doctor"], "CommonName": ["test.doctor"]}}
}
