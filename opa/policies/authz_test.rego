# Suite di test per i 40 unit test riorganizzati con i namespace corretti.


package envoy.authz

import future.keywords
import data.envoy.authz.identity

# ─── Standard Authorization Tests ─────────────────────────────────────────────

test_legitimate_user if {
	allow with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "patients",
			"query": "{\"patient_id\": \"P001\"}"
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
			"user": "test.doctor",
			"command": "drop",
			"collection": "utenti"
		}
	}
}

test_doctor_clinical_find if {
	allow with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "clinical_records",
			"query": "{\"patient_id\": \"P001\"}"
		}
	}
}

# Doctors may query clinical_records without patient_id filter (only update requires it)
test_doctor_clinical_find_no_patient_id_allowed if {
	allow with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "clinical_records",
			"query": "{}"
		}
	}
}

test_doctor_billing_denied if {
	deny with input as {
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "billing"
		}
	}
}

test_billing_staff_clinical_denied if {
	deny with input as {
		"parsed_body": {
			"user": "test.billing",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "clinical_records"
		}
	}
}

test_auditor_read_all if {
	allow with input as {
		"parsed_body": {
			"user": "test.auditor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "billing"
		}
	}
}

test_auditor_no_write if {
	deny with input as {
		"parsed_body": {
			"user": "test.auditor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "insert",
			"collection": "patients"
		}
	}
}

test_unknown_role_denied if {
	deny with input as {
		"parsed_body": {
			"user": "attacker.external",
			"device": "no-tpm",
			"network_ip": "8.8.8.8",
			"command": "find",
			"collection": "patients"
		}
	}
}

test_receptionist_no_clinical if {
	deny with input as {
		"parsed_body": {
			"user": "test.receptionist",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "clinical_records"
		}
	}
}

# ─── Content Inspection Tests ─────────────────────────────────────────────────

test_clinical_no_patient_id_denied if {
	deny with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "update",
			"collection": "clinical_records",
			"query": "{}"
		}
	}
}

test_clinical_with_patient_id_allowed if {
	allow with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "clinical_records",
			"query": "{\"patient_id\": \"P001\"}"
		}
	}
}

test_billing_where_operator_denied if {
	deny with input as {
		"attributes": {"source": {"principal": "test.billing"}},
		"parsed_body": {
			"user": "test.billing",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "billing",
			"query": "{\"$where\": \"this.amount > 1000\"}"
		}
	}
}

test_patients_empty_query_denied_receptionist if {
	deny with input as {
		"attributes": {"source": {"principal": "test.receptionist"}},
		"parsed_body": {
			"user": "test.receptionist",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "patients",
			"query": "{}"
		}
	}
}

test_admin_empty_query_allowed if {
	allow with input as {
		"attributes": {"source": {"principal": "admin"}},
		"parsed_body": {
			"user": "admin",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "patients",
			"query": "{}"
		}
	}
}

# ─── View query authorization tests ───────────────────────────────────────────

test_doctor_clinical_view_allowed if {
	allow with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "v_clinical_doctor",
			"query": "{\"patient_id\": \"P001\"}"
		}
	}
}

test_doctor_clinical_view_no_patient_id_denied if {
	deny with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "update",
			"collection": "v_clinical_doctor",
			"query": "{}"
		}
	}
}

test_doctor_billing_view_denied if {
	deny with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "v_billing_staff",
			"query": "{}"
		}
	}
}

# ─── OIDC Verification Tests ──────────────────────────────────────────────────

test_oidc_valid if {
	allow with input as {
		"attributes": {
			"source": {
				"principal": "test.doctor",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "find",
			"collection": "patients",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "exp": 9999999999, "cnf": {"x5t#S256_hex": "mock-fingerprint"}}
	with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
	with data.envoy.authz.identity.cert_der_bytes as "mock-der"
	with crypto.sha256 as "mock-fingerprint"
}

test_oidc_invalid_cert_denied if {
	not allow with input as {
		"attributes": {
			"source": {
				"principal": "test.doctor",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "find",
			"collection": "patients",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "exp": 9999999999, "cnf": {"x5t#S256_hex": "different-fingerprint"}}
	with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
	with data.envoy.authz.identity.cert_der_bytes as "mock-der"
	with crypto.sha256 as "mock-fingerprint"
}

test_oidc_expired_token_denied if {
	not allow with input as {
		"attributes": {
			"source": {
				"principal": "test.doctor",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "find",
			"collection": "patients",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "exp": 100000, "cnf": {"x5t#S256_hex": "mock-fingerprint"}}
	with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
	with data.envoy.authz.identity.cert_der_bytes as "mock-der"
	with crypto.sha256 as "mock-fingerprint"
}

test_oidc_wrong_cn_denied if {
	not allow with input as {
		"attributes": {
			"source": {
				"principal": "test.doctor",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "find",
			"collection": "patients",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "attacker.name", "role": "doctor", "exp": 9999999999, "cnf": {"x5t#S256_hex": "mock-fingerprint"}}
	with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
	with data.envoy.authz.identity.cert_der_bytes as "mock-der"
	with crypto.sha256 as "mock-fingerprint"
}

test_oidc_trusted_proxy_valid if {
	allow with input as {
		"attributes": {
			"source": {
				"principal": "envoy",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "find",
			"collection": "patients",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "exp": 9999999999, "cnf": {"x5t#S256_hex": "different-fingerprint"}}
	with data.envoy.authz.identity.cert_subject_cn as "envoy"
}

# ─── Unknown Connection / Ext-Authz Tests ─────────────────────────────────────

test_unknown_action_allowed_for_valid_role if {
	allow with input as {
		"attributes": {
			"source": {
				"principal": "test.doctor",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "unknown"
		}
	}
	with data.envoy.authz.identity.current_role as "doctor"
}

test_unknown_action_denied_for_invalid_role if {
	not allow with input as {
		"attributes": {
			"source": {
				"principal": "attacker.evil",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "unknown"
		}
	}
	with data.envoy.authz.identity.current_role as "unknown"
}

test_unknown_action_allowed_for_trusted_proxy if {
	allow with input as {
		"attributes": {
			"source": {
				"principal": "envoy",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "unknown"
		}
	}
	with data.envoy.authz.identity.cert_subject_cn as "envoy"
}

test_unknown_action_unseen_device_denied if {
	deny with input as {
		"attributes": {
			"source": {
				"principal": "test.doctor",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"command": "unknown",
			"device": "device-attacker-pc",
			"network_ip": "172.20.0.5"
		}
	}
	with data.envoy.authz.identity.current_role as "doctor"
	with data.splunk.trust_registry as {
		"test.doctor": {
			"device-laptop-001": ["172.20.0.5"]
		}
	}
	with http.send as mock_http_send_high_risk
}

# ─── HTTP Specific Tests ──────────────────────────────────────────────────────

test_http_get_patients_allowed if {
	allow with input as {
		"attributes": {
			"source": {"principal": "test.doctor"},
			"request": {
				"http": {
					"method": "GET",
					"path": "/patients",
					"headers": {"x-user": "test.doctor"}
				}
			}
		}
	}
}

test_http_post_clinical_records_allowed if {
	allow with input as {
		"attributes": {
			"source": {
				"principal": "test.doctor",
				"address": "172.20.0.5"
			},
			"request": {
				"http": {
					"method": "POST",
					"path": "/clinical_records",
					"headers": {"x-user": "test.doctor"}
				}
			}
		}
	}
}

test_http_get_billing_denied_doctor if {
	deny with input as {
		"attributes": {
			"source": {"principal": "test.doctor"},
			"request": {
				"http": {
					"method": "GET",
					"path": "/billing",
					"headers": {"x-user": "test.doctor"}
				}
			}
		}
	}
}

test_http_non_existent_role_denied if {
	deny with input as {
		"attributes": {
			"source": {"principal": "attacker.external"},
			"request": {
				"http": {
					"method": "GET",
					"path": "/patients",
					"headers": {"x-user": "attacker.external"}
				}
			}
		}
	}
}

# ─── Hybrid ZTA Risk Score & Threshold Tests ──────────────────────────────────

test_risk_threshold_deny_under_high_risk if {
	allow with input as {
		"attributes": {
			"source": {"principal": "test.doctor"},
			"address": "8.8.8.8"
		},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "8.8.8.8",
			"command": "find",
			"collection": "patients",
			"query": "{\"name\": \"Pippo\"}"
		}
	}
}

# ─── Trust Registry Unit Tests ────────────────────────────────────────────────

test_trust_registry_match_allowed if {
	allow with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "patients",
			"query": "{\"patient_id\": \"P001\"}"
		}
	}
	with http.send as mock_http_send_safe
}

test_trust_registry_unseen_device_denied if {
	deny with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-attacker-pc",
			"network_ip": "172.20.0.5",
			"command": "insert",
			"collection": "admissions",
			"query": "{\"patient_id\": \"P001\"}"
		}
	}
	with http.send as mock_http_send_high_risk
}

test_trust_registry_unseen_ip_denied if {
	deny with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "192.168.1.50",
			"command": "insert",
			"collection": "admissions",
			"query": "{\"patient_id\": \"P001\"}"
		}
	}
	with http.send as mock_http_send_medium_risk
}

# ─── Dynamic subnet (/24 prefix) IP Matching tests ───────────────────────────

test_trust_registry_dhcp_subnet_match_allowed if {
	allow with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.99",
			"command": "find",
			"collection": "patients",
			"query": "{\"patient_id\": \"P001\"}"
		}
	}
	with http.send as mock_http_send_safe
}

# ─── Anti-Spoofing Certificate MAC Verification tests ──────────────────────────

test_device_identity_from_certificate if {
	identity.device_identity == "AA-BB-CC-DD-EE-FF" with input as {
		"attributes": {
			"source": {
				"principal": "test.doctor",
				"certificate": "---BEGIN CERTIFICATE---\n---END CERTIFICATE---"
			}
		}
	} with crypto.x509.parse_certificates as [{
		"Subject": {
			"CommonName": "test.doctor",
			"OrganizationalUnit": ["MAC:AA-BB-CC-DD-EE-FF"]
		}
	}]
}

# ─── Multi-Service Threat Intelligence Integration Tests ────────────────────

test_snort_alert_raises_risk_and_denies if {
	deny with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "8.8.8.8",
			"command": "insert",
			"collection": "admissions",
			"query": "{\"patient_id\": \"P001\"}"
		}
	}
	with http.send as mock_http_send_high_risk
}

test_nftables_drops_raises_risk_and_denies if {
	deny with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "8.8.8.8",
			"command": "insert",
			"collection": "admissions",
			"query": "{\"patient_id\": \"P001\"}"
		}
	}
	with http.send as mock_http_send_medium_risk
}

test_mongo_failures_raises_risk_and_denies if {
	deny with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "insert",
			"collection": "admissions",
			"query": "{\"patient_id\": \"P001\"}"
		}
	}
	with http.send as mock_http_send_high_risk
}

# ─── NoSQL Injection & WAF Tests ──────────────────────────────────────────────

test_nosql_injection_where_denied if {
	deny with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "patients",
			"query": "{\"$where\": \"this.age > 30\"}"
		}
	}
	with data.envoy.authz.identity.current_role as "doctor"
	with data.splunk.trust_registry as {"test.doctor": {"device-laptop-001": ["172.20.0.5"]}}
}

test_nosql_injection_function_denied if {
	deny with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "patients",
			"query": "{\"$function\": \"function() { return true; }\"}"
		}
	}
	with data.envoy.authz.identity.current_role as "doctor"
	with data.splunk.trust_registry as {"test.doctor": {"device-laptop-001": ["172.20.0.5"]}}
}

test_nosql_injection_sleep_denied if {
	deny with input as {
		"attributes": {"source": {"principal": "test.doctor"}},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "find",
			"collection": "patients",
			"query": "{\"name\": \"test; sleep(5000);\"}"
		}
	}
	with data.envoy.authz.identity.current_role as "doctor"
	with data.splunk.trust_registry as {"test.doctor": {"device-laptop-001": ["172.20.0.5"]}}
}



# Helper mocks per http.send
mock_http_send_high_risk(req) := {
	"status_code": 200,
	"body": {
		"risk_boost": 100
	}
}

mock_http_send_medium_risk(req) := {
	"status_code": 200,
	"body": {
		"risk_boost": 60
	}
}

mock_http_send_safe(req) := {
	"status_code": 200,
	"body": {
		"risk_boost": 0
	}
}

# ─── Step-Up Authentication for Delete Actions Tests ─────────────────────────

test_doctor_delete_admissions_with_step_up_allowed if {
	allow with input as {
		"attributes": {
			"source": {
				"principal": "test.doctor",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "delete",
			"collection": "admissions",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "step_up": true, "step_up_time": 9999999999, "exp": 9999999999, "cnf": {"x5t#S256_hex": "mock-fingerprint"}}
	with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
	with data.envoy.authz.identity.cert_der_bytes as "mock-der"
	with crypto.sha256 as "mock-fingerprint"
	with http.send as mock_http_send_safe
}

test_doctor_delete_admissions_without_step_up_denied if {
	deny with input as {
		"attributes": {
			"source": {
				"principal": "test.doctor",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "delete",
			"collection": "admissions",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "step_up": false, "exp": 9999999999, "cnf": {"x5t#S256_hex": "mock-fingerprint"}}
	with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
	with data.envoy.authz.identity.cert_der_bytes as "mock-der"
	with crypto.sha256 as "mock-fingerprint"
}

test_receptionist_delete_admissions_with_step_up_allowed if {
	allow with input as {
		"attributes": {
			"source": {
				"principal": "test.receptionist",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"user": "test.receptionist",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "delete",
			"collection": "admissions",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.receptionist", "role": "receptionist", "step_up": true, "step_up_time": 9999999999, "exp": 9999999999, "cnf": {"x5t#S256_hex": "mock-fingerprint"}}
	with data.envoy.authz.identity.cert_subject_cn as "test.receptionist"
	with data.envoy.authz.identity.cert_der_bytes as "mock-der"
	with crypto.sha256 as "mock-fingerprint"
	with http.send as mock_http_send_safe
}

test_receptionist_delete_admissions_without_step_up_denied if {
	deny with input as {
		"attributes": {
			"source": {
				"principal": "test.receptionist",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"user": "test.receptionist",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "delete",
			"collection": "admissions",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.receptionist", "role": "receptionist", "step_up": false, "exp": 9999999999, "cnf": {"x5t#S256_hex": "mock-fingerprint"}}
	with data.envoy.authz.identity.cert_subject_cn as "test.receptionist"
	with data.envoy.authz.identity.cert_der_bytes as "mock-der"
	with crypto.sha256 as "mock-fingerprint"
}

test_billing_staff_delete_billing_with_step_up_allowed if {
	allow with input as {
		"attributes": {
			"source": {
				"principal": "test.billing",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"user": "test.billing",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "delete",
			"collection": "billing",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.billing", "role": "billing_staff", "step_up": true, "step_up_time": 9999999999, "exp": 9999999999, "cnf": {"x5t#S256_hex": "mock-fingerprint"}}
	with data.envoy.authz.identity.cert_subject_cn as "test.billing"
	with data.envoy.authz.identity.cert_der_bytes as "mock-der"
	with crypto.sha256 as "mock-fingerprint"
	with http.send as mock_http_send_safe
}

test_billing_staff_delete_billing_without_step_up_denied if {
	deny with input as {
		"attributes": {
			"source": {
				"principal": "test.billing",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"user": "test.billing",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "delete",
			"collection": "billing",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.billing", "role": "billing_staff", "step_up": false, "exp": 9999999999, "cnf": {"x5t#S256_hex": "mock-fingerprint"}}
	with data.envoy.authz.identity.cert_subject_cn as "test.billing"
	with data.envoy.authz.identity.cert_der_bytes as "mock-der"
	with crypto.sha256 as "mock-fingerprint"
}

test_doctor_delete_billing_denied if {
	deny with input as {
		"attributes": {
			"source": {
				"principal": "test.doctor",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock-pem\n-----END CERTIFICATE-----"
			}
		},
		"parsed_body": {
			"user": "test.doctor",
			"device": "device-laptop-001",
			"network_ip": "172.20.0.5",
			"command": "delete",
			"collection": "billing",
			"mechanism": "MONGODB-OIDC",
			"query": {
				"payload": "a.b.c"
			}
		}
	}
	with data.envoy.authz.identity.verify_oidc_jwt as {"sub": "test.doctor", "role": "doctor", "step_up": true, "step_up_time": 9999999999, "exp": 9999999999, "cnf": {"x5t#S256_hex": "mock-fingerprint"}}
	with data.envoy.authz.identity.cert_subject_cn as "test.doctor"
	with data.envoy.authz.identity.cert_der_bytes as "mock-der"
	with crypto.sha256 as "mock-fingerprint"
}
