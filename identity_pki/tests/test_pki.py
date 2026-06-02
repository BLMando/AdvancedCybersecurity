import json
import tempfile
import unittest
from pathlib import Path

from cryptography import x509

from identity_pki.app import create_app
from identity_pki.pki import PKIService


class PKIServiceTests(unittest.TestCase):
    def test_ca_is_persistent(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            service_a = PKIService(data_dir=Path(temp_dir))
            first_fingerprint = service_a.ca_summary()["fingerprint_sha256"]

            service_b = PKIService(data_dir=Path(temp_dir))
            second_fingerprint = service_b.ca_summary()["fingerprint_sha256"]

            self.assertEqual(first_fingerprint, second_fingerprint)
            self.assertTrue(service_b.ca_key_path.exists())
            self.assertTrue(service_b.ca_cert_path.exists())

    def test_certificate_contains_hardware_san(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            service = PKIService(data_dir=Path(temp_dir))
            bundle = service.issue_certificate(
                user="mario.rossi",
                role="doctor",
                department="Cardiologia",
                hardware_mode="manual",
                mac="AA:BB:CC:DD:EE:FF",
                cpu="CPU-TEST-1234",
            )

            cert = x509.load_pem_x509_certificate(bundle.paths.certificate.read_bytes())
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            values = san.value.get_values_for_type(x509.DNSName)

            self.assertIn("MAC-AA:BB:CC:DD:EE:FF", values)
            self.assertIn("CPU-CPU-TEST-1234", values)
            self.assertIn("mario.rossi.internal", values)

    def test_api_returns_certificate_payload(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app = create_app(data_dir=Path(temp_dir))
            app.config["TESTING"] = True

            with app.test_client() as client:
                response = client.post(
                    "/api/certificates",
                    json={
                        "user": "anna.verdi",
                        "role": "billing_staff",
                        "department": "Amministrazione",
                        "hardware_mode": "random",
                    },
                )

                self.assertEqual(response.status_code, 200)
                payload = json.loads(response.data.decode("utf-8"))
                self.assertEqual(payload["status"], "created")
                self.assertEqual(payload["certificate"]["user"], "anna.verdi")

    def test_oidc_endpoints(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app = create_app(data_dir=Path(temp_dir))
            app.config["TESTING"] = True
            
            with app.test_client() as client:
                # 1. Test JWKS
                jwks_resp = client.get("/.well-known/jwks.json")
                self.assertEqual(jwks_resp.status_code, 200)
                jwks = json.loads(jwks_resp.data.decode("utf-8"))
                self.assertIn("keys", jwks)
                self.assertEqual(len(jwks["keys"]), 1)
                self.assertEqual(jwks["keys"][0]["alg"], "RS256")
                
                # 2. Test Token Issuance
                chal_resp = client.get("/api/challenge")
                self.assertEqual(chal_resp.status_code, 200)
                chal_data = json.loads(chal_resp.data.decode("utf-8"))
                challenge_id = chal_data["challenge_id"]
                
                # Register a software cert for 'paolo.roselli'
                reg_resp = client.post(
                    "/api/certificates",
                    json={
                        "user": "paolo.roselli",
                        "role": "doctor",
                        "department": "Cardiologia",
                        "hardware_mode": "random",
                    },
                )
                self.assertEqual(reg_resp.status_code, 200)
                
                # Mock signature verification
                from unittest.mock import patch
                with patch('identity_pki.pki.PKIService.verify_proof') as mock_verify:
                    mock_verify.return_value = {
                        "user": "paolo.roselli",
                        "role": "doctor",
                        "department": "Cardiologia"
                    }
                    
                    token_resp = client.post(
                        "/api/oidc/token",
                        json={
                            "challenge_id": challenge_id,
                            "signature": "mock_sig",
                            "public_key_pem": "mock_pub",
                            "proof_string": "mock_proof"
                        }
                    )
                    self.assertEqual(token_resp.status_code, 200)
                    token_data = json.loads(token_resp.data.decode("utf-8"))
                    self.assertIn("access_token", token_data)
                    self.assertEqual(token_data["token_type"], "Bearer")

    def test_api_query_oidc_pymongo_standard(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app = create_app(data_dir=Path(temp_dir))
            app.config["TESTING"] = True
            
            with app.test_client() as client:
                client.post(
                    "/api/certificates",
                    json={
                        "user": "paolo.roselli",
                        "role": "doctor",
                        "department": "Cardiologia",
                        "hardware_mode": "random",
                    },
                )
                
                from unittest.mock import patch, MagicMock
                mock_client_instance = MagicMock()
                mock_client_instance.__getitem__.return_value.__getitem__.return_value.find.return_value.limit.return_value = []
                
                with patch('identity_pki.app.MongoClient', return_value=mock_client_instance) as mock_mongo_client:
                    jwt_token = "hdr.eyJ1c2VyIjoicGFvbG8ucm9zZWxsaSIsInJvbGUiOiJkb2N0b3IifQ.sig"
                    query_resp = client.post(
                        "/api/query",
                        json={
                            "user": "paolo.roselli",
                            "collection": "patients",
                            "filter": "{}",
                            "jwt_token": jwt_token
                        }
                    )
                    self.assertEqual(query_resp.status_code, 200)
                    
                    mock_mongo_client.assert_called_once()
                    _, kwargs = mock_mongo_client.call_args
                    self.assertIn("authMechanismProperties", kwargs)
                    callback = kwargs["authMechanismProperties"]["OIDC_CALLBACK"]
                    self.assertIsNotNone(callback)
                    
                    from pymongo.auth_oidc import OIDCCallbackResult
                    res = callback.fetch(None)
                    self.assertIsInstance(res, OIDCCallbackResult)
                    self.assertEqual(res.access_token, jwt_token)

    def test_invalid_cn_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            service = PKIService(data_dir=Path(temp_dir))
            with self.assertRaises(ValueError):
                service.issue_certificate(user="../evil")


if __name__ == "__main__":
    unittest.main()
