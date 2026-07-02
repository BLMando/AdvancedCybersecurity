import json
import tempfile
import unittest
from datetime import UTC
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
                from datetime import datetime
                from unittest.mock import patch

                from identity_pki.app import PRIMARY_SESSIONS

                PRIMARY_SESSIONS["paolo.roselli"] = {
                    "login_time": datetime.now(UTC),
                    "last_mfa_time": datetime.now(UTC),
                }
                with patch("identity_pki.pki.PKIService.verify_proof") as mock_verify:
                    mock_verify.return_value = {"user": "paolo.roselli", "role": "doctor", "department": "Cardiologia"}

                    token_resp = client.post(
                        "/api/oidc/token",
                        json={
                            "challenge_id": challenge_id,
                            "signature": "mock_sig",
                            "public_key_pem": "mock_pub",
                            "proof_string": "mock_proof",
                        },
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

                from unittest.mock import MagicMock, patch

                with patch("requests.post") as mock_post, patch("urllib.request.urlopen") as mock_url_open:
                    mock_response = MagicMock()
                    mock_response.status_code = 200
                    mock_response.json.return_value = {
                        "status": "success",
                        "count": 0,
                        "results": [],
                        "message": "Success",
                    }
                    mock_post.return_value = mock_response

                    mock_url_response = MagicMock()
                    mock_url_response.read.return_value = b'{"result": false}'
                    mock_url_open.return_value.__enter__.return_value = mock_url_response

                    jwt_token = "hdr.eyJ1c2VyIjoicGFvbG8ucm9zZWxsaSIsInJvbGUiOiJkb2N0b3IifQ.sig"
                    query_resp = client.post(
                        "/api/query",
                        json={
                            "user": "paolo.roselli",
                            "collection": "patients",
                            "filter": "{}",
                            "jwt_token": jwt_token,
                        },
                    )
                    self.assertEqual(query_resp.status_code, 200)

                    mock_post.assert_called_once()
                    args, kwargs = mock_post.call_args
                    self.assertEqual(args[0], "https://envoy:10000/query")
                    self.assertIn("data", kwargs)

                    # Verify StaticTokenCallback behavior directly
                    from pymongo.auth_oidc import OIDCCallback, OIDCCallbackResult

                    class StaticTokenCallback(OIDCCallback):
                        def __init__(self, token):
                            self.token = token

                        def fetch(self, context):
                            return OIDCCallbackResult(access_token=self.token)

                    callback = StaticTokenCallback(jwt_token)
                    res = callback.fetch(None)
                    self.assertIsInstance(res, OIDCCallbackResult)
                    self.assertEqual(res.access_token, jwt_token)

    def test_csr_enrollment_with_proof_string_and_is_hw(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app = create_app(data_dir=Path(temp_dir))
            app.config["TESTING"] = True

            with app.test_client() as client:
                from datetime import datetime, timedelta

                from identity_pki.app import ENROLLMENT_SESSIONS

                session_token = "mock_session_token"
                ENROLLMENT_SESSIONS[session_token] = {
                    "cn": "paolo.roselli",
                    "role": "doctor",
                    "department": "Cardiologia",
                    "expires_at": datetime.now(UTC) + timedelta(minutes=10),
                }
                # Mock service verify_proof and issue_hardware_bound_certificate
                from unittest.mock import patch

                with (
                    patch("identity_pki.pki.PKIService.verify_proof") as mock_verify,
                    patch("identity_pki.pki.PKIService.issue_hardware_bound_certificate") as mock_issue,
                ):
                    mock_verify.return_value = {"user": "paolo.roselli", "role": "doctor", "department": "Cardiologia"}
                    mock_issue.return_value = "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----"

                    # We pass raw binary-like signature in signature (attestation_sig_b64)
                    # which cannot be decoded to UTF-8
                    response = client.post(
                        "/api/csr",
                        json={
                            "user": "paolo.roselli",
                            "role": "doctor",
                            "department": "Cardiologia",
                            "challenge_id": "mock_chal",
                            "proof_string": "ZTA-CERT-BINDING|CN=paolo.roselli|TIME=2026-06-04T16:29:00Z",
                            "attestation_sig_b64": "AP8B+QD4AP0B",  # Binary signature representation (fails to decode to UTF-8)
                            "is_hardware_csr": True,
                            "public_key_pem": "mock_pub",
                            "enrollment_session_token": session_token,
                        },
                    )

                    self.assertEqual(response.status_code, 200)
                    payload = json.loads(response.data.decode("utf-8"))
                    self.assertEqual(payload["status"], "signed")
                    self.assertEqual(
                        payload["certificate_pem"], "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----"
                    )

    def test_invalid_cn_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            service = PKIService(data_dir=Path(temp_dir))
            with self.assertRaises(ValueError):
                service.issue_certificate(user="../evil")


if __name__ == "__main__":
    unittest.main()
