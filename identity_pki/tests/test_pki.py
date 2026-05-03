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
                        "role": "billing",
                        "department": "Amministrazione",
                        "hardware_mode": "random",
                    },
                )

                self.assertEqual(response.status_code, 200)
                payload = json.loads(response.data.decode("utf-8"))
                self.assertEqual(payload["status"], "created")
                self.assertEqual(payload["certificate"]["user"], "anna.verdi")

    def test_invalid_cn_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            service = PKIService(data_dir=Path(temp_dir))
            with self.assertRaises(ValueError):
                service.issue_certificate(user="../evil")


if __name__ == "__main__":
    unittest.main()
