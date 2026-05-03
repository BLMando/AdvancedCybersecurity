#!/usr/bin/env python3
"""End-to-end test of the CSR-based enrollment flow.

Tests:
1. Client generates CSR with hardware identifiers
2. Client sends CSR to PKI server
3. Server signs CSR and returns certificate
4. Verify certificate contains correct extensions and SAN
"""

import json
import sys
import tempfile
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from identity_pki.pki import PKIService


def generate_csr(cn: str) -> tuple[str, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    return csr_pem.decode("utf-8"), key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def test_csr_enrollment():
    """Test CSR-based enrollment workflow."""
    print("\n" + "=" * 70)
    print("TESTING CSR-BASED ENROLLMENT WORKFLOW")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        pki_data_dir = tmpdir / "pki_data"
        client_dir = tmpdir / "client_certs"
        pki_data_dir.mkdir()
        client_dir.mkdir()

        # Initialize PKI Service
        print("\n[1] Initializing PKI Service...")
        service = PKIService(data_dir=pki_data_dir)
        print(f"    CA CN: {service.ca_common_name}")
        print(f"    CA created: {service._ca_record.created}")

        # Step 1: Client generates CSR
        print("\n[2] Client generates CSR locally...")
        csr_pem, private_key_pem = generate_csr("dr_mario_rossi")
        key_path = client_dir / "dr_mario_rossi.key"
        key_path.write_bytes(private_key_pem)
        print(f"    ✓ Private key: {key_path}")
        print("    ✓ CSR generated")

        # Step 2: Server signs CSR
        print("\n[3] Server signs CSR...")
        bundle = service.sign_csr(
            csr_pem=csr_pem,
            user="dr_mario_rossi",
            role="doctor",
            department="Cardiologia",
            hardware_mac="00:1A:2B:3C:4D:5E",
            hardware_cpu="Intel(R) Core(TM) i7-10700K",
        )
        print(f"    ✓ Certificate signed: {bundle.paths.certificate}")
        print(f"    ✓ Serial: {bundle.serial_number}")
        print(f"    ✓ Expires: {bundle.expires_at}")

        # Step 3: Verify certificate
        print("\n[4] Verifying certificate...")
        cert_pem = bundle.paths.certificate.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)

        # Check subject
        print(f"    Subject: {cert.subject.rfc4514_string()}")
        assert "dr_mario_rossi" in cert.subject.rfc4514_string().lower()

        # Check SAN
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns = [v.value for v in san_ext.value if isinstance(v, x509.DNSName)]
        print(f"    SAN DNS entries: {san_dns}")
        assert any("MAC-" in s for s in san_dns), "Missing MAC in SAN"
        assert any("CPU-" in s for s in san_dns), "Missing CPU in SAN"

        # Check Extensions
        print(f"    Extensions:")
        for ext in cert.extensions:
            print(f"      - {ext.oid._name if hasattr(ext.oid, '_name') else ext.oid}: critical={ext.critical}")

        # Check EKU
        eku_ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        print(f"    Extended Key Usage: {eku_ext.value}")
        assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku_ext.value

        # Step 4: Verify metadata
        print("\n[5] Verifying metadata...")
        metadata = json.loads(bundle.paths.metadata.read_text())
        print(f"    User: {metadata['user']}")
        print(f"    Role: {metadata['role']}")
        print(f"    Department: {metadata['department']}")
        print(f"    Hardware MAC: {metadata['hardware']['mac']}")
        print(f"    Hardware CPU: {metadata['hardware']['cpu']}")
        print(f"    Enrollment method: {metadata.get('enrollment_method', 'unknown')}")
        assert metadata['enrollment_method'] == 'csr', "Expected CSR enrollment"

        # Step 5: Test uniqueness check
        print("\n[6] Testing CN uniqueness enforcement...")
        try:
            service.sign_csr(csr_pem=csr_pem, user="dr_mario_rossi", role="doctor")
            print("    ✗ ERROR: Should have rejected duplicate CN!")
            return False
        except ValueError as e:
            if "already exists" in str(e):
                print(f"    ✓ Correctly rejected duplicate: {str(e)[:60]}...")
            else:
                raise

        print("\n" + "=" * 70)
        print("ALL TESTS PASSED ✓")
        print("=" * 70)
        return True


if __name__ == "__main__":
    success = test_csr_enrollment()
    sys.exit(0 if success else 1)
