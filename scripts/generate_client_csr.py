#!/usr/bin/env python3
"""Generate a Certificate Signing Request (CSR) for device enrollment.

This script should run ON THE CLIENT DEVICE (the doctor's machine/laptop).
It generates a local keypair and creates a CSR that gets sent to the PKI server.
The private key NEVER leaves the device.

Usage:
  python3 generate_client_csr.py \
    --cn "paolo" \
    --department "Cardiologia" \
    --mac "00:1A:2B:3C:4D:5E" \
    --cpu "Intel(R) Core(TM) i7-10700K" \
    --output-dir ./certs

This creates:
  - client_key.pem (KEEP SECURE! Never share)
  - client_csr.pem (send to PKI server via /api/csr)
"""

import argparse
import json
import platform
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _format_mac(raw_value: int) -> str:
    """Format MAC address."""
    return ":".join(
        "{:02X}".format((raw_value >> shift) & 0xFF)
        for shift in range(40, -1, -8)
    )


def generate_client_csr(
    cn: str,
    organization: str = "Ospedale-San-Raffaele",
    department: str = "Cardiologia",
    country: str = "IT",
    mac: str = None,
    cpu: str = None,
    output_dir: Path = None,
) -> dict:
    """Generate a CSR on the client device (locally generated keys).
    
    Args:
        cn: Common Name (username/device identifier)
        organization: Organization name
        department: Department/OU
        country: Country code
        mac: MAC address (auto-detected if None)
        cpu: CPU identifier (auto-detected if None)
        output_dir: Directory to save key and CSR (default: current dir)
    
    Returns:
        dict with paths and metadata
    """
    output_dir = Path(output_dir or ".")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Auto-detect hardware if not provided
    if not mac:
        mac = _format_mac(uuid.getnode())
    if not cpu:
        cpu = (
            platform.processor()
            or platform.uname().processor
            or platform.machine()
            or "Generic-CPU"
        )

    # Generate local keypair
    print(f"[*] Generating RSA keypair (2048 bits) on {cn}...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Create subject DN
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, department),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )

    # Create SAN extension with hardware identifiers
    san_list = [
        x509.DNSName(f"{cn.lower().replace(' ', '-')}.internal"),
        x509.DNSName(f"MAC-{mac}"),
        x509.DNSName(f"CPU-{cpu}"),
    ]

    # Build CSR
    print("[*] Building CSR with device identifiers...")
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Save private key locally
    key_path = output_dir / f"{cn}_key.pem"
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(key_pem)
    key_path.chmod(0o600)
    print(f"[✓] Private key saved: {key_path}")

    # Save CSR
    csr_path = output_dir / f"{cn}_csr.pem"
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    csr_path.write_bytes(csr_pem)
    print(f"[✓] CSR saved: {csr_path}")

    # Create metadata
    metadata = {
        "cn": cn,
        "organization": organization,
        "department": department,
        "country": country,
        "hardware": {
            "mac": mac,
            "cpu": cpu,
        },
        "created_at": str(__import__("datetime").datetime.now().isoformat()),
        "files": {
            "private_key": str(key_path),
            "csr": str(csr_path),
        },
    }
    metadata_path = output_dir / f"{cn}_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2))
    print(f"[✓] Metadata saved: {metadata_path}")

    return {
        "private_key": key_path,
        "csr": csr_path,
        "metadata": metadata_path,
        "csr_pem": csr_pem.decode("utf-8"),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate client CSR for PKI enrollment"
    )
    parser.add_argument("--cn", required=True, help="Common Name (username)")
    parser.add_argument("--department", default="Cardiologia", help="Department/OU")
    parser.add_argument("--organization", default="Ospedale-San-Raffaele", help="Organization")
    parser.add_argument("--mac", help="MAC address (auto-detect if omitted)")
    parser.add_argument("--cpu", help="CPU identifier (auto-detect if omitted)")
    parser.add_argument("--output-dir", "-o", help="Output directory (default: current dir)")

    args = parser.parse_args()

    result = generate_client_csr(
        cn=args.cn,
        organization=args.organization,
        department=args.department,
        mac=args.mac,
        cpu=args.cpu,
        output_dir=args.output_dir,
    )

    print("\n" + "=" * 70)
    print("CSR GENERATION COMPLETE")
    print("=" * 70)
    print(f"Private Key (KEEP SECURE!): {result['private_key']}")
    print(f"CSR (send to server):       {result['csr']}")
    print(f"Metadata:                   {result['metadata']}")
    print("\nNext step: Send the CSR to the PKI server:")
    print('  curl -X POST http://pki-server:8080/api/csr \\')
    print('    -H "Content-Type: application/json" \\')
    print('    -d "{')
    print('      \\"csr\\": \\"' + result['csr_pem'][:50].replace('\n', '\\n') + '...\\",')
    print('      \\"user\\": \\"' + args.cn + '\\",')
    print('      \\"role\\": \\"doctor\\",')
    print('      \\"department\\": \\"' + args.department + '\\"')
    print('    }"')
    print("=" * 70)
