import base64
import json
import logging
import os

from .pki import PKIService

# Simulated Active Directory / HR database for ZTA Identity Verification
AD_USERS = {
    "zta.healthcare+admin@outlook.com": {
        "cn": "test.admin",
        "role": "admin",
        "department": "IT",
        "password": "password123",
    },
    "zta.healthcare+doctor@outlook.com": {
        "cn": "test.doctor",
        "role": "doctor",
        "department": "Cardiology",
        "password": "password123",
    },
    "zta.healthcare+auditor@outlook.com": {
        "cn": "test.auditor",
        "role": "auditor",
        "department": "Audit",
        "password": "password123",
    },
    "zta.healthcare+receptionist@outlook.com": {
        "cn": "test.receptionist",
        "role": "receptionist",
        "department": "Reception",
        "password": "password123",
    },
    "zta.healthcare+billing@outlook.com": {
        "cn": "test.billing",
        "role": "billing_staff",
        "department": "Billing",
        "password": "password123",
    },
}

PENDING_OTPS = {} 
ENROLLMENT_SESSIONS = {}
PRIMARY_SESSIONS = {}


def get_rls_view_name(role: str, collection_name: str) -> str:
    """Map a raw collection name to the corresponding RLS view for the role."""
    if role == "admin":
        return collection_name

    rls_views = {
        "doctor": {
            "patients": "v_patients_doctor",
            "providers": "v_providers_all",
            "admissions": "v_admissions_doctor",
            "clinical_records": "v_clinical_doctor",
        },
        "billing_staff": {
            "patients": "v_patients_billing",
            "providers": "v_providers_all",
            "admissions": "v_admissions_billing",
            "billing": "v_billing_staff",
        },
        "auditor": {
            "patients": "v_patients_doctor",
            "providers": "v_providers_all",
            "admissions": "v_admissions_auditor",
            "clinical_records": "v_clinical_auditor",
            "billing": "v_billing_auditor",
        },
        "receptionist": {
            "patients": "v_patients_reception",
            "providers": "v_providers_all",
            "admissions": "v_admissions_reception",
        },
    }
    return rls_views.get(role, {}).get(collection_name, collection_name)


def extract_role_from_jwt(jwt_token: str | None, logger: logging.Logger) -> str:
    """Parse JWT claims to extract the user's role."""
    if not jwt_token:
        return "unknown"
    try:
        parts = jwt_token.split(".")
        if len(parts) == 3:
            payload_b64 = parts[1]
            payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
            payload_data = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
            claims = json.loads(payload_data)
            role = claims.get("role", "unknown")
            if isinstance(role, list):
                role = role[0] if role else "unknown"
            return str(role)
    except Exception as ex:
        logger.warning(f"Failed to decode JWT claims: {ex}")
    return "unknown"


def resolve_user_metadata(
    service: PKIService, user_cn: str, cert_path: str, jwt_token: str | None, logger: logging.Logger
) -> tuple[str, bool, str]:
    """Resolve the user's role, hardware mode, and device details from metadata and JWT."""
    role = extract_role_from_jwt(jwt_token, logger)
    hardware_mode = False
    device_info = "no-tpm"

    metadata_path = os.path.join(service.cert_dir, f"issued/{user_cn}/metadata.json")
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path) as f:
                meta = json.load(f)
                if role == "unknown":
                    role = str(meta.get("role", "unknown"))
                enroll_method = meta.get("enrollment_method", "manual")
                hardware_mode = enroll_method in ("random", "tpm", "hardware_proof")
                if hardware_mode:
                    hw = meta.get("hardware", {})
                    cpu = hw.get("cpu", "CPU-UNKNOWN")
                    mac = hw.get("mac", "MAC-UNKNOWN")
                    device_info = f"Hardware-Bound (CPU: {cpu}, MAC: {mac})"
        except Exception:
            pass

    if role == "unknown":
        try:
            from cryptography import x509

            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
                titles = cert.subject.get_attributes_for_oid(x509.NameOID.TITLE)
                if titles:
                    val = titles[0].value
                    role = val.decode("utf-8") if isinstance(val, bytes) else str(val)
        except Exception:
            pass

    return role, hardware_mode, device_info
