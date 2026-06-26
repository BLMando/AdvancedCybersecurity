import os
import json
import base64
import logging
from typing import Optional, Any
from datetime import datetime, timezone
from .pki import PKIService

# Simulated Active Directory / HR database for ZTA Identity Verification
AD_USERS = {
    "test.doctor@ospedale.it": {
        "cn": "test.doctor",
        "role": "doctor",
        "department": "Cardiologia",
        "password": "password123"
    },
    "test.auditor@ospedale.it": {
        "cn": "test.auditor",
        "role": "auditor",
        "department": "Audit",
        "password": "password123"
    },
    "test.receptionist@ospedale.it": {
        "cn": "test.receptionist",
        "role": "receptionist",
        "department": "Accettazione",
        "password": "password123"
    },
     "test.billing@ospedale.it": {
        "cn": "test.billing",
        "role": "billing_staff",
        "department": "Cardiologia",
        "password": "password123"
    }
}

PENDING_OTPS = {}          # email -> {"otp": "123456", "expires_at": datetime, "user_info": dict}
ENROLLMENT_SESSIONS = {}   # token -> {"cn": cn, "role": role, "department": department, "expires_at": datetime}
PRIMARY_SESSIONS = {}      # cn -> {"login_time": datetime, "last_mfa_time": datetime}

def check_action_permissions(role: str, collection_name: str, mongo_action: str) -> bool:
    """Check if the role is allowed to perform the given action on the collection."""
    if role == "admin":
        return True
        
    action_permission_map = {
        "doctor": {
            "patients": {"find"},
            "providers": {"find"},
            "admissions": {"find", "insert", "update", "delete"},
            "clinical_records": {"find", "insert", "update", "delete"},
            "billing": set()
        },
        "billing_staff": {
            "patients": {"find"},
            "providers": {"find"},
            "admissions": {"find"},
            "clinical_records": set(),
            "billing": {"find", "insert", "update", "delete"}
        },
        "auditor": {
            "patients": {"find"},
            "providers": {"find"},
            "admissions": {"find"},
            "clinical_records": {"find"},
            "billing": {"find"}
        },
        "receptionist": {
            "patients": {"find", "insert", "update"},
            "providers": {"find"},
            "admissions": {"find", "insert", "update", "delete"},
            "clinical_records": set(),
            "billing": set()
        }
    }
    
    role_allowed_actions = action_permission_map.get(role, {}).get(collection_name, set())
    return mongo_action in role_allowed_actions


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
        }
    }
    return rls_views.get(role, {}).get(collection_name, collection_name)


def extract_role_from_jwt(jwt_token: Optional[str], logger: logging.Logger) -> str:
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


def resolve_user_metadata(service: PKIService, user_cn: str, cert_path: str, jwt_token: Optional[str], logger: logging.Logger) -> tuple[str, bool]:
    """Resolve the user's role and hardware mode from metadata and JWT."""
    role = extract_role_from_jwt(jwt_token, logger)
    hardware_mode = False

    metadata_path = os.path.join(service.cert_dir, f"issued/{user_cn}/metadata.json")
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path) as f:
                meta = json.load(f)
                if role == "unknown":
                    role = str(meta.get("role", "unknown"))
                hardware_mode = meta.get("enrollment_method", "manual") in ("random", "tpm")
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

    return role, hardware_mode
