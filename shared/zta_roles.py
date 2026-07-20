# ZTA Roles - Single Source of Truth

ZTA_ROLES = {
    "doctor": {
        "display_name": "Doctor",
        "mongo_role": "zta_doctor",
        "default_department": "Cardiology",
        "allowed_collections": ["patients", "providers", "admissions", "clinical_records"],
        "description": "Access to clinical data and patient records",
    },
    "billing_staff": {
        "display_name": "Billing Staff",
        "mongo_role": "zta_billing",
        "default_department": "Billing",
        "allowed_collections": ["patients", "providers", "admissions", "billing"],
        "description": "Access to billing data",
    },
    "auditor": {
        "display_name": "Auditor",
        "mongo_role": "zta_auditor",
        "default_department": "Audit",
        "allowed_collections": ["patients", "providers", "admissions", "clinical_records", "billing"],
        "description": "Read-only access to everything, with masked data",
    },
    "receptionist": {
        "display_name": "Receptionist",
        "mongo_role": "zta_receptionist",
        "default_department": "Reception",
        "allowed_collections": ["patients", "admissions", "providers"],
        "description": "Access to schedule and patients, no clinical data",
    },
    "admin": {
        "display_name": "System Administrator",
        "mongo_role": "zta_admin",
        "default_department": "IT",
        "allowed_collections": ["*"],
        "description": "Full access - only for authorized IT personnel",
    },
}

VALID_ROLE_NAMES = list(ZTA_ROLES.keys())
