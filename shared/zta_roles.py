# ZTA Roles - Single Source of Truth

ZTA_ROLES = {
    "doctor": {
        "display_name": "Medico",
        "mongo_role": "zta_doctor",
        "default_department": "Cardiologia",
        "allowed_collections": ["patients", "providers", "admissions", "clinical_records"],
        "description": "Accesso a dati clinici e cartelle pazienti",
    },
    "billing_staff": {
        "display_name": "Personale Amministrativo",
        "mongo_role": "zta_billing",
        "default_department": "Amministrazione",
        "allowed_collections": ["patients", "providers", "admissions", "billing"],
        "description": "Accesso ai dati di fatturazione",
    },
    "auditor": {
        "display_name": "Revisore",
        "mongo_role": "zta_auditor",
        "default_department": "Compliance",
        "allowed_collections": ["patients", "providers", "admissions", "clinical_records", "billing"],
        "description": "Accesso in sola lettura a tutto, con dati mascherati",
    },
    "receptionist": {
        "display_name": "Receptionist",
        "mongo_role": "zta_receptionist",
        "default_department": "Accettazione",
        "allowed_collections": ["patients", "admissions", "providers"],
        "description": "Accesso all'agenda e ai pazienti, no dati clinici",
    },
    "admin": {
        "display_name": "Amministratore di Sistema",
        "mongo_role": "zta_admin",
        "default_department": "IT",
        "allowed_collections": ["*"],
        "description": "Accesso completo — solo per personale IT autorizzato",
    },
}

VALID_ROLE_NAMES = list(ZTA_ROLES.keys())
