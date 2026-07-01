import argparse
import os
import sys
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import OperationFailure

try:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from shared.zta_roles import ZTA_ROLES
except ImportError:
    ZTA_ROLES = {}

MONGO_USER = os.getenv("MONGO_ROOT_USERNAME", "zta_user")
MONGO_PASS = os.getenv("MONGO_ROOT_PASSWORD", "zta_password")
MONGO_DB = os.getenv("MONGO_DATABASE", "zta_db")
MONGO_URI = f"mongodb://{MONGO_USER}:{MONGO_PASS}@localhost:27017/{MONGO_DB}?authSource=admin"

# CLI args  
parser = argparse.ArgumentParser(description="Init ZTA Healthcare DB")
parser.add_argument("--uri", default=MONGO_URI, help="MongoDB connection URI")
args = parser.parse_args()

# Connect
CA_PATH = "/etc/certs/ca/ca.crt"
CLIENT_PEM_PATH = "/etc/certs/server/mongo.pem" # server cert & key

client = MongoClient(
    args.uri,
    tls=True,
    tlsCertificateKeyFile=CLIENT_PEM_PATH,
    tlsCAFile=CA_PATH,
    tlsAllowInvalidCertificates=True
)
db = client[MONGO_DB]

print("\n *** ZTA Healthcare DB — initialising *** ")


# Helper
def safe_drop(name: str) -> None:
    try:
        db[name].drop()
    except OperationFailure:
        pass

for col in ["patients", "admissions", "clinical_records", "billing", "providers"]:
    safe_drop(col)


# 1. PATIENTS
db.create_collection(
    "patients",
    validator={
        "$jsonSchema": {
            "bsonType": "object",
            "title": "Patient document",
            "required": ["_id", "full_name", "age", "gender", "blood_type", "created_at"],
            "additionalProperties": False,
            "properties": {
                "_id":        {"bsonType": "string", "description": "UUID v4 — primary key"},
                "full_name":  {"bsonType": "string", "minLength": 2, "maxLength": 120},
                "age":        {"bsonType": "int",    "minimum": 0, "maximum": 130},
                "gender":     {"enum": ["Male", "Female", "Other"]},
                "blood_type": {"enum": ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]},
                "created_at": {"bsonType": "date"},
                "updated_at": {"bsonType": "date"},
            },
        }
    },
    validationLevel="strict",
    validationAction="error",
)
db.patients.create_index([("full_name", ASCENDING)])
db.patients.create_index([("age", ASCENDING)])
print("Collection: patients")


# 2. PROVIDERS — Doctors & Hospitals (INTERNAL)
db.create_collection(
    "providers",
    validator={
        "$jsonSchema": {
            "bsonType": "object",
            "title": "Provider document",
            "required": ["_id", "type", "name"],
            "additionalProperties": False,
            "properties": {
                "_id":      {"bsonType": "string"},
                "type":     {"enum": ["doctor", "hospital"]},
                "name":     {"bsonType": "string", "minLength": 2, "maxLength": 200},
                "metadata": {"bsonType": "object"},
            },
        }
    },
    validationLevel="strict",
    validationAction="error",
)
db.providers.create_index([("type", ASCENDING), ("name", ASCENDING)])
print("Collection: providers")


# 3. ADMISSIONS
db.create_collection(
    "admissions",
    validator={
        "$jsonSchema": {
            "bsonType": "object",
            "title": "Admission document",
            "required": [
                "_id", "patient_id", "doctor_id", "hospital_id",
                "admission_type", "date_of_admission", "room_number", "created_at",
            ],
            "additionalProperties": False,
            "properties": {
                "_id":               {"bsonType": "string"},
                "patient_id":        {"bsonType": "string"},
                "doctor_id":         {"bsonType": "string"},
                "hospital_id":       {"bsonType": "string"},
                "admission_type":    {"enum": ["Elective", "Emergency", "Urgent"]},
                "date_of_admission": {"bsonType": "date"},
                "discharge_date":    {"bsonType": ["date", "null"]},
                "room_number":       {"bsonType": "int", "minimum": 1},
                "status":            {"enum": ["active", "discharged", "transferred"]},
                "created_at":        {"bsonType": "date"},
                "updated_at":        {"bsonType": "date"},
            },
        }
    },
    validationLevel="strict",
    validationAction="error",
)
db.admissions.create_index([("patient_id", ASCENDING)])
db.admissions.create_index([("doctor_id", ASCENDING)])
db.admissions.create_index([("date_of_admission", DESCENDING)])
db.admissions.create_index([("status", ASCENDING)])
print("Collection: admissions")


# 4. CLINICAL_RECORDS
db.create_collection(
    "clinical_records",
    validator={
        "$jsonSchema": {
            "bsonType": "object",
            "title": "Clinical record",
            "required": [
                "_id", "patient_id", "admission_id",
                "medical_condition", "medication", "test_results", "recorded_at",
            ],
            "additionalProperties": False,
            "properties": {
                "_id":               {"bsonType": "string"},
                "patient_id":        {"bsonType": "string"},
                "admission_id":      {"bsonType": "string"},
                "medical_condition": {"enum": ["Arthritis", "Asthma", "Cancer", "Diabetes", "Hypertension", "Obesity"]},
                "medication":        {"enum": ["Aspirin", "Ibuprofen", "Lipitor", "Paracetamol", "Penicillin"]},
                "test_results":      {"enum": ["Normal", "Abnormal", "Inconclusive"]},
                "notes":             {"bsonType": "string", "maxLength": 4000},
                "recorded_at":       {"bsonType": "date"},
                "updated_at":        {"bsonType": "date"},
            },
        }
    },
    validationLevel="strict",
    validationAction="error",
)
db.clinical_records.create_index([("patient_id", ASCENDING)])
db.clinical_records.create_index([("admission_id", ASCENDING)])
db.clinical_records.create_index([("medical_condition", ASCENDING)])
db.clinical_records.create_index([("test_results", ASCENDING)])
print("Collection: clinical_records")


# 5. BILLING — Financial records
db.create_collection(
    "billing",
    validator={
        "$jsonSchema": {
            "bsonType": "object",
            "title": "Billing record",
            "required": [
                "_id", "patient_id", "admission_id",
                "insurance_provider", "billing_amount",
                "payment_status", "created_at",
            ],
            "additionalProperties": False,
            "properties": {
                "_id":                {"bsonType": "string"},
                "patient_id":         {"bsonType": "string"},
                "admission_id":       {"bsonType": "string"},
                "insurance_provider": {"enum": ["Aetna", "Blue Cross", "Cigna", "Medicare", "UnitedHealthcare"]},
                "billing_amount":     {"bsonType": "double"},
                "payment_status":     {"enum": ["pending", "paid", "disputed", "written_off"]},
                "created_at":         {"bsonType": "date"},
                "updated_at":         {"bsonType": "date"},
            },
        }
    },
    validationLevel="strict",
    validationAction="error",
)
db.billing.create_index([("patient_id", ASCENDING)])
db.billing.create_index([("admission_id", ASCENDING)])
db.billing.create_index([("insurance_provider", ASCENDING)])
db.billing.create_index([("payment_status", ASCENDING)])
print("Collection: billing")


# VIEWS — Field-Level Row-Level Security
# Every role reads from a VIEW, never from the raw collection directly.

# Drop existing views (idempotent)
for view in [
    "v_patients_doctor", "v_patients_billing", "v_patients_reception",
    "v_admissions_doctor", "v_admissions_reception", "v_admissions_billing",
    "v_admissions_auditor",
    "v_clinical_doctor", "v_clinical_auditor",
    "v_billing_staff", "v_billing_auditor",
    "v_providers_all",
]:
    safe_drop(view)


# VIEW: patients — doctor
# Doctors see all demographic fields (blood type is clinically relevant).
db.command("create", "v_patients_doctor", viewOn="patients", pipeline=[
    {
        "$project": {
            "_id": 1,
            "full_name": 1,
            "age": 1,
            "gender": 1,
            "blood_type": 1, 
            "created_at": 1,
        }
    }
])
print("View: v_patients_doctor")


# VIEW: patients — billing_staff
# Billing staff sees name + age to match invoices.
# blood_type and gender are NOT needed for billing and are hidden.
db.command("create", "v_patients_billing", viewOn="patients", pipeline=[
    {
        "$project": {
            "_id": 1,
            "full_name": 1,
            "age": 1,
            # gender, blood_type, created_at not listed → hidden
        }
    }
])
print("View: v_patients_billing")


# VIEW: patients — receptionist
# Receptionists handle check-in: need name, age, gender. Not blood type.
db.command("create", "v_patients_reception", viewOn="patients", pipeline=[
    {
        "$project": {
            "_id": 1,
            "full_name": 1,
            "age": 1,
            "gender": 1,
            "created_at": 1,
            # blood_type not listed → hidden
        }
    }
])
print("View: v_patients_reception")


# VIEW: admissions — doctor / receptionist
# Full admission record (both roles need this for scheduling/clinical work).
_admissions_full_pipeline = [
    {
        "$project": {
            "_id": 1, "patient_id": 1, "doctor_id": 1, "hospital_id": 1,
            "admission_type": 1, "date_of_admission": 1, "discharge_date": 1,
            "room_number": 1, "status": 1, "created_at": 1,
        }
    }
]
db.command("create", "v_admissions_doctor",    viewOn="admissions", pipeline=_admissions_full_pipeline)
print("View: v_admissions_doctor")
db.command("create", "v_admissions_reception", viewOn="admissions", pipeline=_admissions_full_pipeline)
print("View: v_admissions_reception")


# VIEW: admissions — billing_staff
# Billing needs dates and type to compute fees, but not room details.
db.command("create", "v_admissions_billing", viewOn="admissions", pipeline=[
    {
        "$project": {
            "_id": 1, "patient_id": 1,
            "admission_type": 1, "date_of_admission": 1, "discharge_date": 1,
            "status": 1,
            # room_number, doctor_id, hospital_id not listed → hidden
        }
    }
])
print("View: v_admissions_billing")


# VIEW: admissions — auditor
# Auditors see everything in admissions (for compliance verification).
db.command("create", "v_admissions_auditor", viewOn="admissions", pipeline=[
    {
        "$project": {
            "_id": 1, "patient_id": 1, "doctor_id": 1, "hospital_id": 1,
            "admission_type": 1, "date_of_admission": 1, "discharge_date": 1,
            "room_number": 1, "status": 1, "created_at": 1, "updated_at": 1,
        }
    }
])
print("View: v_admissions_auditor")


# VIEW: clinical_records — doctor
# Doctors see full clinical record — this is their core job.
db.command("create", "v_clinical_doctor", viewOn="clinical_records", pipeline=[
    {
        "$project": {
            "_id": 1, "patient_id": 1, "admission_id": 1,
            "medical_condition": 1, "medication": 1, "test_results": 1,
            "notes": 1, "recorded_at": 1,
        }
    }
])
print("View: v_clinical_doctor")


# VIEW: clinical_records — auditor
# Auditors see clinical data for compliance but patient name is masked
db.command("create", "v_clinical_auditor", viewOn="clinical_records", pipeline=[
    {
        "$lookup": {
            "from": "patients",
            "localField": "patient_id",
            "foreignField": "_id",
            "as": "patient",
        }
    },
    {"$unwind": {"path": "$patient", "preserveNullAndEmptyArrays": True}},
    {
        "$addFields": {
            # "Mario Rossi" → "M.R." — auditor can check patterns, not individuals
            "patient_initials": {
                "$reduce": {
                    "input": {"$split": [{"$ifNull": ["$patient.full_name", ""]}, " "]},
                    "initialValue": "",
                    "in": {
                        "$concat": [
                            "$$value",
                            {
                                "$cond": [
                                    {"$eq": ["$$value", ""]},
                                    {"$substrCP": ["$$this", 0, 1]},
                                    {"$concat": [".", {"$substrCP": ["$$this", 0, 1]}, "."]},
                                ]
                            },
                        ]
                    },
                }
            },
            # Age bands instead of exact age: <30 / 30-50 / 50-70 / 70+
            "patient_age_band": {
                "$switch": {
                    "branches": [
                        {"case": {"$lt": ["$patient.age", 30]}, "then": "<30"},
                        {"case": {"$lt": ["$patient.age", 50]}, "then": "30-50"},
                        {"case": {"$lt": ["$patient.age", 70]}, "then": "50-70"},
                    ],
                    "default": "70+",
                }
            },
        }
    },
    {
        "$project": {
            "_id": 1, "admission_id": 1,
            "patient_initials": 1,   # M.R. instead of Mario Rossi
            "patient_age_band": 1,   # 30-50 instead of exact age
            "medical_condition": 1,
            "medication": 1,
            "test_results": 1,
            "recorded_at": 1,
            # patient_id, patient embed not listed → hidden
        }
    },
])
print("View: v_clinical_auditor")


# VIEW: billing — billing_staff
# Full billing access for billing_staff — this is their core job.
db.command("create", "v_billing_staff", viewOn="billing", pipeline=[
    {
        "$project": {
            "_id": 1, "patient_id": 1, "admission_id": 1,
            "insurance_provider": 1, "billing_amount": 1,
            "payment_status": 1, "created_at": 1, "updated_at": 1,
        }
    }
])
print("View: v_billing_staff")


# VIEW: billing — auditor
# Auditors see billing for compliance but amounts are rounded to nearest 1000
# and insurance provider is partially masked.
db.command("create", "v_billing_auditor", viewOn="billing", pipeline=[
    {
        "$addFields": {
            # 18856.28 → 19000 — order of magnitude visible, exact amount hidden
            "billing_amount_approx": {
                "$multiply": [
                    {"$round": [{"$divide": ["$billing_amount", 1000]}, 0]},
                    1000,
                ]
            },
            # "Blue Cross" → "Blu***" — provider category visible, not exact name
            "insurance_masked": {
                "$concat": [
                    {"$substrCP": ["$insurance_provider", 0, 3]},
                    "***",
                ]
            },
        }
    },
    {
        "$project": {
            "_id": 1, "patient_id": 1, "admission_id": 1,
            "billing_amount_approx": 1,   # rounded to nearest 1000
            "insurance_masked": 1,         # first 3 chars + ***
            "payment_status": 1,
            "created_at": 1,
            # billing_amount, insurance_provider not listed → hidden
        }
    },
])
print("View: v_billing_auditor")


# VIEW: providers — all roles
# Providers (doctors/hospitals) are not sensitive — all roles see the same.
db.command("create", "v_providers_all", viewOn="providers", pipeline=[
    {"$project": {"_id": 1, "type": 1, "name": 1}}
])
print("View: v_providers_all")


# ROLES — each role reads from views, writes to raw collections

roles_def = [
    {
        "role": "zta_admin",
        "privileges": [
            # Admin has full access to raw collections AND views
            {
                "resource": {"db": MONGO_DB, "collection": ""},
                "actions": [
                    "find", "insert", "update", "remove",
                    "createCollection", "dropCollection", "createIndex", "listCollections",
                ],
            }
        ],
        "roles": [],
    },
    {
        "role": "zta_doctor",
        "privileges": [
            # Reads from views (field-level RLS enforced by the view pipeline)
            {"resource": {"db": MONGO_DB, "collection": "v_patients_doctor"},   "actions": ["find"]},
            {"resource": {"db": MONGO_DB, "collection": "v_providers_all"},     "actions": ["find"]},
            {"resource": {"db": MONGO_DB, "collection": "v_admissions_doctor"}, "actions": ["find"]},
            {"resource": {"db": MONGO_DB, "collection": "v_clinical_doctor"},   "actions": ["find"]},
            # Writes go to raw collections (schema validation still applies)
            {"resource": {"db": MONGO_DB, "collection": "admissions"},       "actions": ["insert", "update"]},
            {"resource": {"db": MONGO_DB, "collection": "clinical_records"}, "actions": ["insert", "update"]},
            # Explicitly NO access to: billing
        ],
        "roles": [],
    },
    {
        "role": "zta_billing",
        "privileges": [
            # Views: patients without blood_type, admissions without room/doctor,
            #        billing full access (it's their core job)
            {"resource": {"db": MONGO_DB, "collection": "v_patients_billing"},   "actions": ["find"]},
            {"resource": {"db": MONGO_DB, "collection": "v_admissions_billing"}, "actions": ["find"]},
            {"resource": {"db": MONGO_DB, "collection": "v_providers_all"},      "actions": ["find"]},
            {"resource": {"db": MONGO_DB, "collection": "v_billing_staff"},      "actions": ["find"]},
            # Writes to billing raw collection
            {"resource": {"db": MONGO_DB, "collection": "billing"}, "actions": ["insert", "update"]},
            # Explicitly NO access to: clinical_records
        ],
        "roles": [],
    },
    {
        "role": "zta_auditor",
        "privileges": [
            # Auditors see everything but with masked sensitive fields via views
            {"resource": {"db": MONGO_DB, "collection": "v_patients_doctor"},   "actions": ["find"]},
            {"resource": {"db": MONGO_DB, "collection": "v_providers_all"},     "actions": ["find"]},
            {"resource": {"db": MONGO_DB, "collection": "v_admissions_auditor"}, "actions": ["find"]},
            {"resource": {"db": MONGO_DB, "collection": "v_clinical_auditor"},  "actions": ["find"]},  # patient name → initials
            {"resource": {"db": MONGO_DB, "collection": "v_billing_auditor"},   "actions": ["find"]},  # amount rounded, provider masked
            # Auditors NEVER write anything
        ],
        "roles": [],
    },
    {
        "role": "zta_receptionist",
        "privileges": [
            # Receptionists see patients (no blood_type) and manage admissions
            {"resource": {"db": MONGO_DB, "collection": "v_patients_reception"},   "actions": ["find"]},
            {"resource": {"db": MONGO_DB, "collection": "v_providers_all"},        "actions": ["find"]},
            {"resource": {"db": MONGO_DB, "collection": "v_admissions_reception"}, "actions": ["find"]},
            # Writes
            {"resource": {"db": MONGO_DB, "collection": "patients"},   "actions": ["insert", "update"]},
            {"resource": {"db": MONGO_DB, "collection": "admissions"},  "actions": ["insert", "update"]},
            # Explicitly NO access to: clinical_records, billing
        ],
        "roles": [],
    },
]

for role_doc in roles_def:
    try:
        db.command("dropRole", role_doc["role"])
    except OperationFailure:
        pass
    db.command("createRole", role_doc["role"],
               privileges=role_doc["privileges"],
               roles=role_doc["roles"])
    print(f"Role created: {role_doc['role']}")

# Create the Envoy proxy X.509 user in $external database
db_external = client["$external"]
db_admin = client["admin"]

# Create custom role with 'impersonate' privilege to allow proxy impersonation
try:
    db_admin.command(
        "createRole", "impersonatorRole",
        privileges=[
            {
                "resource": { "db": "", "collection": "" },
                "actions": [ "impersonate" ]
            }
        ],
        roles=[]
    )
    print("Role 'impersonatorRole' created in admin")
except OperationFailure as e:
    if "already exists" in str(e):
        print("Role 'impersonatorRole' already exists")
    else:
        print(f"Warning: Failed to create impersonatorRole: {e}")

ZTA_ORGANIZATION = os.getenv("ZTA_ORGANIZATION", "AdvancedCybersecurity-ORG")

try:
    db_external.command("dropUser", f"CN=envoy,O={ZTA_ORGANIZATION},C=IT")
except OperationFailure:
    pass

envoy_roles = [{"role": role_config["mongo_role"], "db": MONGO_DB} for role_config in ZTA_ROLES.values()]
envoy_roles.append({"role": "impersonatorRole", "db": "admin"})

db_external.command(
    "createUser", f"CN=envoy,O={ZTA_ORGANIZATION},C=IT",
    roles=envoy_roles
)
print(f"X.509 User created in $external: CN=envoy,O={ZTA_ORGANIZATION},C=IT")
print("\n *** RLS complete: views + roles + users ready ***")

client.close()
