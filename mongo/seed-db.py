#!/usr/bin/env python3
"""
seed-db.py — Reads healthcare_dataset.csv and populates the ZTA MongoDB.

Usage:
  python3 mongo/seed-db.py [--uri mongodb://admin:secret@localhost:10000/zta_db?authSource=admin]
                            [--csv path/to/healthcare_dataset.csv]
                            [--limit N]   # rows to import (default: all)

The script normalises the flat CSV into the five relational-style collections:
  patients / providers / admissions / clinical_records / billing

Each document receives a deterministic UUID derived from the row's natural key
so re-running the script is idempotent (upsert, not insert).
"""

import sys
import uuid
import argparse
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

try:
    from pymongo import MongoClient, UpdateOne
    from pymongo.errors import BulkWriteError
except ImportError:
    print("ERROR: pymongo not installed. Run: pip install pymongo --break-system-packages")
    sys.exit(1)

# ─── CLI args ──────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Seed ZTA Healthcare DB from CSV")
parser.add_argument(
    "--uri",   default="mongodb://admin:secret@localhost:27017/zta_db?authSource=admin")
parser.add_argument("--csv",   default="mongo/dataset/healthcare_dataset.csv")
parser.add_argument("--limit", type=int, default=None,
                    help="Max rows to import")
args = parser.parse_args()

# ─── Helpers ────────────────────────────────────────────────────────────────


def det_uuid(namespace: str, key: str) -> str:
    """Deterministic UUID5 from a namespace string + natural key."""
    ns = uuid.UUID(hashlib.md5(namespace.encode()).hexdigest())
    return str(uuid.uuid5(ns, key))


def parse_date(val: Any | None):
    """Parse ISO date string → timezone-aware datetime."""
    if not val or pd.isna(val):
        return None
    return datetime.fromisoformat(str(val)).replace(tzinfo=timezone.utc)


def norm_name(raw: Any) -> str:
    """Normalise mixed-case names like 'Bobby JacksOn' → 'Bobby Jackson'."""
    return str(raw).strip().title()


NOW = datetime.now(timezone.utc)

# ─── Load CSV ───────────────────────────────────────────────────────────────
csv_path = Path(args.csv)
if not csv_path.exists():
    print(f"ERROR: CSV not found at {csv_path}")
    sys.exit(1)

print(f"Loading {csv_path} …", flush=True)
df = pd.read_csv(csv_path, nrows=args.limit)
df.columns = [c.strip() for c in df.columns]

# Normalise name casing
df["Name"] = df["Name"].apply(norm_name)
df["Doctor"] = df["Doctor"].apply(norm_name)
df["Hospital"] = df["Hospital"].apply(norm_name)

total_rows = len(df)
print(f"  {total_rows:,} rows loaded")

# ─── Connect ────────────────────────────────────────────────────────────────
print(f"Connecting to {args.uri} …", flush=True)
client: MongoClient[dict[str, Any]] = MongoClient(
    args.uri, serverSelectionTimeoutMS=5000)
try:
    client.admin.command("ping")
except Exception as e:
    print(f"ERROR: Cannot connect to MongoDB — {e}")
    sys.exit(1)

db: Any = client.get_database()
print("  Connected\n")

# ─── 1. PROVIDERS ───────────────────────────────────────────────────────────
print("→ Seeding: providers …", flush=True)
provider_ops: list[UpdateOne] = []

doctors = df["Doctor"].dropna().unique()
hospitals = df["Hospital"].dropna().unique()

for name in doctors:
    pid = det_uuid("doctor", name)
    provider_ops.append(UpdateOne(
        {"_id": pid},
        {"$setOnInsert": {"_id": pid, "type": "doctor", "name": name}},
        upsert=True
    ))

for name in hospitals:
    pid = det_uuid("hospital", name)
    provider_ops.append(UpdateOne(
        {"_id": pid},
        {"$setOnInsert": {"_id": pid, "type": "hospital", "name": name}},
        upsert=True
    ))

if provider_ops:
    db.providers.bulk_write(provider_ops, ordered=False)
print(f"   {len(doctors):,} doctors, {len(hospitals):,} hospitals")

# ─── 2. PATIENTS ─────────────────────────────────────────────────────────────
print("→ Seeding: patients …", flush=True)
patient_ops: list[UpdateOne] = []
patient_id_map = {}  # name → uuid

unique_patients = df.drop_duplicates(subset=["Name"]).copy()
for _, row in unique_patients.iterrows():
    pid = det_uuid("patient", row["Name"])
    patient_id_map[row["Name"]] = pid
    patient_ops.append(UpdateOne(
        {"_id": pid},
        {"$setOnInsert": {
            "_id":        pid,
            "full_name":  row["Name"],
            "age":        int(row["Age"]),
            "gender":     row["Gender"],
            "blood_type": row["Blood Type"],
            "created_at": NOW,
        }},
        upsert=True
    ))

if patient_ops:
    db.patients.bulk_write(patient_ops, ordered=False)
print(f"   {len(unique_patients):,} unique patients")

# ─── 3. ADMISSIONS + 4. CLINICAL RECORDS + 5. BILLING ───────────────────────
print("→ Seeding: admissions / clinical_records / billing …", flush=True)
admission_ops: list[UpdateOne] = []
clinical_ops: list[UpdateOne] = []
billing_ops: list[UpdateOne] = []

for row_num, (_, row) in enumerate(df.iterrows(), start=1):
    patient_id = det_uuid("patient",  row["Name"])
    doctor_id = det_uuid("doctor",   row["Doctor"])
    hospital_id = det_uuid("hospital", row["Hospital"])

    # Natural key for admission: patient + date of admission
    adm_key = f"{row['Name']}|{row['Date of Admission']}"
    adm_id = det_uuid("admission", adm_key)

    # 3. Admissions
    discharge = parse_date(row.get("Discharge Date"))
    status = "discharged" if discharge else "active"

    admission_ops.append(UpdateOne(
        {"_id": adm_id},
        {"$setOnInsert": {
            "_id":               adm_id,
            "patient_id":        patient_id,
            "doctor_id":         doctor_id,
            "hospital_id":       hospital_id,
            "admission_type":    row["Admission Type"],
            "date_of_admission": parse_date(row["Date of Admission"]),
            "discharge_date":    discharge,
            "room_number":       int(row["Room Number"]),
            "status":            status,
            "created_at":        NOW,
            "updated_at":        NOW,
        }},
        upsert=True
    ))

    # 4. Clinical records
    clin_key = f"{adm_key}|clinical"
    clin_id = det_uuid("clinical", clin_key)

    clinical_ops.append(UpdateOne(
        {"_id": clin_id},
        {"$setOnInsert": {
            "_id":               clin_id,
            "patient_id":        patient_id,
            "admission_id":      adm_id,
            "medical_condition": row["Medical Condition"],
            "medication":        row["Medication"],
            "test_results":      row["Test Results"],
            "recorded_at":       parse_date(row["Date of Admission"]),
            "updated_at":        NOW,
        }},
        upsert=True
    ))

    # 5. Billing
    bill_key = f"{adm_key}|billing"
    bill_id = det_uuid("billing", bill_key)
    amount = float(row["Billing Amount"]) if pd.notna(
        row["Billing Amount"]) else 0.0

    billing_ops.append(UpdateOne(
        {"_id": bill_id},
        {"$setOnInsert": {
            "_id":                bill_id,
            "patient_id":         patient_id,
            "admission_id":       adm_id,
            "insurance_provider": row["Insurance Provider"],
            "billing_amount":     amount,
            "payment_status":     "paid" if discharge else "pending",
            "created_at":         NOW,
            "updated_at":         NOW,
        }},
        upsert=True
    ))

    if row_num % 5000 == 0:
        print(f"   {row_num:,} / {total_rows:,} rows processed …", flush=True)

# Flush in batches


def bulk(collection: Any, ops: list[UpdateOne], label: str) -> None:
    if not ops:
        return
    try:
        result = collection.bulk_write(ops, ordered=False)
        print(
            f"   {label}: {result.upserted_count:,} new, {result.matched_count:,} existing")
    except BulkWriteError as e:
        print(
            f"   {label}: partial write — {e.details['nInserted']} inserted, errors: {len(e.details['writeErrors'])}")


bulk(db.admissions,       admission_ops, "admissions       ")
bulk(db.clinical_records, clinical_ops,  "clinical_records ")
bulk(db.billing,          billing_ops,   "billing          ")

# ─── Summary ────────────────────────────────────────────────────────────────
print()
print("╔══════════════════════════════════════════════════════════════╗")
print("║  Seed complete — collection counts                          ║")
print("╚══════════════════════════════════════════════════════════════╝")
for col in ["patients", "providers", "admissions", "clinical_records", "billing"]:
    n = db[col].count_documents({})
    print(f"  {col:<20} {n:>8,} documents")

client.close()
print("\nDone.")
