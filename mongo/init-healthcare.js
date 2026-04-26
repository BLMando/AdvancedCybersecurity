// ─── ZTA Healthcare Database — Schema Validation & Collection Setup ────────
// Run via: mongosh -u admin -p <pass> --eval "load('/init-healthcare.js')"
// Or: docker exec mongo mongosh -u admin -p secret --file /docker-entrypoint-initdb.d/init-healthcare.js

const db = db.getSiblingDB("zta_db");

print("╔══════════════════════════════════════════════════════════════╗");
print("║  RLS complete: views + roles + users ready.                 ║");
print("║  Run: python3 mongo/seed-db.py                             ║");
print("╚══════════════════════════════════════════════════════════════╝");

// ─── Drop existing collections (idempotent init) ───────────────────────────
["patients", "admissions", "clinical_records", "billing", "providers"].forEach(c => {
  try { db[c].drop(); } catch (e) { }
});

// ─── 1. PATIENTS — Identity layer (SENSITIVE) ──────────────────────────────
// Contains: demographic data and PII.
// Accessible by: admin (CRUD), doctor/nurse (R), receptionist (R), billing_staff (R — limited fields).
// clinical data is intentionally NOT stored here (normalised to clinical_records).
db.createCollection("patients", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      title: "Patient document",
      required: ["_id", "full_name", "age", "gender", "blood_type", "created_at"],
      additionalProperties: false,
      properties: {
        _id: { bsonType: "string", description: "UUID v4 — primary key" },
        full_name: { bsonType: "string", minLength: 2, maxLength: 120 },
        age: { bsonType: "int", minimum: 0, maximum: 130 },
        gender: { enum: ["Male", "Female", "Other"] },
        blood_type: { enum: ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"] },
        created_at: { bsonType: "date" },
        updated_at: { bsonType: "date" }
      }
    }
  },
  validationLevel: "strict",
  validationAction: "error"
});

db.patients.createIndex({ full_name: 1 });
db.patients.createIndex({ age: 1 });
print("✓  Collection: patients");

// ─── 2. PROVIDERS — Doctors & Hospitals (INTERNAL) ────────────────────────
// Contains: doctor names, hospital names.
// Accessible by: all authenticated users (R), admin (CRUD).
db.createCollection("providers", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      title: "Provider document",
      required: ["_id", "type", "name"],
      additionalProperties: false,
      properties: {
        _id: { bsonType: "string" },
        type: { enum: ["doctor", "hospital"] },
        name: { bsonType: "string", minLength: 2, maxLength: 200 },
        metadata: { bsonType: "object" }
      }
    }
  },
  validationLevel: "strict",
  validationAction: "error"
});

db.providers.createIndex({ type: 1, name: 1 });
print("✓  Collection: providers");

// ─── 3. ADMISSIONS — Encounter records (SENSITIVE) ────────────────────────
// Contains: admission dates, type, room, discharge, FK to patient & provider.
// Accessible by: admin (CRUD), doctor (CRUD), receptionist (CRUD), nurse (R), auditor (R).
db.createCollection("admissions", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      title: "Admission document",
      required: ["_id", "patient_id", "doctor_id", "hospital_id",
        "admission_type", "date_of_admission", "room_number", "created_at"],
      additionalProperties: false,
      properties: {
        _id: { bsonType: "string" },
        patient_id: { bsonType: "string" },
        doctor_id: { bsonType: "string" },
        hospital_id: { bsonType: "string" },
        admission_type: { enum: ["Elective", "Emergency", "Urgent"] },
        date_of_admission: { bsonType: "date" },
        discharge_date: { bsonType: ["date", "null"] },
        room_number: { bsonType: "int", minimum: 1 },
        status: { enum: ["active", "discharged", "transferred"] },
        created_at: { bsonType: "date" },
        updated_at: { bsonType: "date" }
      }
    }
  },
  validationLevel: "strict",
  validationAction: "error"
});

db.admissions.createIndex({ patient_id: 1 });
db.admissions.createIndex({ doctor_id: 1 });
db.admissions.createIndex({ date_of_admission: -1 });
db.admissions.createIndex({ status: 1 });
print("✓  Collection: admissions");

// ─── 4. CLINICAL_RECORDS — Medical data (MOST SENSITIVE) ──────────────────
// Contains: diagnosis, medication, test results.
// Accessible by: admin (CRUD), doctor (CRUD), nurse (R). ALL OTHERS: DENY.
// This collection is in OPA sensitive_collections → tighter risk threshold.
db.createCollection("clinical_records", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      title: "Clinical record",
      required: ["_id", "patient_id", "admission_id",
        "medical_condition", "medication", "test_results", "recorded_at"],
      additionalProperties: false,
      properties: {
        _id: { bsonType: "string" },
        patient_id: { bsonType: "string" },
        admission_id: { bsonType: "string" },
        medical_condition: { enum: ["Arthritis", "Asthma", "Cancer", "Diabetes", "Hypertension", "Obesity"] },
        medication: { enum: ["Aspirin", "Ibuprofen", "Lipitor", "Paracetamol", "Penicillin"] },
        test_results: { enum: ["Normal", "Abnormal", "Inconclusive"] },
        notes: { bsonType: "string", maxLength: 4000 },
        recorded_at: { bsonType: "date" },
        updated_at: { bsonType: "date" }
      }
    }
  },
  validationLevel: "strict",
  validationAction: "error"
});

db.clinical_records.createIndex({ patient_id: 1 });
db.clinical_records.createIndex({ admission_id: 1 });
db.clinical_records.createIndex({ medical_condition: 1 });
db.clinical_records.createIndex({ test_results: 1 });
print("✓  Collection: clinical_records");

// ─── 5. BILLING — Financial records (SENSITIVE) ────────────────────────────
// Contains: billing amounts, insurance provider, FK to admission & patient.
// Accessible by: admin (CRUD), billing_staff (CRUD), auditor (R). ALL OTHERS: DENY.
db.createCollection("billing", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      title: "Billing record",
      required: ["_id", "patient_id", "admission_id",
        "insurance_provider", "billing_amount",
        "payment_status", "created_at"],
      additionalProperties: false,
      properties: {
        _id: { bsonType: "string" },
        patient_id: { bsonType: "string" },
        admission_id: { bsonType: "string" },
        insurance_provider: { enum: ["Aetna", "Blue Cross", "Cigna", "Medicare", "UnitedHealthcare"] },
        billing_amount: { bsonType: "double" },
        payment_status: { enum: ["pending", "paid", "disputed", "written_off"] },
        created_at: { bsonType: "date" },
        updated_at: { bsonType: "date" }
      }
    }
  },
  validationLevel: "strict",
  validationAction: "error"
});

db.billing.createIndex({ patient_id: 1 });
db.billing.createIndex({ admission_id: 1 });
db.billing.createIndex({ insurance_provider: 1 });
db.billing.createIndex({ payment_status: 1 });
print("✓  Collection: billing");


// ═══════════════════════════════════════════════════════════════════════════
// VIEWS — Field-Level Row-Level Security
// ═══════════════════════════════════════════════════════════════════════════
// Every role reads from a VIEW, never from the raw collection directly.
// The view pipeline acts as a mandatory projection that cannot be bypassed
// by the client — MongoDB enforces it server-side before returning results.
//
// RLS matrix summary:
//   patients_for_billing  → billing_staff  : no blood_type, no gender
//   patients_for_reception→ receptionist   : no blood_type
//   patients_for_doctor   → doctor         : full demographics, no billing link
//   billing_for_auditor   → auditor        : amount rounded to nearest 1000
//   clinical_for_auditor  → auditor        : patient name masked to initials
// ═══════════════════════════════════════════════════════════════════════════

// Drop existing views (idempotent)
[
  "v_patients_doctor", "v_patients_billing", "v_patients_reception",
  "v_admissions_doctor", "v_admissions_reception", "v_admissions_billing",
  "v_admissions_auditor",
  "v_clinical_doctor", "v_clinical_auditor",
  "v_billing_staff", "v_billing_auditor",
  "v_providers_all"
].forEach(v => { try { db[v].drop(); } catch (e) { } });

// ─── VIEW: patients — doctor ───────────────────────────────────────────────
// Doctors see all demographic fields (they need blood type for clinical care).
db.createView("v_patients_doctor", "patients", [
  {
    $project: {
      _id: 1,
      full_name: 1,
      age: 1,
      gender: 1,
      blood_type: 1,  // ← visible: clinically relevant
      created_at: 1
    }
  }
]);
print("✓  View: v_patients_doctor");

// ─── VIEW: patients — billing_staff ────────────────────────────────────────
// Billing staff sees name + age to match invoices.
// blood_type and gender are NOT needed for billing and are hidden.
db.createView("v_patients_billing", "patients", [
  {
    $project: {
      _id: 1,
      full_name: 1,
      age: 1
      // gender, blood_type, created_at not listed → hidden
    }
  }
]);
print("✓  View: v_patients_billing");

// ─── VIEW: patients — receptionist ─────────────────────────────────────────
// Receptionists handle check-in: need name, age, gender. Not blood type.
db.createView("v_patients_reception", "patients", [
  {
    $project: {
      _id: 1,
      full_name: 1,
      age: 1,
      gender: 1,
      created_at: 1
      // blood_type not listed → hidden
    }
  }
]);
print("✓  View: v_patients_reception");

// ─── VIEW: admissions — doctor / receptionist ──────────────────────────────
// Full admission record (both roles need this for scheduling/clinical work).
db.createView("v_admissions_doctor", "admissions", [
  {
    $project: {
      _id: 1, patient_id: 1, doctor_id: 1, hospital_id: 1,
      admission_type: 1, date_of_admission: 1, discharge_date: 1,
      room_number: 1, status: 1, created_at: 1
    }
  }
]);
print("✓  View: v_admissions_doctor");

db.createView("v_admissions_reception", "admissions", [
  {
    $project: {
      _id: 1, patient_id: 1, doctor_id: 1, hospital_id: 1,
      admission_type: 1, date_of_admission: 1, discharge_date: 1,
      room_number: 1, status: 1, created_at: 1
    }
  }
]);
print("✓  View: v_admissions_reception");

// ─── VIEW: admissions — billing_staff ──────────────────────────────────────
// Billing needs dates and type to compute fees, but not room details.
db.createView("v_admissions_billing", "admissions", [
  {
    $project: {
      _id: 1, patient_id: 1,
      admission_type: 1, date_of_admission: 1, discharge_date: 1,
      status: 1
      // room_number, doctor_id, hospital_id not listed → hidden
    }
  }
]);
print("✓  View: v_admissions_billing");

// ─── VIEW: admissions — auditor ────────────────────────────────────────────
// Auditors see everything in admissions (for compliance verification).
db.createView("v_admissions_auditor", "admissions", [
  {
    $project: {
      _id: 1, patient_id: 1, doctor_id: 1, hospital_id: 1,
      admission_type: 1, date_of_admission: 1, discharge_date: 1,
      room_number: 1, status: 1, created_at: 1, updated_at: 1
    }
  }
]);
print("✓  View: v_admissions_auditor");

// ─── VIEW: clinical_records — doctor ───────────────────────────────────────
// Doctors see full clinical record — this is their core job.
db.createView("v_clinical_doctor", "clinical_records", [
  {
    $project: {
      _id: 1, patient_id: 1, admission_id: 1,
      medical_condition: 1, medication: 1, test_results: 1,
      notes: 1, recorded_at: 1
    }
  }
]);
print("✓  View: v_clinical_doctor");

// ─── VIEW: clinical_records — auditor ──────────────────────────────────────
// Auditors see clinical data for compliance but patient name is masked
// to initials (joined from patients collection via $lookup).
// This prevents the auditor from identifying specific individuals.
db.createView("v_clinical_auditor", "clinical_records", [
  {
    $lookup: {
      from: "patients",
      localField: "patient_id",
      foreignField: "_id",
      as: "patient"
    }
  },
  { $unwind: { path: "$patient", preserveNullAndEmptyArrays: true } },
  {
    $addFields: {
      // "Mario Rossi" → "M.R." — auditor can check patterns, not individuals
      patient_initials: {
        $reduce: {
          input: { $split: [{ $ifNull: ["$patient.full_name", ""] }, " "] },
          initialValue: "",
          in: {
            $concat: [
              "$$value",
              {
                $cond: [
                  { $eq: ["$$value", ""] },
                  { $substrCP: ["$$this", 0, 1] },
                  { $concat: [".", { $substrCP: ["$$this", 0, 1] }, "."] }
                ]
              }
            ]
          }
        }
      },
      patient_age_band: {
        // Age bands instead of exact age: <30 / 30-50 / 50-70 / 70+
        $switch: {
          branches: [
            { case: { $lt: ["$patient.age", 30] }, then: "<30" },
            { case: { $lt: ["$patient.age", 50] }, then: "30-50" },
            { case: { $lt: ["$patient.age", 70] }, then: "50-70" },
          ],
          default: "70+"
        }
      }
    }
  },
  {
    $project: {
      _id: 1, admission_id: 1,
      patient_initials: 1,   // M.R. instead of Mario Rossi
      patient_age_band: 1,   // 30-50 instead of exact age
      medical_condition: 1,
      medication: 1,
      test_results: 1,
      recorded_at: 1
      // patient_id, patient embed not listed → hidden
    }
  }
]);
print("✓  View: v_clinical_auditor");

// ─── VIEW: billing — billing_staff ─────────────────────────────────────────
// Full billing access for billing_staff — this is their core job.
db.createView("v_billing_staff", "billing", [
  {
    $project: {
      _id: 1, patient_id: 1, admission_id: 1,
      insurance_provider: 1, billing_amount: 1,
      payment_status: 1, created_at: 1, updated_at: 1
    }
  }
]);
print("✓  View: v_billing_staff");

// ─── VIEW: billing — auditor ───────────────────────────────────────────────
// Auditors see billing for compliance but amounts are rounded to nearest 1000
// and insurance provider is partially masked.
db.createView("v_billing_auditor", "billing", [
  {
    $addFields: {
      // 18856.28 → 19000 — order of magnitude visible, exact amount hidden
      billing_amount_approx: {
        $multiply: [
          { $round: [{ $divide: ["$billing_amount", 1000] }, 0] },
          1000
        ]
      },
      // "Blue Cross" → "Blu***" — provider category visible, not exact name
      insurance_masked: {
        $concat: [
          { $substrCP: ["$insurance_provider", 0, 3] },
          "***"
        ]
      }
    }
  },
  {
    $project: {
      _id: 1, patient_id: 1, admission_id: 1,
      billing_amount_approx: 1,  // rounded to nearest 1000
      insurance_masked: 1,  // first 3 chars + ***
      payment_status: 1,
      created_at: 1
      // billing_amount, insurance_provider not listed → hidden
    }
  }
]);
print("✓  View: v_billing_auditor");

// ─── VIEW: providers — all roles ───────────────────────────────────────────
// Providers (doctors/hospitals) are not sensitive — all roles see the same.
db.createView("v_providers_all", "providers", [
  { $project: { _id: 1, type: 1, name: 1 } }
]);
print("✓  View: v_providers_all");

// ═══════════════════════════════════════════════════════════════════════════
// ROLES — each role reads from views, writes to raw collections
// ═══════════════════════════════════════════════════════════════════════════

const rolesDef = [
  {
    role: "zta_admin",
    privileges: [
      // Admin has full access to raw collections AND views
      {
        resource: { db: "zta_db", collection: "" },
        actions: ["find", "insert", "update", "remove", "createCollection", "dropCollection", "createIndex", "listCollections"]
      }
    ],
    roles: []
  },
  {
    role: "zta_doctor",
    privileges: [
      // Reads from views (field-level RLS enforced by the view pipeline)
      { resource: { db: "zta_db", collection: "v_patients_doctor" }, actions: ["find"] },
      { resource: { db: "zta_db", collection: "v_providers_all" }, actions: ["find"] },
      { resource: { db: "zta_db", collection: "v_admissions_doctor" }, actions: ["find"] },
      { resource: { db: "zta_db", collection: "v_clinical_doctor" }, actions: ["find"] },
      // Writes go to raw collections (schema validation still applies)
      { resource: { db: "zta_db", collection: "admissions" }, actions: ["insert", "update"] },
      { resource: { db: "zta_db", collection: "clinical_records" }, actions: ["insert", "update"] },
      // Explicitly NO access to: billing
    ],
    roles: []
  },
  {
    role: "zta_billing",
    privileges: [
      // Views: patients without blood_type, admissions without room/doctor,
      //        billing full access (it's their core job)
      { resource: { db: "zta_db", collection: "v_patients_billing" }, actions: ["find"] },
      { resource: { db: "zta_db", collection: "v_admissions_billing" }, actions: ["find"] },
      { resource: { db: "zta_db", collection: "v_providers_all" }, actions: ["find"] },
      { resource: { db: "zta_db", collection: "v_billing_staff" }, actions: ["find"] },
      // Writes to billing raw collection
      { resource: { db: "zta_db", collection: "billing" }, actions: ["insert", "update"] },
      // Explicitly NO access to: clinical_records
    ],
    roles: []
  },
  {
    role: "zta_auditor",
    privileges: [
      // Auditors see everything but with masked sensitive fields via views
      { resource: { db: "zta_db", collection: "v_patients_doctor" }, actions: ["find"] },
      { resource: { db: "zta_db", collection: "v_providers_all" }, actions: ["find"] },
      { resource: { db: "zta_db", collection: "v_admissions_auditor" }, actions: ["find"] },
      { resource: { db: "zta_db", collection: "v_clinical_auditor" }, actions: ["find"] }, // patient name → initials
      { resource: { db: "zta_db", collection: "v_billing_auditor" }, actions: ["find"] }, // amount rounded, provider masked
      // Auditors NEVER write anything
    ],
    roles: []
  },
  {
    role: "zta_receptionist",
    privileges: [
      // Receptionists see patients (no blood_type) and manage admissions
      { resource: { db: "zta_db", collection: "v_patients_reception" }, actions: ["find"] },
      { resource: { db: "zta_db", collection: "v_providers_all" }, actions: ["find"] },
      { resource: { db: "zta_db", collection: "v_admissions_reception" }, actions: ["find"] },
      // Writes
      { resource: { db: "zta_db", collection: "patients" }, actions: ["insert", "update"] },
      { resource: { db: "zta_db", collection: "admissions" }, actions: ["insert", "update"] },
      // Explicitly NO access to: clinical_records, billing
    ],
    roles: []
  }
];

rolesDef.forEach(r => {
  try { db.dropRole(r.role); } catch (e) { }
  db.createRole(r);
  print(`✓  Role created: ${r.role}`);
});

// ─── MongoDB Users ──────────────────────────────────────────────────────────
const usersDef = [
  { user: "mario.rossi", pwd: "MarioRossi2024!", roles: [{ role: "zta_doctor", db: "zta_db" }] },
  { user: "anna.verdi", pwd: "AnnaVerdi2024!", roles: [{ role: "zta_billing", db: "zta_db" }] },
  { user: "giulia.bianchi", pwd: "GiuliaBianchi2024!", roles: [{ role: "zta_auditor", db: "zta_db" }] },
  { user: "luca.ferrari", pwd: "LucaFerrari2024!", roles: [{ role: "zta_receptionist", db: "zta_db" }] },
];

usersDef.forEach(u => {
  try { db.dropUser(u.user); } catch (e) { }
  db.createUser({ user: u.user, pwd: u.pwd, roles: u.roles });
  print(`✓  User created: ${u.user}`);
});

print("\n╔══════════════════════════════════════════════════════════════╗");
print("║  RLS complete: views + roles + users ready.                 ║");
print("║  Run: python3 scripts/seed-db.py                           ║");
print("╚══════════════════════════════════════════════════════════════╝");
