import os
import sys
import argparse
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

try:
    from pymongo import MongoClient
    from pymongo.errors import ConfigurationError
except ImportError:
    print("ERROR: pymongo not installed. Run: pip install pymongo")
    sys.exit(1)

# List of all raw collections containing application data
COLLECTIONS = ["patients", "providers", "admissions", "clinical_records", "billing"]

def main():
    parser = argparse.ArgumentParser(description="Clean all data in ZTA MongoDB collections.")
    parser.add_argument(
        "--uri",
        default=os.getenv("MONGODB_URI", "mongodb://zta_user:zta_password@localhost:27017/zta_db?authSource=admin"),
        help="MongoDB connection URI"
    )
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip confirmation prompt"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show counts of documents that would be deleted without deleting them"
    )
    args = parser.parse_args()

    # Paths to certificates
    ca_file = PROJECT_ROOT / "volumes" / "certs" / "ca" / "ca.crt"
    cert_file = PROJECT_ROOT / "volumes" / "certs" / "server" / "mongo.pem"

    # Set up TLS connection params if certs exist
    tls_params = {}
    if ca_file.exists() and cert_file.exists():
        tls_params = {
            "tls": True,
            "tlsCertificateKeyFile": str(cert_file),
            "tlsCAFile": str(ca_file),
            "tlsAllowInvalidCertificates": True
        }
        print(f"ℹUsing TLS credentials:")
        print(f"   CA: {ca_file}")
        print(f"   Cert/Key: {cert_file}")
    else:
        print("Warning: TLS cert files not found. Connecting without cert parameters.")

    print(f"🔌 Connecting to MongoDB...")
    
    try:
        client = MongoClient(
            args.uri,
            serverSelectionTimeoutMS=5000,
            **tls_params
        )
        # Ping database to confirm connectivity
        client.admin.command("ping")
    except Exception as e:
        print(f"ERROR: Cannot connect to MongoDB — {e}")
        sys.exit(1)

    try:
        db = client.get_database()
    except ConfigurationError:
        default_db = os.getenv("MONGO_INITDB_DATABASE", "zta_db")
        db = client.get_database(default_db)
    db_name = db.name
    print(f"Connected to database: {db_name}\n")

    # Fetch document counts before reset
    counts = {}
    total_docs = 0
    print("Current collection counts:")
    for col_name in COLLECTIONS:
        try:
            count = db[col_name].count_documents({})
            counts[col_name] = count
            total_docs += count
            print(f"   - {col_name:<20}: {count:>8,} documents")
        except Exception as e:
            print(f"   - {col_name:<20}: Error reading count ({e})")
            counts[col_name] = None

    if total_docs == 0:
        print("\nAll collections are already empty. Nothing to clean.")
        client.close()
        return

    if args.dry_run:
        print(f"\n[Dry Run] Would have deleted a total of {total_docs:,} documents across {len(COLLECTIONS)} collections.")
        client.close()
        return

    # Ask for confirmation if not bypassed via --yes
    if not args.yes:
        confirm = input(f"\nAre you sure you want to delete ALL data from database '{db_name}'? (y/N): ")
        if confirm.strip().lower() not in ["y", "yes"]:
            print("Cancelled. No data was deleted.")
            client.close()
            return

    # Clean the collections data
    print("\nCleaning collections data...")
    for col_name in COLLECTIONS:
        if counts.get(col_name) is None:
            print(f"   ⚠️  Skipping {col_name} due to read error.")
            continue
        try:
            result = db[col_name].delete_many({})
            print(f"   - {col_name:<20}: Deleted {result.deleted_count:,} documents")
        except Exception as e:
            print(f"   - {col_name:<20}: Error deleting data — {e}")

    print("\nDB Reset Complete.")
    print("Final collection counts:")
    for col_name in COLLECTIONS:
        try:
            count = db[col_name].count_documents({})
            print(f"   - {col_name:<20}: {count:>8,} documents")
        except Exception as e:
            print(f"   - {col_name:<20}: Error reading count ({e})")

    client.close()

if __name__ == "__main__":
    main()
