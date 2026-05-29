#!/usr/bin/env python3
"""
mongo_proxy_cli.py — ZTA-aware MongoDB Proxy CLI

Invia query MongoDB attraverso Envoy (mTLS) caricando i certificati
dal TPM/Secure Enclave tramite ZTA Agent (localhost:9090).
Gestisce i diversi utenti/ruoli MongoDB in base al CN del certificato.

Architettura:
    Python CLI → [mTLS con cert da Secure Enclave] → Envoy :10000 → OPA → MongoDB

Utenti e ruoli supportati (da HEALTHCARE_DB.md):
    CN                 | Ruolo OPA      | MongoDB user
    -------------------|----------------|------------------
    mario.rossi        | doctor         | zta_doctor
    anna.verdi         | billing_staff  | zta_billing
    giulia.bianchi     | auditor        | zta_auditor
    luca.ferrari       | receptionist   | zta_receptionist
    admin              | admin          | zta_admin (root)

Usage:
    # Query su una collection (role-based access via OPA + MongoDB RBAC)
    python scripts/mongo_proxy_cli.py --cn mario.rossi query --collection clinical_records --filter '{"medical_condition": "Cancer"}' --limit 5

    # Whoami: mostra identità corrente e ruolo
    python scripts/mongo_proxy_cli.py --cn mario.rossi whoami

    # Status: verifica connettività mTLS verso Envoy
    python scripts/mongo_proxy_cli.py --cn mario.rossi status

    # Insert
    python scripts/mongo_proxy_cli.py --cn admin insert --collection providers --doc '{"name": "Dr. Test", "type": "doctor"}'

    # Modalità interattiva REPL
    python scripts/mongo_proxy_cli.py --cn mario.rossi repl
"""

import argparse
import base64
import json
import os
import platform
import shutil
import ssl
import sys
import tempfile
import textwrap
import time
import urllib.request
from pathlib import Path
from typing import Optional

try:
    import pymongo
    from pymongo import MongoClient
    from bson import json_util
except ImportError:
    print("[!] pymongo non installato. Esegui: uv add pymongo")
    sys.exit(1)

# ─── Configurazione default ──────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Envoy mTLS endpoint (MongoDB wire protocol)
ENVOY_HOST = os.environ.get("ZTA_ENVOY_HOST", "localhost")
ENVOY_PORT = int(os.environ.get("ZTA_ENVOY_PORT", "10000"))

# ZTA Agent (Swift app su macOS, espone HTTP :9090)
ZTA_AGENT_URL = os.environ.get("ZTA_AGENT_URL", "http://localhost:9090")

# PKI server (per challenge/verify)
PKI_URL = os.environ.get("ZTA_PKI_URL", "http://127.0.0.1:8080")

# CA per verificare il server Envoy
CA_CERT = (
    Path(os.environ.get("ZTA_CA_CERT", ""))
    if os.environ.get("ZTA_CA_CERT")
    else PROJECT_ROOT / "volumes" / "certs" / "ca" / "ca.crt"
)

# Fallback: directory con cert già presenti su disco (mattia.mandorlini o simili)
CERT_DIR = PROJECT_ROOT / "volumes" / "certs" / "client"

# Database MongoDB
MONGO_DB = os.environ.get("ZTA_MONGO_DB", "zta_db")

# ─── Mappa CN → MongoDB credentials ─────────────────────────────────────────

# La password di ogni utente ZTA è definita in init-healthcare.py
# Questi sono gli utenti creati dallo script di inizializzazione.
# Helper to retrieve user role dynamically from client certificate on disk
def get_user_role(cn: str) -> str:
    """Legge il ruolo direttamente dal certificato client dell'utente."""
    cert_path = CERT_DIR / f"{cn}.crt"
    if not cert_path.exists():
        # Fallback per CN speciali senza cert emesso
        if cn == "admin" or cn == "mattia.mandorlini":
            return "admin"
        return "unknown"
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        titles = cert.subject.get_attributes_for_oid(x509.NameOID.TITLE)
        if titles:
            return titles[0].value
    except Exception:
        pass
    return "unknown"

# Collezioni disponibili nel DB healthcare
COLLECTIONS = ["patients", "providers", "admissions", "clinical_records", "billing"]

# ─── Colori CLI ──────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
GREY   = "\033[90m"

def ok(msg):  print(f"{GREEN}[✓]{RESET} {msg}")
def err(msg): print(f"{RED}[✗]{RESET} {msg}")
def info(msg): print(f"{CYAN}[*]{RESET} {msg}")
def warn(msg): print(f"{YELLOW}[!]{RESET} {msg}")
def sep():    print(f"{GREY}{'─' * 70}{RESET}")


# ─── Gestione certificati (TPM / Secure Enclave via ZTA Agent) ───────────────

class CertBundle:
    """Coppia (cert PEM, key PEM) estratta dal Secure Enclave o da file."""

    def __init__(self, cert_path: str, key_path: Optional[str], source: str):
        self.cert_path = cert_path  # path temporaneo o fisso su disco
        self.key_path = key_path    # None se non disponibile
        self.source = source
        self._tmpdir = None

    @classmethod
    def from_file(cls, cn: str) -> "CertBundle":
        """
        Fallback: carica il cert dal disco (certs/client/).
        Nota: questa modalità non usa il TPM — valida solo in lab.
        """
        # Cerca cert corrispondente al CN
        candidates = list(CERT_DIR.glob(f"{cn}.crt")) + list(CERT_DIR.glob(f"{cn}.pem"))
        # Fallback generico: prende il primo .crt disponibile
        if not candidates:
            candidates = list(CERT_DIR.glob("*.crt"))

        if not candidates:
            raise FileNotFoundError(
                f"Nessun certificato trovato in {CERT_DIR} per CN={cn}"
            )

        cert_path = str(candidates[0])
        # Cerca la chiave privata corrispondente
        key_path_candidate = Path(cert_path).with_suffix(".key")
        key_path = str(key_path_candidate) if key_path_candidate.exists() else None

        warn(f"Modalità FALLBACK: cert da disco ({Path(cert_path).name}), non da Secure Enclave")
        return cls(cert_path=cert_path, key_path=key_path, source="file")

    @classmethod
    def from_zta_agent(cls, cn: str) -> "CertBundle":
        """
        Estrae il certificato PEM dal ZTA Agent (Secure Enclave / Keychain).

        Il ZTA Agent (Swift app su :9090) espone:
          POST /cert  → { "common_name": "..." }
          Risposta:   { "cert_pem": "...", "key_available": true }

        La chiave privata rimane nel Secure Enclave: non viene mai esportata.
        L'agent restituisce solo il cert pubblico PEM; la firma avviene
        internamente via SecIdentity/URLCredential.
        Per pymongo, usiamo il cert PEM su disco + SSLContext con la chiave
        temporanea firmata dall'agent (se disponibile), altrimenti solo cert.
        """
        info(f"Contatto ZTA Agent per il certificato di {cn}...")
        payload = json.dumps({"common_name": cn}).encode()
        req = urllib.request.Request(
            f"{ZTA_AGENT_URL}/cert",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"ZTA Agent non raggiungibile su {ZTA_AGENT_URL}: {e}\n"
                "Assicurati che l'app ZTAAgent (Xcode) sia in esecuzione."
            )

        cert_pem = data.get("cert_pem", "")
        if not cert_pem:
            raise ValueError(f"ZTA Agent non ha restituito un cert PEM per {cn}")

        # Scrivi il cert in un file temporaneo
        tmpdir = tempfile.mkdtemp(prefix="zta_")
        cert_path = os.path.join(tmpdir, f"{cn}.crt")
        with open(cert_path, "w") as f:
            f.write(cert_pem)

        bundle = cls(cert_path=cert_path, key_path=None, source="secure_enclave")
        bundle._tmpdir = tmpdir
        ok(f"Certificato estratto dal Secure Enclave ({cn})")
        return bundle

    def cleanup(self):
        if self._tmpdir and os.path.exists(self._tmpdir):
            shutil.rmtree(self._tmpdir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.cleanup()


def get_cert_bundle(cn: str, force_file: bool = False) -> CertBundle:
    """
    Prova prima il ZTA Agent (Secure Enclave), poi fallback su file.
    Su macOS tenta sempre l'agent; su altri OS usa direttamente il file.
    """
    if force_file:
        return CertBundle.from_file(cn)

    if platform.system() in ("Darwin", "Windows"):
        try:
            return CertBundle.from_zta_agent(cn)
        except Exception as e:
            warn(f"ZTA Agent non disponibile ({e})")
            warn("Fallback su certificato da file...")
            return CertBundle.from_file(cn)
    else:
        return CertBundle.from_file(cn)


# ─── Connessione MongoDB via Envoy mTLS ──────────────────────────────────────

def build_mongo_client(cn: str, bundle: CertBundle, insecure: bool = False) -> MongoClient:
    """
    Costruisce un MongoClient che si connette a Envoy via mTLS.
    Utilizza l'autenticazione X.509 delegata senza password.
    """
    import urllib.parse
    ENVOY_SUBJECT_DN = "CN=envoy,O=AdvancedCybersecurity-Clients,C=IT"
    encoded_subject = urllib.parse.quote_plus(ENVOY_SUBJECT_DN)
    role = get_user_role(cn)

    info(f"Connessione a Envoy {ENVOY_HOST}:{ENVOY_PORT} (ruolo: {role})")

    # Configurazione TLS
    tls_params: dict = {
        "tls": True,
        "tlsCAFile": str(CA_CERT) if CA_CERT.exists() else None,
        "tlsAllowInvalidCertificates": insecure or not CA_CERT.exists(),
        "tlsAllowInvalidHostnames": True,
    }

    # Se abbiamo anche la chiave privata, usa mTLS completo
    if bundle.key_path:
        combined_pem = os.path.join(
            os.path.dirname(bundle.cert_path), f"{cn}_combined.pem"
        )
        with open(combined_pem, "w") as out:
            with open(bundle.cert_path) as c:
                out.write(c.read())
            with open(bundle.key_path) as k:
                out.write(k.read())
        tls_params["tlsCertificateKeyFile"] = combined_pem
        ok("mTLS completo: cert + chiave privata")
    elif bundle.cert_path:
        tls_params["tlsCertificateKeyFile"] = bundle.cert_path
    else:
        warn("Nessun certificato client: connessione TLS semplice")

    # Rimuovi None values
    tls_params = {k: v for k, v in tls_params.items() if v is not None}

    uri = (
        f"mongodb://{encoded_subject}@{ENVOY_HOST}:{ENVOY_PORT}/{MONGO_DB}"
        f"?authMechanism=MONGODB-X509&authSource=%24external&directConnection=true"
    )

    client = MongoClient(uri, serverSelectionTimeoutMS=5000, **tls_params)
    mongo_info = {
        "user": ENVOY_SUBJECT_DN,
        "role": role
    }
    return client, mongo_info


def is_agent_running() -> bool:
    """Verifica se il ZTA Agent è in ascolto sulla porta 9090."""
    import socket
    try:
        with socket.create_connection(("localhost", 9090), timeout=0.5):
            return True
    except OSError:
        return False


class ZTAProxySession:
    """Gestisce il ciclo di vita del tunnel locale delegato al ZTA Agent."""

    def __init__(self, cn: str, ttl: int = 900):
        self.cn = cn
        self.ttl = ttl
        self.port = None
        self.token = None

    def __enter__(self):
        info(f"Contatto ZTA Agent per avviare il tunnel MongoDB per {self.cn}...")
        payload = json.dumps({"common_name": self.cn, "ttl_seconds": self.ttl}).encode()
        req = urllib.request.Request(
            f"{ZTA_AGENT_URL}/proxy/start",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                if data.get("status") == "success" or "port" in data:
                    self.port = data["port"]
                    self.token = data["session_token"]
                    ok(f"Tunnel ZTA avviato su localhost:{self.port} (Token: {self.token})")
                    return self
                else:
                    raise ValueError(data.get("message", "Errore sconosciuto avvio proxy"))
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"ZTA Agent non raggiungibile su {ZTA_AGENT_URL}: {e}\n"
                "Assicurati che l'agente ZTA sia attivo."
            )

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.token:
            info(f"Chiusura del tunnel ZTA ({self.token})...")
            payload = json.dumps({"session_token": self.token}).encode()
            req = urllib.request.Request(
                f"{ZTA_AGENT_URL}/proxy/stop",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    pass
            except Exception as e:
                warn(f"Errore arresto tunnel: {e}")


class ZTAMongoConnection:
    """Context manager unificato per la connessione MongoDB ZTA."""

    def __init__(self, cn: str, args):
        self.cn = cn
        self.args = args
        self.proxy_session = None
        self.bundle = None
        self.client = None
        self.agent_process = None

    def __enter__(self):
        # Utilizza il proxy agent se siamo su macOS o Windows e non forziamo file
        use_agent_proxy = (platform.system() in ("Darwin", "Windows") and not self.args.file)

        if use_agent_proxy:
            # Se l'agente non è in esecuzione ed è Windows, proviamo ad avviarlo on-demand
            if not is_agent_running() and platform.system() == "Windows":
                tpm_service_path = PROJECT_ROOT / "scripts" / "windows" / "tpm_agent_service.ps1"
                if tpm_service_path.exists():
                    info("ZTA Agent non attivo. Avvio automatico tpm_agent_service.ps1 in background...")
                    import subprocess
                    cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", str(tpm_service_path)]
                    try:
                        self.agent_process = subprocess.Popen(
                            cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
                        )
                        # Attendi che il server HTTP locale diventi pronto
                        for _ in range(15):
                            time.sleep(0.3)
                            if is_agent_running():
                                ok("ZTA Agent Windows avviato con successo.")
                                break
                    except Exception as e:
                        warn(f"Impossibile avviare automaticamente l'agente Windows: {e}")

            try:
                self.proxy_session = ZTAProxySession(self.cn)
                self.proxy_session.__enter__()

                import urllib.parse
                ENVOY_SUBJECT_DN = "CN=envoy,O=AdvancedCybersecurity-Clients,C=IT"
                encoded_subject = urllib.parse.quote_plus(ENVOY_SUBJECT_DN)
                role = get_user_role(self.cn)

                info(f"Connessione al tunnel locale localhost:{self.proxy_session.port} (ruolo: {role})...")

                uri = (
                    f"mongodb://{encoded_subject}@localhost:{self.proxy_session.port}/{MONGO_DB}"
                    f"?authMechanism=MONGODB-X509&authSource=%24external&directConnection=true"
                )
                self.client = MongoClient(uri, serverSelectionTimeoutMS=8000)
                mongo_info = {
                    "user": ENVOY_SUBJECT_DN,
                    "role": role
                }
                return self.client, mongo_info
            except Exception as e:
                warn(f"Errore connessione tramite ZTA Agent ({e}). Fallback su connessione diretta con file...")
                self.proxy_session = None

        # Fallback a connessione diretta mTLS (es. Linux, o macOS/Windows senza agent running, o con flag --file)
        self.bundle = get_cert_bundle(self.cn, force_file=True)
        self.client, mongo_info = build_mongo_client(self.cn, self.bundle, insecure=self.args.insecure)
        return self.client, mongo_info

    def __exit__(self, exc_type, exc_val, exc_tb):
        import subprocess
        if self.client:
            self.client.close()
        if self.proxy_session:
            self.proxy_session.__exit__(exc_type, exc_val, exc_tb)
        if self.bundle:
            self.bundle.cleanup()
        if self.agent_process:
            info("Arresto automatico del servizio ZTA Agent Windows...")
            self.agent_process.terminate()
            try:
                self.agent_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.agent_process.kill()
            ok("ZTA Agent Windows arrestato.")


def get_read_collection_name(collection_name: str, cn: str) -> str:
    """
    Traduce il nome della collection fisica nella view RLS corrispondente
    in base al ruolo dell'utente (CN), per rispettare i permessi di MongoDB RBAC.
    """
    role = get_user_role(cn)

    if role == "admin":
        return collection_name

    # Mappa delle view RLS per ciascun ruolo
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

    role_views = rls_views.get(role, {})
    return role_views.get(collection_name, collection_name)


# ─── Comandi CLI ─────────────────────────────────────────────────────────────

def cmd_whoami(args, cn: str):
    """Mostra identità, ruolo e permessi."""
    role = get_user_role(cn)
    mongo_info = {"user": "CN=envoy,O=AdvancedCybersecurity-Clients,C=IT"}

    print()
    print(f"{BOLD}{'═' * 70}{RESET}")
    print(f"{BOLD} ZTA IDENTITY — {cn.upper()}{RESET}")
    print(f"{'═' * 70}")
    print(f"  CN (Common Name):   {CYAN}{cn}{RESET}")
    print(f"  Ruolo OPA:          {GREEN}{role}{RESET}")
    print(f"  Utente MongoDB:     {CYAN}{mongo_info.get('user', 'N/A')}{RESET}")
    print(f"  Enclave source:     {'Secure Enclave (ZTA Agent)' if platform.system() == 'Darwin' else 'File'}")
    print()
    print(f"  {BOLD}Visibilità collections (policy OPA + MongoDB RBAC):{RESET}")

    rls = {
        "admin":        {"patients": "CRUD", "providers": "CRUD", "admissions": "CRUD", "clinical_records": "CRUD", "billing": "CRUD"},
        "doctor":       {"patients": "R",    "providers": "R",    "admissions": "CRUD", "clinical_records": "CRUD", "billing": "—"},
        "billing_staff":{"patients": "R",    "providers": "R",    "admissions": "R",    "clinical_records": "—",    "billing": "CRUD"},
        "auditor":      {"patients": "R",    "providers": "R",    "admissions": "R",    "clinical_records": "R",    "billing": "R"},
        "receptionist": {"patients": "R+W",  "providers": "R",    "admissions": "CRUD", "clinical_records": "—",    "billing": "—"},
        "unknown":      {"patients": "—",    "providers": "—",    "admissions": "—",    "clinical_records": "—",    "billing": "—"},
    }

    perms = rls.get(role, rls["unknown"])
    for coll, perm in perms.items():
        color = GREEN if perm not in ("—",) else RED
        print(f"    {coll:<20} {color}{perm}{RESET}")

    print(f"{'═' * 70}")
    print()


def cmd_status(args, cn: str):
    """Testa la connettività mTLS verso Envoy."""
    print()
    info(f"Test connettività ZTA → Envoy {ENVOY_HOST}:{ENVOY_PORT}")
    sep()

    try:
        with ZTAMongoConnection(cn, args) as (client, mongo_info):
            db = client[MONGO_DB]
            # Ping MongoDB
            t0 = time.monotonic()
            result = client.admin.command("ping")
            latency = (time.monotonic() - t0) * 1000

            ok(f"Envoy mTLS → MongoDB: CONNECTED ({latency:.1f}ms)")
            ok(f"Utente:    {mongo_info['user']}")
            ok(f"Ruolo:     {mongo_info['role']}")
            ok(f"Database:  {MONGO_DB}")

            # Lista collection accessibili
            try:
                colls = db.list_collection_names()
                ok(f"Collections visibili: {colls}")
            except pymongo.errors.OperationFailure as e:
                warn(f"list_collections negata da MongoDB RBAC: {e.details.get('errmsg', str(e))}")
    except pymongo.errors.ServerSelectionTimeoutError as e:
        err(f"Envoy o tunnel non raggiungibile: {e}")
        err("Controlla che Docker (docker-compose up) sia attivo e ZTAAgent sia avviato")
    except pymongo.errors.OperationFailure as e:
        err(f"Autenticazione MongoDB fallita: {e}")
    except Exception as e:
        err(f"Errore connessione: {e}")

    print()


def cmd_query(args, cn: str):
    """Esegui una query find su una collection."""
    collection_name = args.collection
    limit = args.limit
    skip = args.skip
    projection = json.loads(args.projection) if args.projection else None
    sort_field = args.sort
    sort_dir = pymongo.ASCENDING if args.asc else pymongo.DESCENDING

    try:
        query_filter = json.loads(args.filter) if args.filter else {}
    except json.JSONDecodeError as e:
        err(f"Filtro JSON non valido: {e}")
        sys.exit(1)

    if collection_name not in COLLECTIONS:
        warn(f"Collection '{collection_name}' non standard. Collections disponibili: {COLLECTIONS}")

    print()
    info(f"Query: {collection_name}.find({query_filter}) limit={limit}")
    sep()

    try:
        with ZTAMongoConnection(cn, args) as (client, mongo_info):
            db = client[MONGO_DB]
            view_name = get_read_collection_name(collection_name, cn)
            if view_name != collection_name:
                info(f"RLS: Traduzione collection '{collection_name}' -> '{view_name}'")
            collection = db[view_name]

            t0 = time.monotonic()
            cursor = collection.find(query_filter, projection).limit(limit).skip(skip)
            if sort_field:
                cursor = cursor.sort(sort_field, sort_dir)

            results = list(cursor)
            latency = (time.monotonic() - t0) * 1000

            ok(f"Trovati {len(results)} documenti ({latency:.1f}ms)")
            sep()

            if args.raw:
                print(json_util.dumps(results, indent=2, ensure_ascii=False))
            else:
                _pretty_print_docs(results, collection_name)

    except pymongo.errors.OperationFailure as e:
        code = e.code
        msg = e.details.get("errmsg", str(e)) if e.details else str(e)
        err(f"MongoDB RBAC / OPA ha negato la query [code={code}]: {msg}")
        info("Il tuo ruolo non ha accesso a questa collection o comando.")
    except pymongo.errors.ServerSelectionTimeoutError as e:
        err(f"Envoy o tunnel non raggiungibile: {e}")
    except Exception as e:
        err(f"Errore: {e}")

    print()


def cmd_insert(args, cn: str):
    """Inserisce un documento in una collection."""
    collection_name = args.collection
    try:
        doc = json.loads(args.doc)
    except json.JSONDecodeError as e:
        err(f"Documento JSON non valido: {e}")
        sys.exit(1)

    print()
    info(f"Insert in: {collection_name}")
    sep()

    try:
        with ZTAMongoConnection(cn, args) as (client, mongo_info):
            db = client[MONGO_DB]
            collection = db[collection_name]

            result = collection.insert_one(doc)
            ok(f"Documento inserito con _id: {result.inserted_id}")

    except pymongo.errors.OperationFailure as e:
        msg = e.details.get("errmsg", str(e)) if e.details else str(e)
        err(f"Accesso negato [code={e.code}]: {msg}")
    except Exception as e:
        err(f"Errore: {e}")

    print()


def cmd_count(args, cn: str):
    """Conta i documenti in una collection con filtro opzionale."""
    collection_name = args.collection
    try:
        query_filter = json.loads(args.filter) if args.filter else {}
    except json.JSONDecodeError as e:
        err(f"Filtro JSON non valido: {e}")
        sys.exit(1)

    print()
    info(f"Count: {collection_name}.count_documents({query_filter})")
    sep()

    try:
        with ZTAMongoConnection(cn, args) as (client, mongo_info):
            db = client[MONGO_DB]
            view_name = get_read_collection_name(collection_name, cn)
            if view_name != collection_name:
                info(f"RLS: Traduzione collection '{collection_name}' -> '{view_name}'")
            collection = db[view_name]

            t0 = time.monotonic()
            count = collection.count_documents(query_filter)
            latency = (time.monotonic() - t0) * 1000

            ok(f"Documenti in '{collection_name}': {BOLD}{count}{RESET} ({latency:.1f}ms)")

    except pymongo.errors.OperationFailure as e:
        msg = e.details.get("errmsg", str(e)) if e.details else str(e)
        err(f"Accesso negato [code={e.code}]: {msg}")
    except Exception as e:
        err(f"Errore: {e}")

    print()


def cmd_aggregate(args, cn: str):
    """Esegui una pipeline di aggregazione."""
    collection_name = args.collection
    try:
        pipeline = json.loads(args.pipeline)
    except json.JSONDecodeError as e:
        err(f"Pipeline JSON non valida: {e}")
        sys.exit(1)

    print()
    info(f"Aggregate: {collection_name}")
    sep()

    try:
        with ZTAMongoConnection(cn, args) as (client, mongo_info):
            db = client[MONGO_DB]
            view_name = get_read_collection_name(collection_name, cn)
            if view_name != collection_name:
                info(f"RLS: Traduzione collection '{collection_name}' -> '{view_name}'")
            collection = db[view_name]

            t0 = time.monotonic()
            results = list(collection.aggregate(pipeline))
            latency = (time.monotonic() - t0) * 1000

            ok(f"Risultati aggregazione: {len(results)} ({latency:.1f}ms)")
            sep()
            print(json_util.dumps(results, indent=2, ensure_ascii=False))

    except pymongo.errors.OperationFailure as e:
        msg = e.details.get("errmsg", str(e)) if e.details else str(e)
        err(f"Accesso negato [code={e.code}]: {msg}")
    except Exception as e:
        err(f"Errore: {e}")

    print()


def cmd_repl(args, cn: str):
    """REPL interattivo per eseguire query MongoDB."""
    role = get_user_role(cn)

    print()
    print(f"{BOLD}{'═' * 70}{RESET}")
    print(f"{BOLD} ZTA MongoDB REPL — {cn} ({role}){RESET}")
    print(f"{'═' * 70}")
    print(f"  Comandi disponibili:")
    print(f"    find <collection> [filtro_json] [limit]")
    print(f"    count <collection> [filtro_json]")
    print(f"    aggregate <collection> <pipeline_json>")
    print(f"    collections")
    print(f"    whoami")
    print(f"    exit / quit")
    print(f"{'═' * 70}")

    try:
        with ZTAMongoConnection(cn, args) as (client, mongo_info):
            db = client[MONGO_DB]
            ok(f"Connesso a Envoy mTLS → MongoDB ({MONGO_DB})")
            print()

            while True:
                try:
                    line = input(f"{CYAN}zta:{role}>{RESET} ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\nUscita.")
                    break

                if not line:
                    continue

                parts = line.split(None, 3)
                cmd = parts[0].lower()

                if cmd in ("exit", "quit"):
                    break

                elif cmd == "whoami":
                    print(f"  CN: {cn}, Ruolo: {role}, User: {mongo_info.get('user')}")

                elif cmd == "collections":
                    try:
                        colls = db.list_collection_names()
                        ok(f"Collections: {colls}")
                    except Exception as e:
                        err(str(e))

                elif cmd == "find":
                    if len(parts) < 2:
                        warn("Uso: find <collection> [filtro_json] [limit]")
                        continue
                    coll_name = parts[1]
                    filt = json.loads(parts[2]) if len(parts) > 2 else {}
                    lim = int(parts[3]) if len(parts) > 3 else 10
                    try:
                        view_name = get_read_collection_name(coll_name, cn)
                        if view_name != coll_name:
                            info(f"RLS: Traduzione collection '{coll_name}' -> '{view_name}'")
                        results = list(db[view_name].find(filt).limit(lim))
                        ok(f"{len(results)} documenti")
                        _pretty_print_docs(results, coll_name)
                    except pymongo.errors.OperationFailure as e:
                        msg = e.details.get("errmsg", str(e)) if e.details else str(e)
                        err(f"Accesso negato: {msg}")
                    except Exception as e:
                        err(str(e))

                elif cmd == "count":
                    if len(parts) < 2:
                        warn("Uso: count <collection> [filtro_json]")
                        continue
                    coll_name = parts[1]
                    filt = json.loads(parts[2]) if len(parts) > 2 else {}
                    try:
                        view_name = get_read_collection_name(coll_name, cn)
                        if view_name != coll_name:
                            info(f"RLS: Traduzione collection '{coll_name}' -> '{view_name}'")
                        count = db[view_name].count_documents(filt)
                        ok(f"Documenti in '{coll_name}': {count}")
                    except pymongo.errors.OperationFailure as e:
                        msg = e.details.get("errmsg", str(e)) if e.details else str(e)
                        err(f"Accesso negato: {msg}")
                    except Exception as e:
                        err(str(e))

                elif cmd == "aggregate":
                    if len(parts) < 3:
                        warn("Uso: aggregate <collection> <pipeline_json>")
                        continue
                    coll_name = parts[1]
                    try:
                        view_name = get_read_collection_name(coll_name, cn)
                        if view_name != coll_name:
                            info(f"RLS: Traduzione collection '{coll_name}' -> '{view_name}'")
                        pipeline = json.loads(parts[2])
                        results = list(db[view_name].aggregate(pipeline))
                        ok(f"{len(results)} risultati")
                        print(json_util.dumps(results, indent=2, ensure_ascii=False))
                    except pymongo.errors.OperationFailure as e:
                        msg = e.details.get("errmsg", str(e)) if e.details else str(e)
                        err(f"Accesso negato: {msg}")
                    except Exception as e:
                        err(str(e))

                else:
                    warn(f"Comando sconosciuto: {cmd}")

    except pymongo.errors.ServerSelectionTimeoutError as e:
        err(f"Envoy o tunnel non raggiungibile: {e}")
    except pymongo.errors.OperationFailure as e:
        err(f"Autenticazione fallita: {e}")
    except Exception as e:
        err(f"Errore connessione: {e}")

    print()


# ─── Pretty printer ──────────────────────────────────────────────────────────

def _pretty_print_docs(docs: list, collection_name: str):
    """Stampa i documenti in formato leggibile."""
    if not docs:
        warn("Nessun documento trovato.")
        return

    # Campi sensibili da evidenziare per collection
    sensitive_fields = {
        "patients": ["full_name", "blood_type", "age", "gender"],
        "clinical_records": ["medical_condition", "medication", "test_results"],
        "billing": ["billing_amount", "insurance_provider"],
    }
    highlight = sensitive_fields.get(collection_name, [])

    for i, doc in enumerate(docs, 1):
        print(f"\n{GREY}  ── [{i}] ────────────────────────────────────{RESET}")
        for k, v in doc.items():
            if k == "_id":
                print(f"  {GREY}{k:<22}{RESET} {GREY}{v}{RESET}")
            elif k in highlight:
                print(f"  {YELLOW}{k:<22}{RESET} {v}")
            else:
                print(f"  {k:<22} {v}")


# ─── Main / argparse ─────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mongo_proxy_cli",
        description=textwrap.dedent("""\
            ZTA-aware MongoDB Proxy CLI
            Connette a MongoDB attraverso Envoy mTLS usando certificati
            dal TPM/Secure Enclave (via ZTA Agent) o da file (fallback lab).
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Esempi:
              # Verifica identità e permessi
              python scripts/mongo_proxy_cli.py --cn mario.rossi whoami

              # Test connettività mTLS
              python scripts/mongo_proxy_cli.py --cn mario.rossi status

              # Query clinical_records come medico
              python scripts/mongo_proxy_cli.py --cn mario.rossi query \\
                  --collection clinical_records --limit 5

              # Query con filtro JSON
              python scripts/mongo_proxy_cli.py --cn mario.rossi query \\
                  --collection patients --filter '{"age": {"$gt": 60}}' --limit 10

              # Insert (solo ruoli con write access)
              python scripts/mongo_proxy_cli.py --cn admin insert \\
                  --collection providers --doc '{"name": "Dr. Test", "type": "doctor"}'

              # Count documenti
              python scripts/mongo_proxy_cli.py --cn giulia.bianchi count \\
                  --collection billing

              # Aggregazione
              python scripts/mongo_proxy_cli.py --cn anna.verdi aggregate \\
                  --collection billing \\
                  --pipeline '[{"$group": {"_id": "$insurance_provider", "total": {"$sum": "$billing_amount"}}}]'

              # REPL interattivo
              python scripts/mongo_proxy_cli.py --cn mario.rossi repl

              # Forzare fallback su cert da file (senza ZTA Agent)
              python scripts/mongo_proxy_cli.py --cn mattia.mandorlini --file status
        """),
    )

    # Opzioni globali
    parser.add_argument(
        "--cn", default="mario.rossi",
        help="Common Name dell'identità ZTA (default: mario.rossi)"
    )
    parser.add_argument(
        "--envoy-host", default=ENVOY_HOST,
        help=f"Host Envoy mTLS (default: {ENVOY_HOST})"
    )
    parser.add_argument(
        "--envoy-port", type=int, default=ENVOY_PORT,
        help=f"Porta Envoy mTLS (default: {ENVOY_PORT})"
    )
    parser.add_argument(
        "--db", default=MONGO_DB,
        help=f"Database MongoDB (default: {MONGO_DB})"
    )
    parser.add_argument(
        "--insecure", action="store_true",
        help="Disabilita verifica TLS del server (lab only)"
    )
    parser.add_argument(
        "--file", action="store_true",
        help="Forza caricamento cert da file (bypassa ZTA Agent)"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # whoami
    subparsers.add_parser("whoami", help="Mostra identità, ruolo e permessi")

    # status
    subparsers.add_parser("status", help="Testa connettività mTLS verso Envoy+MongoDB")

    # query
    qp = subparsers.add_parser("query", help="Esegui find su una collection")
    qp.add_argument("--collection", "-c", required=True, choices=COLLECTIONS,
                    help="Nome della collection")
    qp.add_argument("--filter", "-f", default=None,
                    help="Filtro JSON (default: {})")
    qp.add_argument("--projection", "-p", default=None,
                    help="Proiezione JSON (campi da includere/escludere)")
    qp.add_argument("--limit", "-l", type=int, default=10,
                    help="Numero massimo di documenti (default: 10)")
    qp.add_argument("--skip", type=int, default=0,
                    help="Documenti da saltare (default: 0)")
    qp.add_argument("--sort", "-s", default=None,
                    help="Campo di ordinamento")
    qp.add_argument("--asc", action="store_true",
                    help="Ordinamento ascendente (default: discendente)")
    qp.add_argument("--raw", action="store_true",
                    help="Output JSON raw invece di pretty print")

    # insert
    ip = subparsers.add_parser("insert", help="Inserisci un documento")
    ip.add_argument("--collection", "-c", required=True, choices=COLLECTIONS,
                    help="Nome della collection")
    ip.add_argument("--doc", "-d", required=True,
                    help="Documento JSON da inserire")

    # count
    cp = subparsers.add_parser("count", help="Conta documenti in una collection")
    cp.add_argument("--collection", "-c", required=True, choices=COLLECTIONS,
                    help="Nome della collection")
    cp.add_argument("--filter", "-f", default=None,
                    help="Filtro JSON (default: {})")

    # aggregate
    ap = subparsers.add_parser("aggregate", help="Esegui una pipeline di aggregazione")
    ap.add_argument("--collection", "-c", required=True, choices=COLLECTIONS,
                    help="Nome della collection")
    ap.add_argument("--pipeline", required=True,
                    help="Pipeline JSON (array di stage)")

    # repl
    subparsers.add_parser("repl", help="REPL interattivo MongoDB")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Aggiorna variabili globali da args
    global ENVOY_HOST, ENVOY_PORT, MONGO_DB
    ENVOY_HOST = args.envoy_host
    ENVOY_PORT = args.envoy_port
    MONGO_DB = args.db

    cn = args.cn

    # Banner
    print()
    print(f"{BOLD}{'═' * 70}{RESET}")
    print(f"{BOLD} ZTA MongoDB Proxy CLI  •  CN: {cn}{RESET}")
    print(f"{'═' * 70}{RESET}")

    dispatch = {
        "whoami":    cmd_whoami,
        "status":    cmd_status,
        "query":     cmd_query,
        "insert":    cmd_insert,
        "count":     cmd_count,
        "aggregate": cmd_aggregate,
        "repl":      cmd_repl,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args, cn)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
