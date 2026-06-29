# Zero Trust Architecture (ZTA) - Healthcare Lab

1. **Start the Infrastructure**
```bash
docker compose up --build -d
```

2. **Configure Splunk (Log Forwarder)**
   - Access `http://localhost:8000` (credentials in `.env`).
   - Create an HEC token named **zta_token** in **Settings > Data Inputs > HTTP Event Collector** and ensure it has access to the following indexes: `zta_envoy`, `zta_snort`, `zta_nftables`, `zta_mongodb`, `zta_mongodb_audit`.
   - Update `SPLUNK_HEC_TOKEN_ENVOY` in `.env` with your token.
   - Restart the log forwarder:
```bash
docker compose up -d --force-recreate zta-log-forwarder
```

3. **Configure Client and Test**
   - Import the Root CA (`volumes/certs/ca/ca.crt`) as a trusted authority in your browser (Chrome/Firefox) or operating system.
   - Start the local ZTA Agent (port 9090):
     - **Windows**: `powershell -ExecutionPolicy Bypass -File .\scripts\windows\tpm_agent_service.ps1`
     - **macOS**: Compile and run ZTAAgent via Xcode.
   - Navigate to `http://localhost:8080`, log in (e.g., as an Auditor or Doctor), generate your certificate, and access the local proxy!