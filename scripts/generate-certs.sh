#!/bin/bash
# ─── Generate Certificates for Zero Trust Architecture ───────────────────
# Creates CA, server, and client certificates with mTLS support

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="$PROJECT_ROOT/certs"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Zero Trust Architecture - Certificate Generation          ║"
echo "╚════════════════════════════════════════════════════════════╝"

# ─── Create directory structure ─────────────────
echo "[1/6] Creating certificate directories..."
mkdir -p "$CERTS_DIR"/{ca,server,clients}

# ─── Generate Root CA ──────────────────────────
echo "[2/6] Generating Root Certificate Authority..."
openssl req -x509 -newkey rsa:4096 -days 3650 \
	-keyout "$CERTS_DIR/ca/ca.key" \
	-out "$CERTS_DIR/ca/ca.crt" \
	-subj "/CN=ZTA-RootCA/O=UniPM/C=IT" \
	-nodes \
	2>/dev/null

echo "      ✓ Root CA created: ca.crt (valid 10 years)"

# ─── Generate Envoy Server Certificate ─────────
echo "[3/6] Generating Envoy server certificate..."
openssl req -newkey rsa:2048 -nodes \
	-keyout "$CERTS_DIR/server/envoy.key" \
	-out "$CERTS_DIR/server/envoy.csr" \
	-subj "/CN=envoy/O=ZTA/C=IT" \
	2>/dev/null

openssl x509 -req -in "$CERTS_DIR/server/envoy.csr" \
	-CA "$CERTS_DIR/ca/ca.crt" \
	-CAkey "$CERTS_DIR/ca/ca.key" \
	-CAcreateserial \
	-out "$CERTS_DIR/server/envoy.crt" \
	-days 365 \
	-extfile <(printf "subjectAltName=DNS:envoy,DNS:localhost,IP:127.0.0.1") \
	2>/dev/null

echo "      ✓ Envoy certificate created"

# ─── Generate Client Certificate: mario.rossi ──
echo "[4/6] Generating client certificate: mario.rossi (with OID device binding)..."
openssl req -newkey rsa:2048 -nodes \
	-keyout "$CERTS_DIR/clients/mario.key" \
	-out "$CERTS_DIR/clients/mario.csr" \
	-subj "/CN=mario.rossi/O=ZTA/C=IT" \
	2>/dev/null

cat > /tmp/mario_ext.conf << 'EOF'
[v3_client]
subjectAltName = otherName:1.3.6.1.4.1.99999.1;UTF8:device-laptop-001
EOF

openssl x509 -req -in "$CERTS_DIR/clients/mario.csr" \
	-CA "$CERTS_DIR/ca/ca.crt" \
	-CAkey "$CERTS_DIR/ca/ca.key" \
	-CAcreateserial \
	-out "$CERTS_DIR/clients/mario.crt" \
	-days 365 \
	-extfile /tmp/mario_ext.conf \
	-extensions v3_client \
	2>/dev/null

cat "$CERTS_DIR/clients/mario.crt" "$CERTS_DIR/clients/mario.key" > "$CERTS_DIR/clients/mario.pem"
chmod 600 "$CERTS_DIR/clients/mario.pem"

echo "      ✓ Mario certificate created with device OID: 1.3.6.1.4.1.99999.1"

# ─── Generate Client Certificate: unknown.user ─
echo "[5/6] Generating client certificate: unknown.user (no OID)..."
openssl req -newkey rsa:2048 -nodes \
	-keyout "$CERTS_DIR/clients/unknown.key" \
	-out "$CERTS_DIR/clients/unknown.csr" \
	-subj "/CN=unknown.user/O=ZTA/C=IT" \
	2>/dev/null

openssl x509 -req -in "$CERTS_DIR/clients/unknown.csr" \
	-CA "$CERTS_DIR/ca/ca.crt" \
	-CAkey "$CERTS_DIR/ca/ca.key" \
	-CAcreateserial \
	-out "$CERTS_DIR/clients/unknown.crt" \
	-days 365 \
	2>/dev/null

cat "$CERTS_DIR/clients/unknown.crt" "$CERTS_DIR/clients/unknown.key" > "$CERTS_DIR/clients/unknown.pem"
chmod 600 "$CERTS_DIR/clients/unknown.pem"

echo "      ✓ Unknown user certificate created (no device binding)"

# ─── Verify certificates ───────────────────────
echo "[6/6] Verifying certificate chain..."
openssl verify -CAfile "$CERTS_DIR/ca/ca.crt" "$CERTS_DIR/server/envoy.crt" >/dev/null 2>&1 && echo "      ✓ Envoy certificate verified" || echo "      ✗ Envoy certificate verification failed"
openssl verify -CAfile "$CERTS_DIR/ca/ca.crt" "$CERTS_DIR/clients/mario.crt" >/dev/null 2>&1 && echo "      ✓ Mario certificate verified" || echo "      ✗ Mario certificate verification failed"
openssl verify -CAfile "$CERTS_DIR/ca/ca.crt" "$CERTS_DIR/clients/unknown.crt" >/dev/null 2>&1 && echo "      ✓ Unknown certificate verified" || echo "      ✗ Unknown certificate verification failed"

# ─── Display certificate info ──────────────────
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Certificate Details                                       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "MARIO.ROSSI Certificate Subject:"
openssl x509 -in "$CERTS_DIR/clients/mario.crt" -text -noout 2>/dev/null | grep -A2 "Subject:"
echo ""
echo "MARIO.ROSSI Certificate Extensions:"
openssl x509 -in "$CERTS_DIR/clients/mario.crt" -text -noout 2>/dev/null | grep -A2 "Subject Alternative Name" || echo "(Standard - no custom OID shown in text output)"

echo ""
echo "✓ All certificates generated successfully!"
echo ""
echo "Location: $CERTS_DIR/"
echo "  - ca/ca.crt              (Root CA public key)"
echo "  - ca/ca.key              (Root CA private key)"
echo "  - server/envoy.crt       (Envoy server certificate)"
echo "  - server/envoy.key       (Envoy server private key)"
echo "  - clients/mario.crt      (Mario client certificate)"
echo "  - clients/mario.key      (Mario private key)"
echo "  - clients/mario.pem      (Mario combined cert+key)"
echo "  - clients/unknown.crt    (Unknown user certificate)"
echo "  - clients/unknown.key    (Unknown user private key)"
echo "  - clients/unknown.pem    (Unknown user combined cert+key)"

# Cleanup
rm -f /tmp/mario_ext.conf
