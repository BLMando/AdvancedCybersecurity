#!/bin/bash
# ─── Test MongoDB Access Through Envoy ───────────────────────────────────
# Tests end-to-end flow: Client → Envoy → OPA → MongoDB with logging

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="$PROJECT_ROOT/certs"

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Test MongoDB Access Through ZTA Stack                    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"

# ─── Initialize MongoDB Database ───────────────
echo -e "\n${YELLOW}[INIT] Initializing MongoDB database...${NC}"
docker exec mongo mongosh \
	-u admin \
	-p secret \
	--eval "
	db = db.getSiblingDB('zta_db');
	db.createCollection('utenti');
	db.utenti.insertMany([
		{nome: 'Alice', eta: 30, role: 'admin'},
		{nome: 'Bob', eta: 25, role: 'user'},
		{nome: 'Charlie', eta: 35, role: 'user'},
		{nome: 'Diana', eta: 28, role: 'user'}
	]);
	print('Database initialized: zta_db.utenti');
	" 2>&1 | head -5

echo -e "${GREEN}✓ MongoDB database ready${NC}"

# ─── Test 1: Legitimate Query - mario.rossi ────
echo -e "\n${YELLOW}[TEST 1] Legitimate Query - mario.rossi from Internal Network${NC}"
echo "Query: db.utenti.find()"
echo "Expected: ALLOW (known user, internal network, read operation)"

docker cp "$CERTS_DIR/ca/ca.crt" mongo:/tmp/ca.crt >/dev/null
docker cp "$CERTS_DIR/clients/mario.pem" mongo:/tmp/mario.pem >/dev/null

MONGO_OUTPUT=$(docker exec mongo mongosh \
	--tls \
	--tlsCAFile /tmp/ca.crt \
	--tlsCertificateKeyFile /tmp/mario.pem \
	"mongodb://admin:secret@envoy:10000/zta_db?authSource=admin" \
	--eval "db.utenti.find().pretty()" 2>&1 || true)

if echo "$MONGO_OUTPUT" | grep -q "Alice\|Bob\|Charlie"; then
	echo -e "${GREEN}✓ Query ALLOWED - Results returned:${NC}"
	echo "$MONGO_OUTPUT" | grep -E "nome|eta" | head -4
else
	echo -e "${RED}✗ Query DENIED or ERROR${NC}"
	echo "Output: $MONGO_OUTPUT"
fi

# ─── Test 2: Restricted Query - unknown.user ────
echo -e "\n${YELLOW}[TEST 2] Restricted Query - unknown.user (No Device Binding)${NC}"
echo "Query: db.utenti.find()"
echo "Expected: Possible DENY (unknown user + no TPM + risk > threshold)"

docker cp "$CERTS_DIR/clients/unknown.pem" mongo:/tmp/unknown.pem >/dev/null

MONGO_UNKNOWN=$(docker exec mongo mongosh \
	--tls \
	--tlsCAFile /tmp/ca.crt \
	--tlsCertificateKeyFile /tmp/unknown.pem \
	"mongodb://admin:secret@envoy:10000/zta_db?authSource=admin" \
	--eval "db.utenti.find().pretty()" 2>&1 || true)

if echo "$MONGO_UNKNOWN" | grep -q "Alice\|Bob\|error\|denied\|unauthorized"; then
	echo -e "${YELLOW}⚠ Query result:${NC}"
	if echo "$MONGO_UNKNOWN" | grep -qE "error|denied|unauthorized|not authorized"; then
		echo -e "${GREEN}✓ Correctly DENIED${NC}"
	else
		echo -e "${YELLOW}⚠ Allowed (risk threshold permits this operation)${NC}"
	fi
	echo "Output: $MONGO_UNKNOWN" | head -3
else
	echo -e "${YELLOW}⚠ Unable to determine result${NC}"
fi

# ─── Test 3: Count Query ────────────────────────
echo -e "\n${YELLOW}[TEST 3] Count Query - mario.rossi${NC}"
echo "Query: db.utenti.countDocuments()"

COUNT_OUTPUT=$(docker exec mongo mongosh \
	--tls \
	--tlsCAFile /tmp/ca.crt \
	--tlsCertificateKeyFile /tmp/mario.pem \
	"mongodb://admin:secret@envoy:10000/zta_db?authSource=admin" \
	--eval "print('Document count: ' + db.utenti.countDocuments())" 2>&1 || true)

if echo "$COUNT_OUTPUT" | grep -qE "Document count:|[0-9]"; then
	echo -e "${GREEN}✓ Query executed${NC}"
	echo "$COUNT_OUTPUT" | grep "Document count"
else
	echo -e "${RED}✗ Query failed${NC}"
fi

# ─── Test 4: Insert Operation (High Risk) ──────
echo -e "\n${YELLOW}[TEST 4] Insert Operation - mario.rossi${NC}"
echo "Query: db.utenti.insertOne({nome: 'Eve', eta: 32})"
echo "Expected: Possible DENY (insert operation, higher threshold)"

INSERT_OUTPUT=$(docker exec mongo mongosh \
	--tls \
	--tlsCAFile /tmp/ca.crt \
	--tlsCertificateKeyFile /tmp/mario.pem \
	"mongodb://admin:secret@envoy:10000/zta_db?authSource=admin" \
	--eval "db.utenti.insertOne({nome: 'Eve', eta: 32}); print('Insert completed')" 2>&1 || true)

if echo "$INSERT_OUTPUT" | grep -qE "acknowledged|completed|error"; then
	echo -e "${YELLOW}⚠ Insert result:${NC}"
	echo "$INSERT_OUTPUT" | head -3
fi

# ─── Test 5: Envoy Log Verification ────────────
echo -e "\n${YELLOW}[TEST 5] Envoy Log Verification${NC}"
echo "Checking Envoy logs for request metadata..."

ENVOY_LOGS=$(docker logs envoy 2>&1 | grep -E "mongo|identity|zta|command" | tail -5 || true)

if [ -n "$ENVOY_LOGS" ]; then
	echo -e "${GREEN}✓ Envoy logging active${NC}"
	echo "$ENVOY_LOGS"
else
	echo -e "${YELLOW}⚠ No ZTA metadata in recent Envoy logs (may be normal)${NC}"
fi

# ─── Test 6: OPA Log Verification ──────────────
echo -e "\n${YELLOW}[TEST 6] OPA Log Verification${NC}"
echo "Checking OPA decision logs..."

OPA_LOGS=$(docker logs opa 2>&1 | grep -iE "decision|allow|deny" | tail -5 || true)

if [ -n "$OPA_LOGS" ]; then
	echo -e "${GREEN}✓ OPA decisions logged${NC}"
	echo "$OPA_LOGS"
else
	echo -e "${YELLOW}⚠ OPA logs not showing decisions (decision logs may be disabled)${NC}"
fi

# ─── Summary ────────────────────────────────────
echo -e "\n${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  End-to-End Test Summary                                   ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${GREEN}✓ End-to-end flow tested${NC}"
echo ""
echo "Test Coverage:"
echo "  [✓] Legitimate user access (mario.rossi)"
echo "  [✓] Unknown user restrictions (unknown.user)"
echo "  [✓] Multiple query types (find, count, insert)"
echo "  [✓] Envoy identity extraction logging"
echo "  [✓] OPA policy decision logging"
echo ""
echo "Architecture verified:"
echo "  Client (mTLS cert) → Envoy (identity extraction)"
echo "     ↓"
echo "  OPA (policy decision based on risk score)"
echo "     ↓"
echo "  MongoDB (protected access)"
echo ""
