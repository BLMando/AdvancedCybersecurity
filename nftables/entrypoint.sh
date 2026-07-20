#!/bin/sh
set -e

apk add --no-cache nftables inotify-tools

# Create log directory
mkdir -p /var/log/nftables

# Apply nftables rules in Envoy namespace
if [ "${APPLY_NFT_RULES:-0}" = "1" ]; then
  tr -d '\r' < /etc/nftables.conf > /tmp/nftables.conf
  if nft -f /tmp/nftables.conf; then
    echo "[nftables] Rules applied to Envoy namespace"
    nft list ruleset
  else
    echo "[nftables] ERROR: Rules failed to apply"
  fi
else
  echo "[nftables] Safe mode: rules NOT applied (set APPLY_NFT_RULES=1)"
fi

# Capture logs from nft counter (periodic polling)
echo "[nftables] Starting counter log capture..."
while true; do
  nft list ruleset 2>/dev/null | grep -E "counter packets [1-9]" >> /var/log/nftables/nft.log
  sleep 30
done &

# Background sync loop using inotify events for blocklist.txt
echo "[nftables] Starting blocklist sync daemon..."
BLOCKLIST_DIR="/etc/blocklist"
BLOCKLIST_FILE="$BLOCKLIST_DIR/blocklist.txt"

sync_blocklist() {
  IPs=$(grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$BLOCKLIST_FILE" 2>/dev/null | tr -d '\r')
  nft flush set inet zero_trust_fw blocklist 2>/dev/null
  if [ -n "$IPs" ]; then
    ELEMENTS=$(echo "$IPs" | paste -sd, -)
    echo "[nftables] Syncing blocklist elements: $ELEMENTS"
    nft add element inet zero_trust_fw blocklist "{ $ELEMENTS }" 2>/dev/null
  fi
}

# Initial sync
sync_blocklist

# Watch for changes and sync instantly (guarded by MD5 check to avoid infinite loops)
LAST_HASH=""
if [ -f "$BLOCKLIST_FILE" ]; then
  LAST_HASH=$(md5sum "$BLOCKLIST_FILE" 2>/dev/null | cut -d' ' -f1)
fi

inotifywait -q -m -e close_write,moved_to "$BLOCKLIST_DIR" | while read -r directory events filename; do
  if [ "$filename" = "blocklist.txt" ]; then
    CURRENT_HASH=$(md5sum "$BLOCKLIST_FILE" 2>/dev/null | cut -d' ' -f1)
    if [ "$CURRENT_HASH" != "$LAST_HASH" ]; then
      sync_blocklist
      LAST_HASH="$CURRENT_HASH"
    fi
  fi
done &

echo "[nftables] Sidecar ready (Envoy namespace)"
tail -f /dev/null
