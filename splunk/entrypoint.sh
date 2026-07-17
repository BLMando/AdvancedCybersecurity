#!/bin/bash
set -e

echo "Running pre-start HEC configuration..."

# Validate that the token is present
if [ -z "${ZTA_HEC_TOKEN}" ]; then
  echo "ERROR: ZTA_HEC_TOKEN environment variable is not set!" >&2
  exit 1
fi

echo "Generating inputs.conf for HEC..."
mkdir -p /opt/splunk/etc/apps/zta/local

cat <<EOF > /opt/splunk/etc/apps/zta/local/inputs.conf
[http]
disabled = 0
port = 8088
enableSSL = 1

[http://zta_token]
disabled = 0
token = ${ZTA_HEC_TOKEN}
index = zta_baseline_summary
indexes = zta_baseline_summary,zta_envoy,zta_mongodb,zta_mongodb_audit,zta_nftables,zta_snort
EOF

echo "Starting Splunk Service..."
exec /sbin/entrypoint.sh start-service
