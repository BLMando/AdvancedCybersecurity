#!/bin/bash
set -e

# Update CA trust if root
if [ "$(id -u)" = '0' ]; then
    if [ -f /etc/certs/ca/ca.crt ]; then
        echo "[INFO] Copying CA certificate to trust store..."
        cp /etc/certs/ca/ca.crt /etc/pki/ca-trust/source/anchors/zta-ca.crt
        echo "[INFO] Updating CA trust..."
        update-ca-trust
    fi
    
    # Ensure data directory is writable by mongod
    chown -R mongod:mongod /data/db
    
    # Ensure audit log directory is writable by mongod
    mkdir -p /var/log/mongodb
    chown -R mongod:mongod /var/log/mongodb
    
    # Execute the command as the mongod user
    echo "[INFO] Starting mongod as mongod user..."
    exec runuser -u mongod -- "$@"
else
    # We are not root, just exec the command directly
    exec "$@"
fi
