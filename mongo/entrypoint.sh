#!/bin/bash
set -e

# Background initialization routine
(
    echo "[INFO] Starting background database setup..."
    
    pip3 install "pymongo<4.0" "python-dotenv" "pandas<1.2" &>/dev/null || true

    for i in {1..30}; do
        if mongosh --eval "db.runCommand({ping: 1})" --tls --tlsCAFile /etc/certs/ca/ca.crt --tlsCertificateKeyFile /etc/certs/server/mongo.pem --tlsAllowInvalidCertificates < /dev/null &>/dev/null; then
            echo "[INFO] MongoDB is up!"
            break
        fi
        sleep 2
    done

    MONGO_USER="${MONGO_ROOT_USERNAME:-zta_user}"
    MONGO_PASS="${MONGO_ROOT_PASSWORD:-zta_password}"
    MONGO_DB="${MONGO_DATABASE:-zta_db}"
    MONGO_PORT="${MONGO_PORT:-27017}"

    echo "[INFO] Checking/Creating root user '${MONGO_USER}'..."
    CREATE_USER_OUT=$(mongosh "mongodb://127.0.0.1:${MONGO_PORT}/admin?directConnection=true" --tls --tlsCAFile /etc/certs/ca/ca.crt --tlsCertificateKeyFile /etc/certs/server/mongo.pem --tlsAllowInvalidCertificates --quiet --eval 'db.createUser({user: "'"${MONGO_USER}"'", pwd: "'"${MONGO_PASS}"'", roles: [{role: "root", db: "admin"}]})' < /dev/null 2>&1 || true)
    
    if echo "$CREATE_USER_OUT" | grep -q "already exists"; then
        echo "[INFO] Root user '${MONGO_USER}' already exists."
    elif echo "$CREATE_USER_OUT" | grep -q "ok: 1"; then
        echo "[INFO] Root user '${MONGO_USER}' created successfully."
    else
        if mongosh "mongodb://${MONGO_USER}:${MONGO_PASS}@127.0.0.1:${MONGO_PORT}/admin?authSource=admin&directConnection=true" --tls --tlsCAFile /etc/certs/ca/ca.crt --tlsCertificateKeyFile /etc/certs/server/mongo.pem --tlsAllowInvalidCertificates --eval "db.runCommand({ping: 1})" < /dev/null &>/dev/null; then
            echo "[INFO] Root user '${MONGO_USER}' already exists and is working."
        else
            echo "[WARNING] Unexpected user creation result: $CREATE_USER_OUT"
        fi
    fi

    echo "[INFO] Checking if '${MONGO_DB}' database needs initialization..."
    COLLECTIONS_COUNT=$(mongosh "mongodb://${MONGO_USER}:${MONGO_PASS}@127.0.0.1:${MONGO_PORT}/${MONGO_DB}?authSource=admin&directConnection=true" --tls --tlsCAFile /etc/certs/ca/ca.crt --tlsCertificateKeyFile /etc/certs/server/mongo.pem --tlsAllowInvalidCertificates --quiet --eval 'db.getCollectionNames().length' < /dev/null 2>/dev/null || echo "0")
    
    if [ "$COLLECTIONS_COUNT" = "0" ] || [ -z "$COLLECTIONS_COUNT" ]; then
        echo "[INFO] Database is empty. Running initialization..."
                
        python3 /app/mongo/init-healthcare.py
        python3 /app/mongo/seed-db.py --csv /app/mongo/dataset/healthcare_dataset.csv
        echo "[INFO] Database initialization and seeding complete!"
    else
        echo "[INFO] Database already initialized (found $COLLECTIONS_COUNT collections)."
    fi
) &
disown

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
    
    # Ensure log directory is writable by mongod
    mkdir -p /var/log/mongodb
    chown -R mongod:mongod /var/log/mongodb
    
    # Execute the command as the mongod user
    echo "[INFO] Starting mongod as mongod user..."
    exec runuser -u mongod -- "$@"
else
    # We are not root, just exec the command directly
    exec "$@"
fi
