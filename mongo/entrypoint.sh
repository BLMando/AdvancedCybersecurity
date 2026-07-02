#!/bin/bash
set -e

# Background initialization routine
(
    echo "Starting background database setup..."
    
    pip3 install "pymongo<4.0" "python-dotenv" "pandas<1.2" &>/dev/null || true

    for i in {1..30}; do
        if mongosh --eval "db.runCommand({ping: 1})" --tls --tlsCAFile /etc/certs/ca/ca.crt --tlsCertificateKeyFile /etc/certs/server/mongo.pem --tlsAllowInvalidCertificates < /dev/null &>/dev/null; then
            echo " *** MongoDB is up *** "
            break
        fi
        sleep 2
    done

    MONGO_USER="${MONGO_ROOT_USERNAME:-zta_user}"
    MONGO_PASS="${MONGO_ROOT_PASSWORD:-zta_password}"
    MONGO_DB="${MONGO_DATABASE:-zta_db}"

    echo "Checking/Creating root user '${MONGO_USER}'..."
    CREATE_USER_OUT=$(mongosh "mongodb://127.0.0.1:27017/admin?directConnection=true" --tls --tlsCAFile /etc/certs/ca/ca.crt --tlsCertificateKeyFile /etc/certs/server/mongo.pem --tlsAllowInvalidCertificates --quiet --eval 'db.createUser({user: "'"${MONGO_USER}"'", pwd: "'"${MONGO_PASS}"'", roles: [{role: "root", db: "admin"}]})' < /dev/null 2>&1 || true)
    
    if echo "$CREATE_USER_OUT" | grep -q "already exists"; then
        echo "Root user '${MONGO_USER}' already exists."
    elif echo "$CREATE_USER_OUT" | grep -q "ok: 1"; then
        echo "Root user '${MONGO_USER}' created successfully."
    else
        if mongosh "mongodb://${MONGO_USER}:${MONGO_PASS}@127.0.0.1:27017/admin?authSource=admin&directConnection=true" --tls --tlsCAFile /etc/certs/ca/ca.crt --tlsCertificateKeyFile /etc/certs/server/mongo.pem --tlsAllowInvalidCertificates --eval "db.runCommand({ping: 1})" < /dev/null &>/dev/null; then
            echo "Root user '${MONGO_USER}' already exists and is working."
        else
            echo "Unexpected user creation result: $CREATE_USER_OUT"
        fi
    fi

    echo "Checking if '${MONGO_DB}' database needs initialization..."
    PATIENTS_COUNT=$(mongosh "mongodb://${MONGO_USER}:${MONGO_PASS}@127.0.0.1:27017/${MONGO_DB}?authSource=admin&directConnection=true" --tls --tlsCAFile /etc/certs/ca/ca.crt --tlsCertificateKeyFile /etc/certs/server/mongo.pem --tlsAllowInvalidCertificates --quiet --eval 'try { db.patients.countDocuments() } catch(e) { 0 }' < /dev/null 2>/dev/null || echo "0")
    
    if [ "$PATIENTS_COUNT" = "0" ] || [ -z "$PATIENTS_COUNT" ] || [ "$PATIENTS_COUNT" = "null" ]; then
        echo "Database is empty or missing patient records. Running initialization..."
                
        python3 /app/mongo/init-healthcare.py
        python3 /app/mongo/seed-db.py --csv /app/mongo/dataset/healthcare_dataset.csv
        echo "Database initialization and seeding complete!"
    else
        echo "Database already initialized (found $PATIENTS_COUNT patient records)."
    fi
) &
disown

# Update CA trust if root
if [ "$(id -u)" = '0' ]; then
    if [ -f /etc/certs/ca/ca.crt ]; then
        echo "Copying CA certificate to trust store..."
        cp /etc/certs/ca/ca.crt /etc/pki/ca-trust/source/anchors/zta-ca.crt
        echo "Updating CA trust..."
        update-ca-trust
    fi
    
    # Ensure data directory is writable by mongod
    chown -R mongod:mongod /data/db
    
    # Ensure log directory is writable by mongod
    mkdir -p /var/log/mongodb
    chown -R mongod:mongod /var/log/mongodb
    
    # Execute the command as the mongod user
    echo "Starting mongod as mongod user..."
    exec runuser -u mongod -- "$@"
else
    # We are not root, just exec the command directly
    exec "$@"
fi
