import os
from pymongo import MongoClient

def main():
    # Connect using admin credentials
    client = MongoClient('mongodb://admin:secret@mongo:27017/admin?tls=true&tlsCertificateKeyFile=/data/server/mongo.pem&tlsCAFile=/data/certs/ca.crt&tlsAllowInvalidCertificates=true')
    db = client['$external']
    
    users = [
        ('paolo.roselli', 'zta_doctor'),
        ('test_auditor', 'zta_auditor'),
        ('test.user', 'zta_doctor'),
        ('test.user.two', 'zta_billing')
    ]
    
    for user, role in users:
        u = f'oidc/{user}'
        try:
            db.command('dropUser', u)
        except Exception:
            pass
        db.command('createUser', u, roles=[{'role': role, 'db': 'zta_db'}])
        print(f'✓ Provisioned OIDC user: {u} with role: {role}')
        
    client.close()

if __name__ == '__main__':
    main()
