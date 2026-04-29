## Setup
dal root folder lanciare:

docker build -f identity_pki/Dockerfile . -t identity-pki    
docker run --rm -p 8080:8080 -v "$PWD/certs/identity_pki:/data/certs" identity-pki   


# Legge MAC e CPU dal dispositivo reale
python scripts/generate_client_csr.py --cn mario --department Cardiologia

# Oppure con i valori manuali
python scripts/generate_client_csr.py --cn mario --department Cardiologia --mac "AA:BB:CC:DD:EE:FF" --cpu "Intel i7"