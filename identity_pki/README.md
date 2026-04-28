## Setup
dal root folder lanciare:

docker build -f identity_pki/Dockerfile . -t identity-pki    
docker run --rm -p 8080:8080 -v "$PWD/certs/identity_pki:/data/certs" identity-pki   