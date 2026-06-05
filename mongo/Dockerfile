FROM mongodb/mongodb-enterprise-server:8.0-ubi8

USER root

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["mongod", "--bind_ip_all", "--tlsMode", "requireTLS", "--tlsCertificateKeyFile", "/etc/certs/server/mongo.pem", "--tlsCAFile", "/etc/certs/ca/ca.crt", "--setParameter", "authenticationMechanisms=SCRAM-SHA-256,SCRAM-SHA-1,MONGODB-X509,MONGODB-OIDC", "--setParameter", "oidcIdentityProviders=[{\"issuer\":\"https://identity-pki:8080\",\"audience\":\"mongo\",\"clientId\":\"mongo\",\"authNamePrefix\":\"oidc\",\"authorizationClaim\":\"role\"}]"]
