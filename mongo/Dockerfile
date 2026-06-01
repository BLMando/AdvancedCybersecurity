FROM mongodb/mongodb-community-server:8.0-ubi8

EXPOSE 27017

CMD ["mongod", "--bind_ip_all", "--tlsMode", "requireTLS", "--tlsCertificateKeyFile", "/etc/certs/server/mongo.pem", "--tlsCAFile", "/etc/certs/ca/ca.crt"]
