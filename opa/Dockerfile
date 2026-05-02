FROM openpolicyagent/opa:latest

EXPOSE 8181 9002

CMD ["run", "--server", "--addr=0.0.0.0:8181", "--set=plugins.envoy_ext_authz_grpc.addr=:9002", "--log-level=info"]
