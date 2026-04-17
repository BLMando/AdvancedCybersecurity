FROM envoyproxy/envoy:v1.37-latest

EXPOSE 10000 9901

CMD ["envoy", "-c", "/etc/envoy/envoy.yaml", "--service-cluster", "envoy", "--service-node", "envoy", "-l", "info"]
