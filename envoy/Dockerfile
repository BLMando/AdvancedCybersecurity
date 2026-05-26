FROM envoyproxy/envoy:v1.37-latest

USER root
RUN mkdir -p /var/log/envoy && chown 101:101 /var/log/envoy
USER envoy

EXPOSE 10000 9901

CMD ["envoy", "-c", "/etc/envoy/envoy.yaml", "--service-cluster", "envoy", "--service-node", "envoy", "-l", "info"]
