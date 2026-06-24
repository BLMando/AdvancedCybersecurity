# Stage 1: Build the Rust Wasm filter
FROM rust:1.85-slim AS builder

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-wasip1

WORKDIR /build
COPY wasm/Cargo.toml /build/Cargo.toml
COPY wasm/src /build/src

RUN cargo build --target wasm32-wasip1 --release

# Stage 2: Final Envoy Image
FROM envoyproxy/envoy:v1.30-latest

USER root
RUN mkdir -p /var/log/envoy && chown 101:101 /var/log/envoy
RUN mkdir -p /etc/envoy/wasm

COPY --from=builder /build/target/wasm32-wasip1/release/mongo_op_msg_filter.wasm /etc/envoy/wasm/mongo_op_msg_filter.wasm
RUN chown -R 101:101 /etc/envoy/wasm

USER envoy
EXPOSE 10000 9901

CMD ["envoy", "-c", "/etc/envoy/envoy.yaml", "--service-cluster", "envoy", "--service-node", "envoy", "-l", "info", "--log-path", "/var/log/envoy/envoy.log"]
