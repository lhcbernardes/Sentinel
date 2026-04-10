FROM rust:1.75-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates
COPY data ./data

RUN cargo build --release --bin sentinel-rs

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash sentinel

WORKDIR /app

COPY --from=builder /app/target/release/sentinel-rs /usr/local/bin/
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/data ./data

RUN mkdir -p /app/logs /app/data && \
    chown -R sentinel:sentinel /app

USER sentinel

EXPOSE 8080 53/udp 53/tcp

ENV RUST_LOG=info
ENV SNIFFER_ENABLED=true
ENV DNS_ENABLED=false
ENV DNS_PORT=53
ENV FIREWALL_ENABLED=true
ENV INTERFACE=eth0

ENTRYPOINT ["/usr/local/bin/sentinel-rs"]