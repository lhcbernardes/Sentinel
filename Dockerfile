# Estágio de construção (Builder)
FROM rust:1.75-bookworm AS builder

WORKDIR /app

# Instalar dependências do sistema para o build
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Truque para cachear dependências: 
# Copiar apenas os manifestos e buildar as dependências primeiro
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() { fn _start() {} }" > src/lib.rs && \
    cargo build --release && \
    rm -rf src/

# Agora copiar o código real e fazer o build final
COPY src ./src
COPY templates ./templates
RUN touch src/main.rs src/lib.rs && \
    cargo build --release --bin sentinel-rs

# Estágio de execução (Runtime)
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    ca-certificates \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash sentinel

WORKDIR /app

# Copiar binário e templates
COPY --from=builder /app/target/release/sentinel-rs /usr/local/bin/
COPY --from=builder /app/templates ./templates

# Configurar permissões e diretórios
RUN mkdir -p /app/logs /app/data && \
    chown -R sentinel:sentinel /app && \
    setcap 'cap_net_raw,cap_net_admin=eip' /usr/local/bin/sentinel-rs

USER sentinel

EXPOSE 8080 53/udp 53/tcp

ENV RUST_LOG=info
ENV SNIFFER_ENABLED=true
ENV DNS_ENABLED=false
ENV DNS_PORT=53
ENV FIREWALL_ENABLED=true
ENV INTERFACE=eth0

ENTRYPOINT ["/usr/local/bin/sentinel-rs"]