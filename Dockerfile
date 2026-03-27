# Multi-stage Dockerfile for xiraNET v2.1.0
FROM rust:1.82-slim-bookworm as builder

WORKDIR /app

# Sistem bağımlılıkları
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Dependency cache layer
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main(){}" > src/main.rs && echo "" > src/lib.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# Asıl kaynak kodu kopyala ve derle
COPY src/ src/
RUN cargo build --release

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/xiranet /usr/local/bin/xiranet
COPY xiranet.toml /app/xiranet.toml

# Data ve log dizinleri
RUN mkdir -p /app/data /app/logs /app/plugins /app/certs

EXPOSE 9000 9001

ENV RUST_LOG=info

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9000/xira/health -H "X-Api-Key: xira-secret-key-change-me" || exit 1

ENTRYPOINT ["xiranet"]
CMD ["serve", "--config", "/app/xiranet.toml"]
