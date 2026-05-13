# Multi-stage Dockerfile for xiraNET v3.0.0
# Pinned base images for reproducibility. Update digests via `docker pull` then `docker inspect`.
FROM rust:1.88-bookworm AS builder

WORKDIR /app

# Sistem bağımlılıkları
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependency cache layer — workspace crates dahil
COPY Cargo.toml Cargo.lock* ./
COPY crates/ crates/
# Geçici binary stub'u: src/main.rs ve src/lib.rs için thin placeholder
RUN mkdir -p src \
    && echo "fn main(){}" > src/main.rs \
    && echo "" > src/lib.rs \
    && cargo build --release --bin xiranet 2>/dev/null || true \
    && rm -rf src

# Asıl kaynak kodu kopyala ve derle (workspace member'lar değişmediyse cache hit)
COPY src/ src/
RUN cargo build --release --bin xiranet

# Runtime image — minimal, non-root
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    # Non-root user
    && groupadd --system --gid 10001 xira \
    && useradd  --system --uid 10001 --gid xira --home-dir /app --shell /usr/sbin/nologin xira

WORKDIR /app

COPY --from=builder /app/target/release/xiranet /usr/local/bin/xiranet
COPY xiranet.toml /app/xiranet.toml

# Data ve log dizinleri — non-root user'a chown
RUN mkdir -p /app/data /app/logs /app/plugins /app/certs \
    && chown -R xira:xira /app

USER xira

EXPOSE 9000 9001

ENV RUST_LOG=info
ENV XIRA_DB_PATH=/app/data/xiranet.db

# Healthcheck — uses /health (public, no auth required)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9000/health || exit 1

ENTRYPOINT ["xiranet"]
CMD ["serve", "--config", "/app/xiranet.toml"]
