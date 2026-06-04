# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.81-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev musl-tools gcc-x86-64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
# Pre-build deps only (for layer caching)
RUN mkdir src && echo "fn main(){}" > src/main.rs && cargo build --release && rm -rf src

COPY . .
RUN touch src/main.rs && cargo build --release

# ── Stage 2: Final image ───────────────────────────────────────────────────────
FROM debian:bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/janus-cbom/janus"
LABEL org.opencontainers.image.description="Janus CryptoBOM agent — post-quantum cryptographic discovery scanner"

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/janus-agent /usr/local/bin/janus-agent

# Default to scanning /scan (mount host path here)
VOLUME ["/scan", "/data"]
ENV JANUS_SCAN_ROOTS="/scan"
ENV JANUS_CACHE_PATH="/data/agent.db"

ENTRYPOINT ["/usr/local/bin/janus-agent"]
CMD ["--config", "/data/janus-agent.toml"]
