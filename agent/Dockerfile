# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.96-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev musl-tools gcc-x86-64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
# Pre-build deps only (for layer caching)
RUN mkdir src \
    && echo "fn main(){}" > src/main.rs \
    && echo "" > src/interceptor.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY . .
RUN touch src/main.rs src/interceptor.rs && cargo build --release --locked

# ── Stage 2: Final image ───────────────────────────────────────────────────────
FROM debian:bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/janus-cbom/janus"
LABEL org.opencontainers.image.description="Janus CryptoBOM agent — post-quantum cryptographic discovery scanner"

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && groupadd --system janus \
    && useradd --system --gid janus --home-dir /nonexistent --shell /usr/sbin/nologin janus \
    && mkdir -p /data /scan \
    && chown -R janus:janus /data /scan \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/janus-agent /usr/local/bin/janus-agent
COPY --from=builder /src/config/prompts/ /etc/janus/prompts/

# Default to scanning /scan (mount host path here)
VOLUME ["/scan", "/data"]
ENV JANUS_SCAN_ROOTS="/scan"
ENV JANUS_CACHE_PATH="/data/agent.db"
ENV JANUS_HOST_UUID_PATH="/data/janus-host-id"
ENV JANUS_PROMPTS_DIR="/etc/janus/prompts"

USER janus
ENTRYPOINT ["/usr/local/bin/janus-agent"]
CMD ["--config", "/data/janus-agent.toml"]
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD test "$(readlink /proc/1/exe)" = "/usr/local/bin/janus-agent" \
    && test -s "$JANUS_HOST_UUID_PATH" \
    && test -s "$JANUS_CACHE_PATH"
