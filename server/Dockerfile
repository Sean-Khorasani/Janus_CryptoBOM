# ── Stage 1: Build UI ─────────────────────────────────────────────────────────
FROM node:22-alpine AS ui-builder
WORKDIR /ui
COPY ui/package*.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

# ── Stage 2: Build Server ─────────────────────────────────────────────────────
FROM golang:1.25-alpine AS server-builder
WORKDIR /src
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -X main.version=dev" \
    -o /bin/janus-server ./cmd/janus-server

# ── Stage 3: Final image ───────────────────────────────────────────────────────
FROM alpine:3.22
LABEL org.opencontainers.image.source="https://github.com/janus-cbom/janus"
LABEL org.opencontainers.image.description="Janus CryptoBOM server — post-quantum cryptographic posture management"

RUN apk add --no-cache ca-certificates openssl wget \
    && addgroup -S janus \
    && adduser -S -G janus janus \
    && mkdir -p /policies /ui/dist \
    && chown -R janus:janus /policies /ui

COPY --from=server-builder /bin/janus-server /janus-server

COPY --chown=janus:janus --from=ui-builder /ui/dist /ui/dist

COPY --chown=janus:janus policies /policies

ENV JANUS_UI_DIR=/ui/dist
USER janus
EXPOSE 8080 9443
ENTRYPOINT ["/janus-server"]
