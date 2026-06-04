# ── Stage 1: Build UI ─────────────────────────────────────────────────────────
FROM node:22-alpine AS ui-builder
WORKDIR /ui
COPY ui/package*.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

# ── Stage 2: Build Server ─────────────────────────────────────────────────────
FROM golang:1.23-alpine AS server-builder
WORKDIR /src
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -X main.version=dev" \
    -o /bin/janus-server ./cmd/...

# ── Stage 3: Final image ───────────────────────────────────────────────────────
FROM gcr.io/distroless/static:nonroot
LABEL org.opencontainers.image.source="https://github.com/janus-cbom/janus"
LABEL org.opencontainers.image.description="Janus CryptoBOM server — post-quantum cryptographic posture management"

# Copy server binary
COPY --from=server-builder /bin/janus-server /janus-server

# Copy UI dist to be served by the Go server as embedded assets (or via nginx in compose)
COPY --from=ui-builder /ui/dist /ui/dist

# Copy policies
COPY policies /policies

EXPOSE 8080 50051
ENTRYPOINT ["/janus-server"]
