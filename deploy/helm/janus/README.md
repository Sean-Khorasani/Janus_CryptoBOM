This Helm chart deploys Janus CryptoBOM on Kubernetes.

## Quick Start

### Prerequisites
- Kubernetes 1.19+
- Helm 3.2+
- PV provisioner for persistent storage (if using bundled PostgreSQL)

### Linux Validation

Run the chart validation from the repository root:

```bash
./scripts/verify-helm-linux.sh
```

The script always checks Linux runtime, volume, port, and configuration
invariants. When Helm is installed, it also runs `helm lint` and renders the
default, agent-disabled, ephemeral-PostgreSQL, and external-database variants.

### Installing the Chart

```bash
# Add the Helm repository (if available) or install from local path
helm install janus ./deploy/helm/janus

# For a production deployment with custom values:
helm install janus ./deploy/helm/janus -f my-values.yaml
```

### Configuration

The following table lists common configurable parameters:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of server replicas | `1` |
| `image.repository` | Server image repository | `janus-cbom/server` |
| `image.tag` | Server image tag | `0.1.0` |
| `image.agent.repository` | Agent image repository | `janus-cbom/agent` |
| `image.agent.tag` | Agent image tag | `0.1.0` |
| `server.port` | HTTP API port | `8080` |
| `server.grpcPort` | gRPC telemetry port | `9443` |
| `server.logLevel` | Log level (debug/info/warn/error) | `info` |
| `server.disableAuth` | Disable authentication (dev only) | `false` |
| `postgresql.enabled` | Deploy bundled PostgreSQL | `true` |
| `postgresql.persistence.enabled` | Persist bundled PostgreSQL data | `true` |
| `postgresql.persistence.size` | PostgreSQL volume size | `10Gi` |
| `ingress.enabled` | Enable ingress | `false` |

The server root filesystem remains read-only. Writable temporary files and
runtime policy updates use pod-local `emptyDir` volumes. Agent state is also
pod-local; redeploying or rescheduling an agent recreates its local state.

### Using External PostgreSQL

When using an external PostgreSQL instance:

```yaml
postgresql:
  enabled: false

externalDatabase:
  host: my-postgres.example.com
  port: 5432
  database: janus
  username: janus
  password: secure-password
  sslmode: require
```

### Secrets

For production, create a Kubernetes secret named `janus-cryptobom-secrets`:

```yaml
secrets:
  commandSigningKey: "<32-byte-hex-key>"
  jwtSecret: "<your-jwt-secret>"
```

Or override via `--set`:

```bash
helm install janus ./deploy/helm/janus \
  --set secrets.commandSigningKey="<hex-key>" \
  --set secrets.jwtSecret="<jwt-secret>"
```

### Uninstalling

```bash
helm uninstall janus
```

This will NOT delete PVCs by default. To delete PVCs:

```bash
kubectl delete pvc -l app.kubernetes.io/instance=janus
```
