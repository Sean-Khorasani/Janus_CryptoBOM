# OpenSSL Inventory Plugin (sample)

Reports the host's OpenSSL/TLS crypto capabilities — version, offered cipher suites, named
curves, and PQC KEM/signature algorithms (on OpenSSL 3.5+ or an oqs-provider build). It is
**metadata-only**: it prints capability names and versions, never keys or secrets, and is
read-only.

Use it to inventory the *library-level* crypto a Linux/macOS host can negotiate — a useful
complement to source/binary scanning when you care about what the platform's TLS stack
actually offers.

## Enable

```toml
# janus-agent.toml
enable_plugin_discovery = true
plugin_dirs = ["plugins"]
```

Auto-discovered via `plugins/openssl-inventory/plugin.toml`. Inline equivalent:

```toml
[[plugin_commands]]
name = "openssl-inventory"
command = "sh"
args = ["plugins/openssl-inventory/openssl-inventory.sh"]
timeout_seconds = 20
max_memory_mb = 128
max_cpu_percent = 25
```

## Test

```sh
sh plugins/openssl-inventory/openssl-inventory.sh     # eyeball the output
```

If `openssl` is absent the plugin exits 0 with a note on stderr (no findings). See
`docs/PLUGIN_GUIDE.md` for the full contract.
