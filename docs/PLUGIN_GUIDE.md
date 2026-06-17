# Janus CryptoBOM — Plugin Development Guide (DOC-003)

Agent plugins let you extend discovery with host- or ecosystem-specific cryptographic
inventory that the built-in scanners (source, binary, dependency, network, Windows) don't
cover — e.g. an HSM/KMS inventory, a language runtime's crypto provider list, or a vendor
appliance's TLS posture. A plugin is just **an external command the agent runs each scan**.

## The contract (read this first)

It is deliberately simple — there is **no required JSON schema and no stdin**:

1. Each scan, the agent runs your `command` with its `args` (no stdin is provided).
2. It captures the command's **stdout *and* stderr**, combined into one text blob.
3. That blob is stored as a **single `metadata-only` evidence record** (`source_type:
   agent-plugin`, the agent attaches a SHA-256 of the output for integrity).
4. The agent then **keyword-scans the output** (case-insensitive substring) for recognized
   algorithm names and records each as a CBOM component algorithm (status
   `plugin-observed`). Recognized keywords:

   `ml-kem` / `mlkem` / `kyber` · `ml-dsa` / `mldsa` / `dilithium` · `slh-dsa` / `sphincs`
   · `rsa` · `ecdsa` · `ecdh` · `diffie` · `sha1` · `sha256` · `aes`

So: **print whatever you like** (JSON, a table, plain lines) as long as the cryptographic
material you found is named using those tokens. JSON is recommended for human readability,
but the agent matches substrings — it does not parse your structure.

> The plugin's output is **evidence**, and may be sent to an LLM if (and only if) the
> operator has explicitly enabled LLM analysis. **Never print secrets** — private keys,
> passwords, tokens, session material, or decrypted data. Emit metadata only (names, sizes,
> versions, fingerprints). The shipped samples are metadata-only.

## Configuring plugins

Plugins are **off by default**. Enable discovery and either point at a directory of plugins
or declare them inline, in `janus-agent.toml`:

```toml
enable_plugin_discovery = true     # master switch (default false)

# Option A — auto-discover: every <dir>/*/plugin.toml is loaded.
plugin_dirs = ["plugins"]

# Option B — inline declaration (equivalent shape to a plugin.toml).
[[plugin_commands]]
name = "my-plugin"                 # label used in evidence/CBOM
command = "python3"                # executable (on PATH or absolute)
args = ["-u", "plugins/my-plugin/plugin.py"]
timeout_seconds = 30               # default 30; the plugin is killed past this
max_memory_mb = 512                # default 512; floor 64
max_cpu_percent = 50               # default 50; clamped 1–100
```

A discovered `plugin.toml` has exactly the `[[plugin_commands]]` fields at the top level
(`name`, `command`, `args`, `timeout_seconds`, `max_memory_mb`, `max_cpu_percent`).

### Resource limits & OS support

The command runs under enforced limits: **Linux** via cgroups v2 (`memory.max`, `cpu.max`),
**Windows** via a Job Object (`JOBOBJECT_EXTENDED_LIMIT_INFORMATION`). A plugin that exceeds
its time budget is killed (`timeout_seconds`); one that exceeds memory is OOM-killed by the
OS. Any executable works — POSIX shell, Python, PowerShell, or a compiled binary — as long
as it's present on the scan host. The plugin runs with the **agent's** privileges, so only
enable plugins you trust.

### Signing plugins (optional, recommended for fleets)

Auto-discovered manifests run with the agent's privileges, so in shared/fleet deployments you
can require that every discovered `plugin.toml` is signed. Set a shared key in `janus-agent.toml`:

```toml
plugin_signing_key = "<hex secret, shared with whoever signs your plugins>"
```

When set, the agent loads an auto-discovered plugin **only** if a `plugin.toml.sig` sits next
to its `plugin.toml` containing the hex HMAC-SHA256 of the manifest bytes under that key. A
missing or mismatched signature aborts agent startup with an error — it never silently loads an
unverified plugin (SEC-02). Regenerate the sidecar whenever you edit a manifest:

```bash
openssl dgst -sha256 -mac HMAC -macopt hexkey:<hex> -r plugins/my-plugin/plugin.toml \
  | cut -d' ' -f1 > plugins/my-plugin/plugin.toml.sig
```

Leaving `plugin_signing_key` unset keeps the default behaviour (no signature required). Inline
`[[plugin_commands]]` are not signature-checked — they are already part of the
operator-controlled agent config.

## Error handling

- A **non-zero exit** is tolerated — whatever the plugin wrote to stdout/stderr before
  exiting is still ingested (so partial inventory isn't lost). Print a diagnostic to stderr
  rather than aborting on a single sub-probe failure.
- A **timeout** kills the plugin; its output up to that point is *not* guaranteed. Keep the
  plugin well within `timeout_seconds`; do expensive work incrementally and flush early.
- Plugins must be **read-only / passive** — discovery never writes to the scanned host.

## Testing a plugin

1. **Run it standalone** and eyeball the output (this is exactly what the agent captures):
   ```bash
   python3 plugins/my-plugin/plugin.py        # or: sh plugins/.../plugin.sh
   ```
   Confirm it prints the algorithm names you expect and **no secrets**.
2. **Run a single agent scan** with the plugin enabled and inspect the result:
   ```bash
   # janus-agent.toml: enable_plugin_discovery = true, plugin_dirs = ["plugins"]
   janus-agent --config janus-agent.toml --once
   ```
   Then look at the generated HTML/SARIF report (`report_path`/`sarif_path`) or the
   dashboard **CBOM** tab for a component named after your plugin with type
   `agent-plugin-output`, and an `agent-plugin` evidence record.
3. Watch the agent log for `plugin execution timed out` or non-zero-exit warnings.

## Samples (different use cases)

Three shipped examples, one per environment/use case:

| Plugin | Use case | Lang | Path |
|---|---|---|---|
| `windows-crypto-inventory` | Windows cert stores + Schannel/CNG posture | PowerShell | `plugins/windows-inventory/` |
| `openssl-inventory` | Host OpenSSL/TLS library + offered groups | POSIX shell | `plugins/openssl-inventory/` |
| `python-crypto-deps` | Python environment's crypto dependencies | Python | `plugins/python-crypto-deps/` |

Each directory has a `plugin.toml`, the script, and a README. Copy one as a starting point.
With `plugin_dirs = ["plugins"]` and `enable_plugin_discovery = true`, all three load
automatically on the platforms where their interpreter exists.
