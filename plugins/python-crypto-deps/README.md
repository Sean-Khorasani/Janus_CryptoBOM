# Python Crypto Dependencies Plugin (sample)

Inventories crypto-relevant packages installed in the current Python environment
(`cryptography`, `pyOpenSSL`, `pycryptodome`, `paramiko`, `pynacl`, `oqs`/liboqs, …) and the
algorithm families they provide. It is **metadata-only** — package names, versions, and
algorithm families; never keys or secrets — and read-only.

Use it to see the crypto a Python service can actually invoke at runtime, complementing
manifest-based dependency scanning (it reads what's *installed* in the interpreter the
plugin runs under).

## Enable

```toml
# janus-agent.toml
enable_plugin_discovery = true
plugin_dirs = ["plugins"]
```

Auto-discovered via `plugins/python-crypto-deps/plugin.toml`. Inline equivalent:

```toml
[[plugin_commands]]
name = "python-crypto-deps"
command = "python3"
args = ["-u", "plugins/python-crypto-deps/python_crypto_deps.py"]
timeout_seconds = 20
max_memory_mb = 256
max_cpu_percent = 25
```

> Runs under whichever `python3` is on PATH. To audit a specific virtualenv, point
> `command` at that interpreter (e.g. `/srv/app/.venv/bin/python`).

## Test

```sh
python3 plugins/python-crypto-deps/python_crypto_deps.py    # eyeball the JSON output
```

Emits a JSON report; if no recognized crypto packages are present it exits 0 with a note on
stderr. See `docs/PLUGIN_GUIDE.md` for the full contract.
