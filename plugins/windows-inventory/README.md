# Windows Crypto Inventory Plugin

This plugin collects Windows certificate store metadata, Schannel policy, HTTP.sys TLS bindings, and CNG/CAPI provider information.

It is metadata-only. It does not export private keys, session secrets, passwords, or decrypted payloads.

Preferred configuration:

```toml
plugin_dirs = ["plugins"]
```

Manual equivalent:

```toml
[[plugin_commands]]
name = "windows-crypto-inventory"
command = "powershell"
args = ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "plugins/windows-inventory/janus-windows-crypto-inventory.ps1", "-Format", "Json"]
timeout_seconds = 45
```
