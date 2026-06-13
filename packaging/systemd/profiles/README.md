# Janus Agent systemd Privilege Profiles

The base `janus-agent.service` is the supported passive profile. These drop-ins
only grant permissions; they do not enable agent features. Copy the minimum
required profile to `/etc/systemd/system/janus-agent.service.d/`, set its
matching opt-in in `/etc/janus-agent/janus-agent.toml`, and restart the service.
The base service also requires `/etc/janus-agent/command-signing-key`, which
systemd exposes to the process as a private read-only credential.

```bash
sudo install -D -m 0644 packaging/systemd/profiles/runtime-discovery.conf \
  /etc/systemd/system/janus-agent.service.d/runtime-discovery.conf
sudo systemctl daemon-reload
sudo systemctl restart janus-agent
```

- `runtime-discovery.conf`: exposes ptraceable process metadata. Set
  `enable_runtime_discovery = true`.
- `process-memory.conf`: grants `CAP_SYS_PTRACE`. Install it together with the
  runtime profile and set both runtime and process-memory flags.
- `plugin-cgroup.conf`: delegates only cgroup v2 CPU and memory controllers.
  Set `enable_plugin_discovery = true`.

These profiles are experimental until denial, privacy, and end-to-end tests
pass on the supported Linux matrix. Never combine them without a documented
need. Remove a profile to revoke its permission. The current release archive
and install script do not install these source-tree reference profiles.
