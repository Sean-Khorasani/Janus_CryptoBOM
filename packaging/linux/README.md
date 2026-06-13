# Janus Agent Native Linux Packages

Build native packages from an existing Linux release agent binary:

```bash
SOURCE_DATE_EPOCH=1704067200 packaging/linux/build-packages.sh \
  --binary agent/target/release/janus-agent \
  --output-dir dist/packages
```

The builder produces `.deb` and `.rpm` packages by default. Use `--format deb`
or `--format rpm` to build one format. It requires `dpkg-deb` for Debian
packages and `rpmbuild` for RPM packages.

Both packages install:

- `/usr/bin/janus-agent`
- `/etc/janus-agent/janus-agent.toml`
- `/usr/lib/systemd/system/janus-agent.service`
- `/usr/lib/tmpfiles.d/janus-agent.conf`
- optional, inactive privilege profiles in
  `/usr/share/janus-agent/systemd-profiles/`

The configuration is preserved during upgrades. Debian removal preserves
configuration and state; `apt purge janus-agent` removes both. RPM upgrades
preserve modified configuration through `%config(noreplace)`, and uninstall
does not delete agent state. Packages create the locked `janusagent` service
account but do not start the service automatically.

Build portable Linux server+UI and agent tarballs after `make build`:

```bash
packaging/linux/build-release.sh
```

Artifacts use conventional names such as
`janus-server-ui-0.14.0-260611.1-linux-x86_64.tar.gz`, and `SHA256SUMS`
contains their checksums. Run `make release-linux` to build portable artifacts,
DEB, and RPM together.
