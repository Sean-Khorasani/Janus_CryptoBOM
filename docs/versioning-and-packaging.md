# Versioning and Release Artifacts

`VERSION.env` is the canonical Janus release contract. Component manifests use
the base SemVer `JANUS_VERSION`; release builds append
`+YYMMDD.sequence` for display and use `-YYMMDD.sequence` in artifact names.
Increment `JANUS_BUILD_SEQUENCE` for every build published on the same date.

Compatibility is independent of product version:

- `JANUS_API_VERSION` is exposed by the server at `/api/health`.
- `JANUS_UI_REQUIRED_API_VERSION` is compiled into the UI. The UI rejects a
  server with a different API version.
- `JANUS_AGENT_PROTOCOL_VERSION` and `JANUS_AGENT_MIN_SERVER_VERSION` describe
  agent/server compatibility.

Run `make release-linux` to produce Linux server+UI and portable-agent tarballs,
native DEB/RPM agent packages, and SHA-256 checksums under `dist/packages/`.
On Windows, run `build.bat package` or `.\build-windows.ps1 -Package` to produce
the equivalent server+UI and agent ZIPs.

Release archives intentionally exclude credentials, signing keys, TLS private
keys, databases, logs, and generated endpoint identity/state.
