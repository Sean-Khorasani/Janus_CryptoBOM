# Janus Server and UI

This portable bundle contains the Linux server, production UI, policies, and
release manifest. Configure PostgreSQL and required Janus environment variables,
then run `bin/janus-server` from this directory so it can find `policies/`.
Set `JANUS_UI_DIR` to the absolute path of this bundle's `ui/` directory.

Never store database credentials, signing keys, or TLS private keys in the
bundle.
