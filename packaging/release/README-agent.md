# Janus Agent

Edit `janus-agent.toml` for the target endpoint, then run:

```bash
bin/janus-agent --config janus-agent.toml
```

Keep the command-signing key and generated agent state outside this bundle, so
replacing the bundle on upgrade never touches your secrets or queued data.
