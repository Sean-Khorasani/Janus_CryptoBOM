CREATE TABLE IF NOT EXISTS assets (
  host_uuid TEXT PRIMARY KEY,
  hostname TEXT NOT NULL,
  os_name TEXT NOT NULL,
  os_version TEXT NOT NULL,
  arch TEXT NOT NULL,
  execution_mode INTEGER NOT NULL,
  capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS telemetry_payloads (
  telemetry_id TEXT PRIMARY KEY,
  host_uuid TEXT NOT NULL REFERENCES assets(host_uuid) ON DELETE CASCADE,
  scan_started TIMESTAMPTZ NOT NULL,
  scan_finished TIMESTAMPTZ NOT NULL,
  component_count INTEGER NOT NULL,
  finding_count INTEGER NOT NULL,
  network_observation_count INTEGER NOT NULL,
  cyclone_dx JSONB,
  payload JSONB NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS crypto_findings (
  finding_id TEXT PRIMARY KEY,
  telemetry_id TEXT NOT NULL REFERENCES telemetry_payloads(telemetry_id) ON DELETE CASCADE,
  host_uuid TEXT NOT NULL REFERENCES assets(host_uuid) ON DELETE CASCADE,
  severity INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  asset_ref TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  policy_rule_id TEXT NOT NULL,
  migration_profile TEXT NOT NULL,
  evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  status TEXT NOT NULL DEFAULT 'open',
  updated_by TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  confidence DOUBLE PRECISION NOT NULL DEFAULT 0.82,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS migration_transactions (
  command_id TEXT PRIMARY KEY,
  host_uuid TEXT NOT NULL REFERENCES assets(host_uuid) ON DELETE CASCADE,
  target_service TEXT NOT NULL,
  migration_profile TEXT NOT NULL,
  target_kem TEXT NOT NULL,
  target_signature TEXT NOT NULL,
  config_path TEXT NOT NULL,
  state INTEGER NOT NULL,
  dry_run BOOLEAN NOT NULL,
  observed_tls JSONB,
  issued_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_error TEXT NOT NULL DEFAULT '',
  output TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_crypto_findings_host_uuid ON crypto_findings(host_uuid);
CREATE INDEX IF NOT EXISTS idx_crypto_findings_severity ON crypto_findings(severity);
CREATE INDEX IF NOT EXISTS idx_migration_transactions_host_uuid ON migration_transactions(host_uuid);
