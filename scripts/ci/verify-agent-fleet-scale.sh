#!/usr/bin/env bash
set -euo pipefail

: "${JANUS_DATABASE_URL:?Set JANUS_DATABASE_URL to an isolated PostgreSQL test database}"

psql "$JANUS_DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
INSERT INTO assets (
  host_uuid, hostname, os_name, os_version, arch, execution_mode, capabilities,
  last_seen, status, agent_version, observed_ip, dns_name
)
SELECT
  'scale-agent-' || n,
  'scale-host-' || n,
  CASE WHEN n % 2 = 0 THEN 'Linux' ELSE 'Windows' END,
  CASE WHEN n % 2 = 0 THEN '24.04' ELSE '11' END,
  'x86_64', 1, '[]'::jsonb,
  now() - ((n % 3600) || ' seconds')::interval,
  CASE WHEN n % 7 = 0 THEN 'offline' ELSE 'Idle' END,
  '0.1.' || (n % 10),
  '10.20.' || (n % 255) || '.' || ((n / 255) % 255),
  'scale-host-' || n || '.example.test'
FROM generate_series(1, 5000) n
ON CONFLICT (host_uuid) DO UPDATE SET last_seen=EXCLUDED.last_seen;

EXPLAIN (ANALYZE, BUFFERS)
SELECT host_uuid, hostname, os_name, agent_version, observed_ip, status, last_seen
FROM assets
WHERE hostname ILIKE '%scale-host-42%'
ORDER BY last_seen DESC, host_uuid
LIMIT 50;

EXPLAIN (ANALYZE, BUFFERS)
SELECT host_uuid, hostname, status, last_seen
FROM assets
WHERE status='offline'
ORDER BY last_seen DESC, host_uuid
LIMIT 50;
ROLLBACK;
SQL

echo "5,000-agent fleet query evidence generated"
