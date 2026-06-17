#!/usr/bin/env bash
# setup-postgres.sh — create the Janus PostgreSQL role + database (idempotent).
#
# Needed for the PORTABLE and LOCAL-INSTALL deployments, where you bring your own
# PostgreSQL. (The Docker Compose deployment creates the DB automatically from the
# postgres image's POSTGRES_* env, so you do NOT need this there.)
#
# The server creates/upgrades its own schema on startup (versioned migrations) — this
# script only provisions the empty role + database it connects to.
#
# Prereqs: the `psql` client, and a superuser connection to your PostgreSQL.
#
# Usage:
#   PGHOST=localhost PGPORT=5432 PGUSER=postgres PGPASSWORD=secret \
#     ./scripts/setup-postgres.sh [janus_password]
#
# Env knobs (all optional):
#   PGHOST/PGPORT/PGUSER/PGPASSWORD  standard libpq vars for the ADMIN connection
#   JANUS_DB     (default: janus)    database to create
#   JANUS_ROLE   (default: janus)    login role to create
#   JANUS_PASSWORD / $1 (default: janus)  password for the janus role
set -euo pipefail

JANUS_DB="${JANUS_DB:-janus}"
JANUS_ROLE="${JANUS_ROLE:-janus}"
JANUS_PASSWORD="${1:-${JANUS_PASSWORD:-janus}}"
ADMIN_DB="${PGADMIN_DB:-postgres}"

if ! command -v psql >/dev/null 2>&1; then
  echo "error: psql not found. Install the PostgreSQL client (e.g. apt-get install postgresql-client-16)." >&2
  exit 1
fi

# Escape single quotes in the password for safe SQL string literal interpolation.
esc_pw="${JANUS_PASSWORD//\'/\'\'}"

# 1. Role (CREATE ROLE is transactional, so a DO-block guard is fine).
psql -v ON_ERROR_STOP=1 -d "$ADMIN_DB" <<SQL
DO \$do\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${JANUS_ROLE}') THEN
    CREATE ROLE ${JANUS_ROLE} LOGIN PASSWORD '${esc_pw}';
  ELSE
    ALTER ROLE ${JANUS_ROLE} LOGIN PASSWORD '${esc_pw}';
  END IF;
END
\$do\$;
SQL

# 2. Database (CREATE DATABASE cannot run inside a transaction/DO block — guard with a check).
if [ "$(psql -tAc "SELECT 1 FROM pg_database WHERE datname='${JANUS_DB}'" -d "$ADMIN_DB")" != "1" ]; then
  psql -v ON_ERROR_STOP=1 -d "$ADMIN_DB" -c "CREATE DATABASE ${JANUS_DB} OWNER ${JANUS_ROLE}"
  echo "created database ${JANUS_DB}"
else
  echo "database ${JANUS_DB} already exists"
fi

echo
echo "Done. Point the server at it with:"
echo "  JANUS_DATABASE_URL=postgres://${JANUS_ROLE}:<password>@${PGHOST:-localhost}:${PGPORT:-5432}/${JANUS_DB}?sslmode=disable"
echo "(use sslmode=require in production with TLS configured on PostgreSQL)"
