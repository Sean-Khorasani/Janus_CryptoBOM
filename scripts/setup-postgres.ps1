<#
.SYNOPSIS
  Create the Janus PostgreSQL role + database (idempotent). Windows/PowerShell port of
  setup-postgres.sh, for the PORTABLE and LOCAL-INSTALL deployments where you bring your
  own PostgreSQL. (Docker Compose creates the DB automatically — you don't need this there.)

  The server creates/upgrades its own schema on startup; this only provisions the empty
  role + database.

.PARAMETER JanusPassword
  Password for the janus login role (default: janus).

.EXAMPLE
  $env:PGHOST="localhost"; $env:PGUSER="postgres"; $env:PGPASSWORD="secret"
  .\scripts\setup-postgres.ps1 -JanusPassword "a-strong-password"

.NOTES
  Requires the psql client on PATH and a superuser connection via the standard libpq
  env vars (PGHOST/PGPORT/PGUSER/PGPASSWORD).
#>
[CmdletBinding()]
param(
  [string]$JanusPassword = $(if ($env:JANUS_PASSWORD) { $env:JANUS_PASSWORD } else { "janus" }),
  [string]$JanusDb       = $(if ($env:JANUS_DB) { $env:JANUS_DB } else { "janus" }),
  [string]$JanusRole     = $(if ($env:JANUS_ROLE) { $env:JANUS_ROLE } else { "janus" })
)
$ErrorActionPreference = "Stop"
$adminDb = if ($env:PGADMIN_DB) { $env:PGADMIN_DB } else { "postgres" }

if (-not (Get-Command psql -ErrorAction SilentlyContinue)) {
  Write-Error "psql not found. Install the PostgreSQL client (e.g. from postgresql.org or 'choco install postgresql')."
  exit 1
}

$escPw = $JanusPassword -replace "'", "''"

# 1. Role (transactional DO-block guard).
$roleSql = @"
DO `$do`$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$JanusRole') THEN
    CREATE ROLE $JanusRole LOGIN PASSWORD '$escPw';
  ELSE
    ALTER ROLE $JanusRole LOGIN PASSWORD '$escPw';
  END IF;
END
`$do`$;
"@
$roleSql | psql -v ON_ERROR_STOP=1 -d $adminDb
if ($LASTEXITCODE -ne 0) { Write-Error "role creation failed"; exit 1 }

# 2. Database (cannot run in a transaction — guard with a check).
$exists = (psql -tAc "SELECT 1 FROM pg_database WHERE datname='$JanusDb'" -d $adminDb).Trim()
if ($exists -ne "1") {
  psql -v ON_ERROR_STOP=1 -d $adminDb -c "CREATE DATABASE $JanusDb OWNER $JanusRole"
  if ($LASTEXITCODE -ne 0) { Write-Error "database creation failed"; exit 1 }
  "created database $JanusDb"
} else {
  "database $JanusDb already exists"
}

$pgHost = if ($env:PGHOST) { $env:PGHOST } else { "localhost" }
$pgPort = if ($env:PGPORT) { $env:PGPORT } else { "5432" }
""
"Done. Point the server at it with:"
"  JANUS_DATABASE_URL=postgres://$JanusRole`:<password>@$pgHost`:$pgPort/$JanusDb?sslmode=disable"
"(use sslmode=require in production with TLS configured on PostgreSQL)"
