#!/usr/bin/env bash
# clear-scan-data.sh — Development utility to purge scan data from the Janus database.
#
# Under active development the schema evolves quickly and old malformed scan
# results can block testing.  This script lets you selectively wipe scan data
# without dropping the whole database or losing agent registrations.
#
# SAFETY GATES:
#   • Dry-run mode is the DEFAULT — nothing is deleted unless you pass --confirm.
#   • Interactive prompt when --confirm is given without --non-interactive.
#   • All deletes run inside a single transaction; any failure rolls back everything.
#
# Usage:
#   ./scripts/clear-scan-data.sh [TARGET] [OPTIONS]
#
# Targets (at least one required):
#   --all                  Target every registered agent
#   --agent  NAME_OR_UUID  Target one agent by hostname (exact) or host_uuid prefix
#   --pattern GLOB         Target agents whose hostname matches SQL LIKE pattern
#                          e.g.  --pattern 'prod-%'  --pattern '%.corp.example.com'
#
# Options:
#   --remove-agent         Deregister the agent(s) entirely (DELETE FROM assets).
#                          All scan data cascades automatically; --include-* flags
#                          are then redundant but harmless.
#   --include-llm          Also delete LLM analysis jobs, verdicts, and provenance.
#   --include-migrations   Also delete migration transactions and queued commands.
#   --include-connections  Also delete agent connection session history.
#   --older-than DAYS      Only delete scan data older than DAYS days.
#                          Applies to scan_runs, telemetry_payloads.  Agent
#                          registration is never touched by this filter alone.
#   --dry-run              (DEFAULT) Show row counts per table; do not delete.
#   --confirm              Actually execute the deletes (safety gate).
#   --non-interactive      Skip the confirmation prompt (use with --confirm in CI).
#   --db-url URL           PostgreSQL DSN (default: $JANUS_DATABASE_URL).
#                          Falls back to postgres://janus:janus@127.0.0.1:5432/janus
#   -h, --help             Print this help.
#
# Examples:
#   # Preview what would be deleted for a specific host (safe, no changes)
#   ./scripts/clear-scan-data.sh --agent dev-laptop
#
#   # Wipe all scan data for one agent and confirm
#   ./scripts/clear-scan-data.sh --agent dev-laptop --confirm
#
#   # Wipe everything including LLM data for all agents, non-interactive (CI)
#   ./scripts/clear-scan-data.sh --all --include-llm --confirm --non-interactive
#
#   # Remove stale agent registration entirely
#   ./scripts/clear-scan-data.sh --agent old-host-uuid-prefix --remove-agent --confirm
#
#   # Clear only scan data older than 7 days from prod-like hosts
#   ./scripts/clear-scan-data.sh --pattern 'prod-%' --older-than 7 --confirm

set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────
DB_URL="${JANUS_DATABASE_URL:-postgres://janus:janus@127.0.0.1:5432/janus?sslmode=disable}"
TARGET_ALL=false
TARGET_AGENT=""
TARGET_PATTERN=""
REMOVE_AGENT=false
INCLUDE_LLM=false
INCLUDE_MIGRATIONS=false
INCLUDE_CONNECTIONS=false
OLDER_THAN_DAYS=""
DRY_RUN=true   # safe default
NON_INTERACTIVE=false

# ── Colours ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

die()  { echo -e "${RED}ERROR: $*${RESET}" >&2; exit 1; }
info() { echo -e "${CYAN}  $*${RESET}"; }
warn() { echo -e "${YELLOW}  WARNING: $*${RESET}"; }
ok()   { echo -e "${GREEN}  $*${RESET}"; }

# ── Argument parsing ─────────────────────────────────────────────────────────
if [[ $# -eq 0 ]]; then
    grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -60
    exit 0
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)               TARGET_ALL=true ;;
        --agent)             shift; TARGET_AGENT="${1:-}"; [[ -z "$TARGET_AGENT" ]] && die "--agent requires a value" ;;
        --pattern)           shift; TARGET_PATTERN="${1:-}"; [[ -z "$TARGET_PATTERN" ]] && die "--pattern requires a value" ;;
        --remove-agent)      REMOVE_AGENT=true ;;
        --include-llm)       INCLUDE_LLM=true ;;
        --include-migrations) INCLUDE_MIGRATIONS=true ;;
        --include-connections) INCLUDE_CONNECTIONS=true ;;
        --older-than)        shift; OLDER_THAN_DAYS="${1:-}"; [[ -z "$OLDER_THAN_DAYS" ]] && die "--older-than requires a value (days)" ;;
        --dry-run)           DRY_RUN=true ;;
        --confirm)           DRY_RUN=false ;;
        --non-interactive)   NON_INTERACTIVE=true ;;
        --db-url)            shift; DB_URL="${1:-}"; [[ -z "$DB_URL" ]] && die "--db-url requires a value" ;;
        -h|--help)           grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -60; exit 0 ;;
        *) die "Unknown argument: $1.  Run with --help for usage." ;;
    esac
    shift
done

# ── Validate target ──────────────────────────────────────────────────────────
TARGET_COUNT=0
$TARGET_ALL   && TARGET_COUNT=$((TARGET_COUNT+1))
[[ -n "$TARGET_AGENT"   ]] && TARGET_COUNT=$((TARGET_COUNT+1))
[[ -n "$TARGET_PATTERN" ]] && TARGET_COUNT=$((TARGET_COUNT+1))

[[ $TARGET_COUNT -eq 0 ]] && die "No target specified.  Use --all, --agent NAME, or --pattern GLOB."
[[ $TARGET_COUNT -gt 1 ]] && die "Only one of --all / --agent / --pattern may be specified at a time."

# ── Check psql is available ──────────────────────────────────────────────────
command -v psql >/dev/null 2>&1 || die "psql not found.  Install postgresql-client and retry."

# ── Build agent WHERE clause ─────────────────────────────────────────────────
# The clause targets rows in the 'assets' table.
if $TARGET_ALL; then
    AGENT_WHERE="TRUE"
    TARGET_DESC="ALL agents"
elif [[ -n "$TARGET_AGENT" ]]; then
    # Accept either exact hostname match or host_uuid prefix/exact match.
    AGENT_WHERE="(hostname = '$(echo "$TARGET_AGENT" | sed "s/'/''/g")' OR host_uuid = '$(echo "$TARGET_AGENT" | sed "s/'/''/g")' OR host_uuid LIKE '$(echo "$TARGET_AGENT" | sed "s/'/''/g")%')"
    TARGET_DESC="agent matching '${TARGET_AGENT}'"
elif [[ -n "$TARGET_PATTERN" ]]; then
    AGENT_WHERE="hostname LIKE '$(echo "$TARGET_PATTERN" | sed "s/'/''/g")'"
    TARGET_DESC="agents matching hostname pattern '${TARGET_PATTERN}'"
fi

# ── Build time filter ────────────────────────────────────────────────────────
AGE_FILTER=""
AGE_DESC=""
if [[ -n "$OLDER_THAN_DAYS" ]]; then
    [[ "$OLDER_THAN_DAYS" =~ ^[0-9]+$ ]] || die "--older-than must be a positive integer (days)"
    AGE_FILTER="AND scan_finished < NOW() - INTERVAL '${OLDER_THAN_DAYS} days'"
    AGE_DESC=" older than ${OLDER_THAN_DAYS} days"
fi

# ── psql helper ──────────────────────────────────────────────────────────────
psql_exec() {
    psql --no-psqlrc --quiet --tuples-only "$DB_URL" -c "$1" 2>&1
}

psql_count() {
    # Returns integer row count from a SELECT COUNT(*) query.
    local result
    result=$(psql --no-psqlrc --quiet --tuples-only "$DB_URL" -c "$1" 2>&1)
    echo "$result" | tr -d ' \n'
}

# ── Verify connectivity ──────────────────────────────────────────────────────
echo -e "\n${BOLD}Janus Database Scan Data Cleanup${RESET}"
echo -e "Database : ${DB_URL%%@*}@**** (credentials hidden)"
echo

if ! psql --no-psqlrc --quiet "$DB_URL" -c "SELECT 1" >/dev/null 2>&1; then
    die "Cannot connect to database.  Check DB_URL and that PostgreSQL is running."
fi

# ── Resolve target agents ────────────────────────────────────────────────────
AGENT_LIST=$(psql --no-psqlrc --quiet --tuples-only "$DB_URL" \
    -c "SELECT host_uuid, hostname FROM assets WHERE ${AGENT_WHERE} ORDER BY hostname;" 2>&1)

AGENT_ROWS=$(echo "$AGENT_LIST" | grep -c '|' || true)

if [[ $AGENT_ROWS -eq 0 ]]; then
    warn "No agents found matching: ${TARGET_DESC}"
    echo "  Run:  psql \$JANUS_DATABASE_URL -c 'SELECT host_uuid, hostname FROM assets;'  to list all agents."
    exit 0
fi

echo -e "${BOLD}Target:${RESET} ${TARGET_DESC}${AGE_DESC}"
echo -e "${BOLD}Matching agents (${AGENT_ROWS}):${RESET}"
echo "$AGENT_LIST" | while IFS='|' read -r uuid hostname; do
    uuid=$(echo "$uuid" | xargs)
    hostname=$(echo "$hostname" | xargs)
    [[ -n "$uuid" ]] && echo "    ${uuid}  ${hostname}"
done
echo

# ── Build the list of host_uuids as a SQL literal ────────────────────────────
# Used for tables that don't have a direct FK but reference host_uuid as text.
UUID_LIST=$(psql --no-psqlrc --quiet --tuples-only "$DB_URL" \
    -c "SELECT host_uuid FROM assets WHERE ${AGENT_WHERE};" 2>&1 | tr -d ' ' | grep -v '^$' || true)

# Build the SQL IN-list for host_uuid
UUID_IN=$(echo "$UUID_LIST" | awk 'NF{printf "%s'\''%s'\''", sep, $0; sep=","}' | sed "s/^/(/;s/$/)/")

# Also build finding_id list for tables without a FK to assets
FINDING_ID_SUBQ="(SELECT finding_id FROM crypto_findings WHERE host_uuid IN ${UUID_IN})"

# ── Dry-run: show row counts ─────────────────────────────────────────────────
echo -e "${BOLD}Scan data that would be affected:${RESET}"

count_table() {
    local label="$1"
    local query="$2"
    local n
    n=$(psql_count "$query")
    printf "  %-40s %s rows\n" "$label" "$n"
}

# Core scan tables (always affected)
count_table "scan_runs"                \
    "SELECT COUNT(*) FROM scan_runs WHERE host_uuid IN ${UUID_IN} ${AGE_FILTER};"
count_table "  └─ scan_components"     \
    "SELECT COUNT(*) FROM scan_components sc JOIN scan_runs sr ON sc.scan_id=sr.scan_id WHERE sr.host_uuid IN ${UUID_IN} ${AGE_FILTER};"
count_table "  └─ finding_occurrences" \
    "SELECT COUNT(*) FROM finding_occurrences fo JOIN scan_runs sr ON fo.scan_id=sr.scan_id WHERE sr.host_uuid IN ${UUID_IN} ${AGE_FILTER};"

count_table "telemetry_payloads"       \
    "SELECT COUNT(*) FROM telemetry_payloads WHERE host_uuid IN ${UUID_IN};"
count_table "  └─ crypto_findings"     \
    "SELECT COUNT(*) FROM crypto_findings WHERE host_uuid IN ${UUID_IN};"

count_table "agent_progress_events"    \
    "SELECT COUNT(*) FROM agent_progress_events WHERE host_uuid IN ${UUID_IN};"
count_table "agility_metrics"          \
    "SELECT COUNT(*) FROM agility_metrics WHERE host_uuid IN ${UUID_IN};"
count_table "tls_certificates"         \
    "SELECT COUNT(*) FROM tls_certificates WHERE host_uuid IN ${UUID_IN};"
count_table "finding_lifecycle_events" \
    "SELECT COUNT(*) FROM finding_lifecycle_events WHERE host_uuid IN ${UUID_IN};"
count_table "finding_outcomes"         \
    "SELECT COUNT(*) FROM finding_outcomes WHERE finding_id IN ${FINDING_ID_SUBQ};"

# Optional: LLM data
if $INCLUDE_LLM; then
    count_table "llm_analysis_jobs"    \
        "SELECT COUNT(*) FROM llm_analysis_jobs WHERE finding_id IN ${FINDING_ID_SUBQ};"
    count_table "  └─ llm_verdicts"   \
        "SELECT COUNT(*) FROM llm_verdicts WHERE finding_id IN ${FINDING_ID_SUBQ};"
    count_table "  └─ llm_provenance" \
        "SELECT COUNT(*) FROM llm_provenance WHERE finding_id IN ${FINDING_ID_SUBQ};"
fi

# Optional: migration data
if $INCLUDE_MIGRATIONS; then
    count_table "migration_transactions" \
        "SELECT COUNT(*) FROM migration_transactions WHERE host_uuid IN ${UUID_IN};"
    count_table "agent_commands"         \
        "SELECT COUNT(*) FROM agent_commands WHERE host_uuid IN ${UUID_IN};"
fi

# Optional: connection history
if $INCLUDE_CONNECTIONS; then
    count_table "agent_connection_sessions" \
        "SELECT COUNT(*) FROM agent_connection_sessions WHERE host_uuid IN ${UUID_IN};"
fi

# Remove agent?
if $REMOVE_AGENT; then
    count_table "assets (agent records)" \
        "SELECT COUNT(*) FROM assets WHERE ${AGENT_WHERE};"
    warn "  --remove-agent: above counts will cascade-delete all remaining data."
fi

echo

# ── Dry-run exit ─────────────────────────────────────────────────────────────
if $DRY_RUN; then
    echo -e "${YELLOW}Dry-run mode (default): no changes made.${RESET}"
    echo "  Re-run with --confirm to execute.  Add --non-interactive to skip the prompt."
    exit 0
fi

# ── Confirm gate ─────────────────────────────────────────────────────────────
if ! $NON_INTERACTIVE; then
    echo -e "${RED}${BOLD}This will PERMANENTLY DELETE the rows listed above.${RESET}"
    echo -ne "  Type 'yes' to continue, anything else to abort: "
    read -r ANSWER
    [[ "$ANSWER" == "yes" ]] || { echo "Aborted."; exit 0; }
fi

# ── Execute deletes in a single transaction ──────────────────────────────────
echo
info "Executing deletes inside a transaction..."

# Build the SQL — order matters where there are FKs not covered by CASCADE.
SQL=""

# 1. finding_outcomes references finding_id (no FK) — delete before crypto_findings
SQL+="
DELETE FROM finding_outcomes
  WHERE finding_id IN (
    SELECT finding_id FROM crypto_findings WHERE host_uuid IN ${UUID_IN}
  );"

# 2. LLM tables reference finding_id (no FK to assets) — delete before crypto_findings
if $INCLUDE_LLM; then
    SQL+="
DELETE FROM llm_provenance
  WHERE finding_id IN (
    SELECT finding_id FROM crypto_findings WHERE host_uuid IN ${UUID_IN}
  );
DELETE FROM llm_verdicts
  WHERE finding_id IN (
    SELECT finding_id FROM crypto_findings WHERE host_uuid IN ${UUID_IN}
  );
DELETE FROM llm_analysis_jobs
  WHERE finding_id IN (
    SELECT finding_id FROM crypto_findings WHERE host_uuid IN ${UUID_IN}
  );"
fi

# 3. scan_runs — cascades scan_components and finding_occurrences
if [[ -n "$AGE_FILTER" ]]; then
    SQL+="
DELETE FROM scan_runs WHERE host_uuid IN ${UUID_IN} ${AGE_FILTER};"
else
    SQL+="
DELETE FROM scan_runs WHERE host_uuid IN ${UUID_IN};"
fi

# 4. telemetry_payloads — cascades crypto_findings
SQL+="
DELETE FROM telemetry_payloads WHERE host_uuid IN ${UUID_IN};"

# 5. Orphaned crypto_findings not linked to a telemetry_payload (edge case on schema drift)
SQL+="
DELETE FROM crypto_findings WHERE host_uuid IN ${UUID_IN};"

# 6. Progress events and derived metrics
SQL+="
DELETE FROM agent_progress_events WHERE host_uuid IN ${UUID_IN};
DELETE FROM agility_metrics WHERE host_uuid IN ${UUID_IN};
DELETE FROM tls_certificates WHERE host_uuid IN ${UUID_IN};
DELETE FROM finding_lifecycle_events WHERE host_uuid IN ${UUID_IN};"

# 7. Optional: migration data
if $INCLUDE_MIGRATIONS; then
    SQL+="
DELETE FROM migration_transactions WHERE host_uuid IN ${UUID_IN};
DELETE FROM agent_commands WHERE host_uuid IN ${UUID_IN};"
fi

# 8. Optional: connection history
if $INCLUDE_CONNECTIONS; then
    SQL+="
DELETE FROM agent_connection_sessions WHERE host_uuid IN ${UUID_IN};"
fi

# 9. Remove agent registration last (everything else cascades from here,
#    but we've already deleted the referencing rows above without CASCADE
#    on finding_id columns to be explicit about what we're removing).
if $REMOVE_AGENT; then
    SQL+="
DELETE FROM assets WHERE ${AGENT_WHERE};"
fi

# Wrap in transaction with row count reporting
TX_SQL="BEGIN;
${SQL}
COMMIT;"

# Execute and capture output
if psql --no-psqlrc "$DB_URL" -c "$TX_SQL" 2>&1; then
    ok "Done.  All deletes committed successfully."
else
    die "psql reported an error.  The transaction was rolled back — database unchanged."
fi

echo
info "Summary of what was cleared:"
info "  Target:      ${TARGET_DESC}${AGE_DESC}"
info "  LLM data:    $( $INCLUDE_LLM        && echo 'yes' || echo 'no (use --include-llm)')"
info "  Migrations:  $( $INCLUDE_MIGRATIONS  && echo 'yes' || echo 'no (use --include-migrations)')"
info "  Connections: $( $INCLUDE_CONNECTIONS && echo 'yes' || echo 'no (use --include-connections)')"
info "  Agent removed: $( $REMOVE_AGENT     && echo 'yes (deregistered)' || echo 'no (registration kept)')"
