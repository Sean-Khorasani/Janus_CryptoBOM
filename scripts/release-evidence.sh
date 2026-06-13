#!/usr/bin/env bash
# release-evidence.sh — generate a formal release-evidence bundle (WP-025).
#
# Collects the artifacts a release review needs to confirm that documented
# capabilities are backed by passing gates: version contract, build provenance,
# schema version, test outcomes, the documentation-claim lint result, the
# capability-maturity snapshot, and dependency/SBOM status. Writes a single
# timestamped Markdown manifest and prints its path.
#
# Usage:
#   ./scripts/release-evidence.sh [OUTPUT_DIR]
#
# OUTPUT_DIR defaults to ./release-evidence. The manifest is named
# release-evidence-<version>-<gitsha>.md. Each gate's PASS/FAIL/SKIP is recorded
# rather than aborting the run, so the manifest is a complete picture even when
# something fails. Exit code is non-zero if any *required* gate failed.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT/release-evidence}"
cd "$ROOT" || { echo "error: cannot cd to project root $ROOT" >&2; exit 1; }

# shellcheck disable=SC1091
. ./VERSION.env 2>/dev/null || true
VERSION="${JANUS_VERSION:-unknown}"

GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
GIT_DIRTY="clean"
if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
    GIT_DIRTY="dirty (uncommitted changes present)"
fi
# Note: this build environment has no Date.now-style nondeterminism concern;
# the timestamp is captured once here for the manifest header.
STAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo unknown)"

mkdir -p "$OUT_DIR"
MANIFEST="$OUT_DIR/release-evidence-${VERSION}-${GIT_SHA}.md"

overall_rc=0
record() { # name, status, detail
    local name="$1" status="$2" detail="$3"
    printf '| %s | **%s** | %s |\n' "$name" "$status" "$detail" >> "$MANIFEST"
    [ "$status" = "FAIL" ] && overall_rc=1
    return 0
}

# Run a gate command, capturing its result without aborting the script.
run_gate() { # description, command...
    local desc="$1"; shift
    if "$@" >/tmp/janus-gate.$$ 2>&1; then
        record "$desc" "PASS" "$(tail -1 /tmp/janus-gate.$$ | tr -d '|' | cut -c1-80)"
    else
        record "$desc" "FAIL" "$(tail -1 /tmp/janus-gate.$$ | tr -d '|' | cut -c1-80)"
    fi
    rm -f /tmp/janus-gate.$$
}

{
    echo "# Janus CryptoBOM — Release Evidence"
    echo
    echo "- **Version:** \`$VERSION\` (build ${JANUS_BUILD_DATE:-?}.${JANUS_BUILD_SEQUENCE:-?}, API ${JANUS_API_VERSION:-?})"
    echo "- **Commit:** \`$GIT_SHA\` on \`$GIT_BRANCH\` — $GIT_DIRTY"
    echo "- **Generated:** $STAMP"
    echo
    echo "This bundle records the gate outcomes backing the documented capabilities."
    echo "See \`docs/CAPABILITY_MATURITY.md\` for the maturity self-assessment and"
    echo "\`docs/analysis/DETECTION-BENCHMARK.md\` for detection precision/recall."
    echo
    echo "## Gate results"
    echo
    echo "| Gate | Status | Detail |"
    echo "|---|---|---|"
} > "$MANIFEST"

# --- Gates -----------------------------------------------------------------

# Documentation-claim linter (required).
run_gate "Documentation-claim lint" python3 scripts/verify-claims.py

# Documentation completeness (if present).
if [ -f scripts/verify-docs.py ]; then
    run_gate "Documentation completeness" python3 scripts/verify-docs.py
fi

# Go server tests (required if go present).
if command -v go >/dev/null 2>&1; then
    run_gate "Go server tests" bash -c 'cd server && go test ./...'
else
    record "Go server tests" "SKIP" "go toolchain not available"
fi

# Rust agent tests (required if cargo present).
if command -v cargo >/dev/null 2>&1; then
    run_gate "Rust agent tests" bash -c 'cd agent && cargo test --quiet'
else
    record "Rust agent tests" "SKIP" "cargo toolchain not available"
fi

# Detection benchmark (precision/recall by detector + language).
if command -v cargo >/dev/null 2>&1; then
    run_gate "Detection benchmark (WP-014)" bash -c 'cd agent && cargo test detection_benchmark::benchmark_by_language_and_detector'
fi

# Schema version (informational): count of declared migrations.
SCHEMA_COUNT="$(grep -cE '^\s*\{[0-9]+, "' server/internal/store/store.go 2>/dev/null || echo '?')"
record "DB schema migrations declared" "INFO" "$SCHEMA_COUNT migrations in store.go"

# SBOM / dependency lockfiles present (supply-chain evidence).
LOCKS_OK=1
for lk in server/go.sum agent/Cargo.lock ui/package-lock.json; do
    [ -f "$lk" ] || LOCKS_OK=0
done
if [ "$LOCKS_OK" = 1 ]; then
    record "Dependency lockfiles" "PASS" "go.sum, Cargo.lock, package-lock.json present"
else
    record "Dependency lockfiles" "FAIL" "one or more lockfiles missing"
fi

# --- Capability maturity snapshot -----------------------------------------
{
    echo
    echo "## Capability maturity snapshot"
    echo
    echo "Current self-assessed levels (from docs/CAPABILITY_MATURITY.md):"
    echo
    grep -nE 'Current Janus status' docs/CAPABILITY_MATURITY.md 2>/dev/null \
        | sed -E 's/^[0-9]+:/- /; s/\*\*//g' | cut -c1-200 || echo "- (maturity doc not found)"
} >> "$MANIFEST"

echo
if [ "$overall_rc" -eq 0 ]; then
    echo "Release evidence written (all required gates PASSED): $MANIFEST"
else
    echo "Release evidence written (one or more gates FAILED): $MANIFEST" >&2
fi
echo "$MANIFEST"
exit "$overall_rc"
