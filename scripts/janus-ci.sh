#!/bin/bash
# Janus CryptoBOM CI Runner
# Usage: ./scripts/janus-ci.sh [path] [--fail-on high|critical]

set -euo pipefail

SCAN_PATH="${1:-.}"
FAIL_LEVEL="${2:-critical}"
JANUS_BIN="${JANUS_BIN:-janus-cli}"
OUTPUT_DIR="${OUTPUT_DIR:-janus-ci-output}"

mkdir -p "$OUTPUT_DIR"

echo "=== Janus CryptoBOM CI Scan ==="
echo "Scan path: $SCAN_PATH"
echo "Fail level: $FAIL_LEVEL"
echo ""

# Run scan
echo "[1/3] Running cryptographic discovery scan..."
$JANUS_BIN check "$SCAN_PATH" \
  --format sarif \
  --output "$OUTPUT_DIR/janus-findings.sarif" \
  2>&1 | tee "$OUTPUT_DIR/janus-scan.log"
SCAN_EXIT=$?

# Generate CBOM
echo "[2/3] Generating CycloneDX CBOM..."
$JANUS_BIN check "$SCAN_PATH" \
  --format cyclonedx \
  --output "$OUTPUT_DIR/janus-cbom.json" \
  2>&1

# Compliance gate
echo "[3/3] Running compliance gate..."
CRITICAL=$(grep -c '"level": "error"' "$OUTPUT_DIR/janus-findings.sarif" 2>/dev/null || echo 0)
HIGH=$(grep -c '"level": "warning"' "$OUTPUT_DIR/janus-findings.sarif" 2>/dev/null || echo 0)

echo ""
echo "=== Scan Summary ==="
echo "Critical findings: $CRITICAL"
echo "High findings: $HIGH"
echo "SARIF report: $OUTPUT_DIR/janus-findings.sarif"
echo "CBOM report: $OUTPUT_DIR/janus-cbom.json"
echo "Scan log: $OUTPUT_DIR/janus-scan.log"

if [ "$FAIL_LEVEL" = "critical" ] && [ "$CRITICAL" -gt 0 ]; then
  echo "::error::Compliance gate FAILED: $CRITICAL critical findings"
  exit 1
elif [ "$FAIL_LEVEL" = "high" ] && [ "$((CRITICAL + HIGH))" -gt 0 ]; then
  echo "::error::Compliance gate FAILED: $CRITICAL critical + $HIGH high findings"
  exit 1
fi

echo "Compliance gate PASSED"
exit 0
