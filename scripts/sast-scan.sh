#!/usr/bin/env bash
# =============================================================================
# sast-scan.sh — SAST via Semgrep
# Scans TypeScript/JavaScript/NestJS code for security vulnerabilities.
#
# Usage: ./scripts/sast-scan.sh --path <repo> --output <dir> --mode <mode>
# Output: <output>/sast-results.json  (Semgrep JSON format)
# Exit:   0=clean, 1=findings, 2=tool error
# =============================================================================

set -euo pipefail

REPO_PATH="."
OUTPUT_DIR="./security-reports"
SCAN_MODE="local"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(dirname "$SCRIPT_DIR")/templates"

while [[ $# -gt 0 ]]; do
  case $1 in
    --path)   REPO_PATH="$2";  shift 2 ;;
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    --mode)   SCAN_MODE="$2";  shift 2 ;;
    *) shift ;;
  esac
done

mkdir -p "$OUTPUT_DIR"
REPO_PATH="$(realpath "$REPO_PATH")"
OUTPUT_FILE="$OUTPUT_DIR/sast-results.json"

# ── Check tool ───────────────────────────────────────────────────────────────
if ! command -v semgrep &>/dev/null; then
  echo "[sast] ERROR: semgrep not installed. Run: pip install semgrep"
  exit 2
fi

SEMGREP_VERSION=$(semgrep --version 2>/dev/null || echo "unknown")
echo "[sast] semgrep $SEMGREP_VERSION"

# ── Select rulesets based on mode ────────────────────────────────────────────
# MR scan: broad ruleset for discovery
# Pre-deploy: strict + curated rules only
RULESETS=(
  "p/typescript"
  "p/nodejs"
  "p/owasp-top-ten"
  "p/jwt"
  "p/secrets"
)

if [[ "$SCAN_MODE" == "predeploy" ]]; then
  RULESETS+=(
    "p/sql-injection"
    "p/xss"
    "p/injection"
  )
fi

# ── Build ruleset args ────────────────────────────────────────────────────────
RULESET_ARGS=()
for r in "${RULESETS[@]}"; do
  RULESET_ARGS+=("--config" "$r")
done

# Use local config if exists
if [[ -f "$CONFIG_DIR/semgrep.yml" ]]; then
  RULESET_ARGS+=("--config" "$CONFIG_DIR/semgrep.yml")
  echo "[sast] Using custom rules: $CONFIG_DIR/semgrep.yml"
fi

# ── Run Semgrep ───────────────────────────────────────────────────────────────
echo "[sast] Scanning: $REPO_PATH"
echo "[sast] Rulesets: ${RULESETS[*]}"

SEMGREP_EXCLUDE=(
  "--exclude=node_modules"
  "--exclude=dist"
  "--exclude=build"
  "--exclude=.git"
  "--exclude=*.min.js"
  "--exclude=*.test.ts"
  "--exclude=*.spec.ts"
  "--exclude=*.d.ts"
  "--exclude=coverage"
  "--exclude=.nyc_output"
)

# Run and capture exit code
semgrep \
  "${RULESET_ARGS[@]}" \
  "${SEMGREP_EXCLUDE[@]}" \
  --json \
  --json-output="$OUTPUT_FILE" \
  --metrics=off \
  --quiet \
  "$REPO_PATH" || SEMGREP_EXIT=$?

SEMGREP_EXIT="${SEMGREP_EXIT:-0}"

# ── Parse and summarize ───────────────────────────────────────────────────────
if [[ -f "$OUTPUT_FILE" ]]; then
  TOTAL=$(python3 -c "
import json, sys
data = json.load(open('$OUTPUT_FILE'))
results = data.get('results', [])
print(len(results))
" 2>/dev/null || echo "0")

  CRITICAL=$(python3 -c "
import json
data = json.load(open('$OUTPUT_FILE'))
c = sum(1 for r in data.get('results',[]) if r.get('extra',{}).get('severity','').upper() in ['CRITICAL','ERROR'])
print(c)
" 2>/dev/null || echo "0")

  echo "[sast] Total findings: $TOTAL (critical: $CRITICAL)"
  echo "[sast] Report: $OUTPUT_FILE"
else
  echo "[sast] WARNING: No output file produced"
  echo '{"results":[],"errors":[],"stats":{}}' > "$OUTPUT_FILE"
fi

# Semgrep exits 1 when findings exist, 0 when clean, 2+ on error
if [[ $SEMGREP_EXIT -ge 2 ]]; then
  echo "[sast] Semgrep encountered errors (exit $SEMGREP_EXIT)"
  exit 2
elif [[ $SEMGREP_EXIT -eq 1 ]]; then
  exit 1  # findings exist — caller decides blocking
else
  exit 0
fi
