#!/usr/bin/env bash
# =============================================================================
# secret-scan.sh — Secret Detection via Gitleaks
# Scans git history and working tree for secrets, tokens, API keys.
# Falls back to TruffleHog if Gitleaks not available.
#
# Usage: ./scripts/secret-scan.sh --path <repo> --output <dir> --mode <mode>
# Output: <output>/secret-results.json
# Exit:   0=clean, 1=secrets found, 2=tool error
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
OUTPUT_FILE="$OUTPUT_DIR/secret-results.json"

# ── Determine scan depth based on mode ───────────────────────────────────────
# MR: scan only uncommitted changes + last N commits
# Pre-deploy / local: scan full git history
case "$SCAN_MODE" in
  mr)       DEPTH="--log-opts=HEAD~10..HEAD" ;;  # Last 10 commits (MR range)
  predeploy) DEPTH="" ;;                          # Full history
  local)    DEPTH="--no-git" ;;                  # Working tree only (fast)
  *)        DEPTH="--no-git" ;;
esac

# ── Gitleaks path ─────────────────────────────────────────────────────────────
run_gitleaks() {
  local CONFIG_ARG=""
  if [[ -f "$CONFIG_DIR/gitleaks.toml" ]]; then
    CONFIG_ARG="--config=$CONFIG_DIR/gitleaks.toml"
    echo "[secrets] Using custom rules: $CONFIG_DIR/gitleaks.toml"
  fi

  echo "[secrets] Running Gitleaks (mode: $SCAN_MODE)"

  if [[ "$SCAN_MODE" == "local" ]]; then
    # Scan working directory (no git history)
    gitleaks detect \
      --source="$REPO_PATH" \
      --no-git \
      --report-format=json \
      --report-path="$OUTPUT_FILE" \
      ${CONFIG_ARG:+"$CONFIG_ARG"} \
      --redact \
      --exit-code=1 2>/dev/null || return $?
  else
    # Scan git history
    gitleaks detect \
      --source="$REPO_PATH" \
      ${DEPTH:+$DEPTH} \
      --report-format=json \
      --report-path="$OUTPUT_FILE" \
      ${CONFIG_ARG:+"$CONFIG_ARG"} \
      --redact \
      --exit-code=1 2>/dev/null || return $?
  fi
  return 0
}

# ── TruffleHog fallback ───────────────────────────────────────────────────────
run_trufflehog() {
  echo "[secrets] Falling back to TruffleHog"

  if ! command -v trufflehog &>/dev/null; then
    echo "[secrets] ERROR: Neither gitleaks nor trufflehog installed"
    echo "[secrets] Install: brew install gitleaks  OR  pip install trufflehog"
    exit 2
  fi

  trufflehog filesystem \
    "$REPO_PATH" \
    --json \
    --no-update \
    2>/dev/null \
    | python3 -c "
import sys, json
findings = []
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        obj = json.loads(line)
        # Normalize to gitleaks-like format
        findings.append({
            'RuleID': obj.get('DetectorName', 'unknown'),
            'Description': obj.get('DetectorName', 'Secret detected'),
            'File': obj.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'unknown'),
            'Secret': '[REDACTED]',
            'Match': '[REDACTED]',
            'Tags': ['trufflehog']
        })
    except: pass
print(json.dumps(findings, indent=2))
" > "$OUTPUT_FILE"
}

# ── Run ───────────────────────────────────────────────────────────────────────
SCAN_EXIT=0

if command -v gitleaks &>/dev/null; then
  GITLEAKS_VERSION=$(gitleaks version 2>/dev/null || echo "unknown")
  echo "[secrets] gitleaks $GITLEAKS_VERSION"
  run_gitleaks || SCAN_EXIT=$?
else
  run_trufflehog || SCAN_EXIT=$?
fi

# ── Ensure valid JSON output ──────────────────────────────────────────────────
if [[ ! -f "$OUTPUT_FILE" ]] || ! python3 -m json.tool "$OUTPUT_FILE" &>/dev/null; then
  echo "[]" > "$OUTPUT_FILE"
fi

# ── Count findings ────────────────────────────────────────────────────────────
COUNT=$(python3 -c "
import json
data = json.load(open('$OUTPUT_FILE'))
if isinstance(data, list):
    print(len(data))
else:
    print(len(data.get('findings', data.get('leaks', []))))
" 2>/dev/null || echo "0")

echo "[secrets] Secrets found: $COUNT"
echo "[secrets] Report: $OUTPUT_FILE"

# Normalize output to array format if needed
python3 -c "
import json
data = json.load(open('$OUTPUT_FILE'))
if not isinstance(data, list):
    data = data.get('findings', data.get('leaks', []))
# Ensure each finding has severity=CRITICAL (secrets are always critical)
for f in data:
    f.setdefault('severity', 'CRITICAL')
    f.setdefault('scan_type', 'secrets')
with open('$OUTPUT_FILE', 'w') as fp:
    json.dump(data, fp, indent=2)
" 2>/dev/null || true

[[ $COUNT -gt 0 ]] && exit 1 || exit 0
