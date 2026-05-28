#!/usr/bin/env bash
# =============================================================================
# scan-all.sh — Master Security Scan Runner
# Runs SAST, secret detection, and dependency audit sequentially.
# Merges results into a unified report and exits with appropriate code.
#
# Usage:
#   ./scripts/scan-all.sh [OPTIONS]
#
# Options:
#   --path PATH       Root path of repo to scan (default: current dir)
#   --output DIR      Output directory for reports (default: ./security-reports)
#   --mode MODE       Scan mode: 'mr' | 'predeploy' | 'local' (default: local)
#   --branch BRANCH   Current branch name (for report metadata)
#   --skip SCAN       Skip a scan type: sast | secrets | deps (repeatable)
#   --fail-on LEVEL   Fail exit code on: critical | high | medium (default: high)
#
# Exit codes:
#   0 = Clean (no findings at or above --fail-on level)
#   1 = Findings found at or above --fail-on level
#   2 = Tool not installed / scan error
# =============================================================================

set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────
REPO_PATH="."
OUTPUT_DIR="./security-reports"
SCAN_MODE="local"
BRANCH="${CI_COMMIT_BRANCH:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')}"
FAIL_ON="high"
SKIP_SCANS=()
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --path)    REPO_PATH="$2";   shift 2 ;;
    --output)  OUTPUT_DIR="$2";  shift 2 ;;
    --mode)    SCAN_MODE="$2";   shift 2 ;;
    --branch)  BRANCH="$2";      shift 2 ;;
    --skip)    SKIP_SCANS+=("$2"); shift 2 ;;
    --fail-on) FAIL_ON="$2";     shift 2 ;;
    *) echo "Unknown option: $1"; exit 2 ;;
  esac
done

REPO_PATH="$(realpath "$REPO_PATH")"
mkdir -p "$OUTPUT_DIR"

# ── Helpers ──────────────────────────────────────────────────────────────────
log()  { echo -e "${BLUE}[SCAN]${RESET} $*"; }
ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
fail() { echo -e "${RED}[✗]${RESET} $*"; }

should_skip() { [[ " ${SKIP_SCANS[*]} " =~ " $1 " ]]; }

# ── Metadata ─────────────────────────────────────────────────────────────────
SCAN_ID="${CI_PIPELINE_ID:-local-$(date +%s)}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REPO_NAME="$(basename "$REPO_PATH")"

echo -e "\n${BOLD}════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Security Scan Suite${RESET}"
echo -e "${BOLD}  Repo:   ${RESET}$REPO_NAME"
echo -e "${BOLD}  Branch: ${RESET}$BRANCH"
echo -e "${BOLD}  Mode:   ${RESET}$SCAN_MODE"
echo -e "${BOLD}  Output: ${RESET}$OUTPUT_DIR"
echo -e "${BOLD}════════════════════════════════════════${RESET}\n"

# ── Run individual scans ─────────────────────────────────────────────────────
EXIT_CODES=()

run_scan() {
  local name="$1"
  local script="$2"
  shift 2

  if should_skip "$name"; then
    warn "Skipping $name scan (--skip flag)"
    return 0
  fi

  log "Starting $name scan..."
  if bash "$SCRIPT_DIR/$script" \
      --path "$REPO_PATH" \
      --output "$OUTPUT_DIR" \
      "$@"; then
    ok "$name scan completed"
    EXIT_CODES+=("0")
  else
    local code=$?
    if [[ $code -eq 1 ]]; then
      warn "$name scan found issues (exit $code)"
      EXIT_CODES+=("1")
    else
      fail "$name scan encountered an error (exit $code)"
      EXIT_CODES+=("2")
    fi
  fi
}

run_scan "sast"         "sast-scan.sh"         --mode "$SCAN_MODE"
run_scan "secrets"      "secret-scan.sh"       --mode "$SCAN_MODE"
run_scan "deps"         "dep-audit.sh"         --mode "$SCAN_MODE"
run_scan "slopsquat"    "slopsquatting-scan.sh" --mode "$SCAN_MODE"

# ── Merge reports ─────────────────────────────────────────────────────────────
log "Merging scan reports..."
bash "$SCRIPT_DIR/report-merge.sh" \
  --input "$OUTPUT_DIR" \
  --scan-id "$SCAN_ID" \
  --timestamp "$TIMESTAMP" \
  --repo "$REPO_NAME" \
  --branch "$BRANCH" \
  --mode "$SCAN_MODE" \
  --fail-on "$FAIL_ON"

MERGE_EXIT=$?

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════${RESET}"

if [[ -f "$OUTPUT_DIR/summary.json" ]]; then
  CRITICAL=$(python3 -c "import json,sys; d=json.load(open('$OUTPUT_DIR/summary.json')); print(d['summary']['critical'])" 2>/dev/null || echo "?")
  HIGH=$(python3     -c "import json,sys; d=json.load(open('$OUTPUT_DIR/summary.json')); print(d['summary']['high'])"     2>/dev/null || echo "?")
  MEDIUM=$(python3   -c "import json,sys; d=json.load(open('$OUTPUT_DIR/summary.json')); print(d['summary']['medium'])"   2>/dev/null || echo "?")
  LOW=$(python3      -c "import json,sys; d=json.load(open('$OUTPUT_DIR/summary.json')); print(d['summary']['low'])"      2>/dev/null || echo "?")
  BLOCKED=$(python3  -c "import json,sys; d=json.load(open('$OUTPUT_DIR/summary.json')); print(d['summary']['blocked'])"  2>/dev/null || echo "false")

  echo -e "  ${RED}Critical: $CRITICAL${RESET}  |  ${YELLOW}High: $HIGH${RESET}  |  Medium: $MEDIUM  |  Low: $LOW"
  echo ""

  if [[ "$BLOCKED" == "True" || "$BLOCKED" == "true" ]]; then
    fail "Pipeline BLOCKED — see $OUTPUT_DIR/summary.json"
  else
    ok "Pipeline CLEAN — no blocking findings"
  fi
fi

echo -e "${BOLD}  Report:  ${RESET}$OUTPUT_DIR/summary.json"
echo -e "${BOLD}════════════════════════════════════════${RESET}\n"

exit $MERGE_EXIT
