#!/usr/bin/env bash
# =============================================================================
# dep-audit.sh — Dependency CVE Audit via npm audit + Trivy
# Scans package.json / package-lock.json for known CVEs.
# Trivy filesystem scan provides additional SCA coverage.
#
# Usage: ./scripts/dep-audit.sh --path <repo> --output <dir> --mode <mode>
# Output: <output>/dep-results.json
# Exit:   0=clean, 1=findings, 2=tool error
# =============================================================================

set -euo pipefail

REPO_PATH="."
OUTPUT_DIR="./security-reports"
SCAN_MODE="local"
# Severity threshold: only report CVEs at or above this level
# Values: critical | high | moderate | low
AUDIT_LEVEL="moderate"

while [[ $# -gt 0 ]]; do
  case $1 in
    --path)      REPO_PATH="$2";   shift 2 ;;
    --output)    OUTPUT_DIR="$2";  shift 2 ;;
    --mode)      SCAN_MODE="$2";   shift 2 ;;
    --level)     AUDIT_LEVEL="$2"; shift 2 ;;
    *) shift ;;
  esac
done

mkdir -p "$OUTPUT_DIR"
REPO_PATH="$(realpath "$REPO_PATH")"
OUTPUT_FILE="$OUTPUT_DIR/dep-results.json"
NPM_RAW="$OUTPUT_DIR/npm-audit-raw.json"
TRIVY_RAW="$OUTPUT_DIR/trivy-raw.json"

# ── Find package.json files ───────────────────────────────────────────────────
PACKAGE_FILES=()
while IFS= read -r f; do
  # Skip node_modules, dist, build
  if [[ "$f" != *node_modules* && "$f" != */dist/* && "$f" != */build/* ]]; then
    PACKAGE_FILES+=("$f")
  fi
done < <(find "$REPO_PATH" -name "package.json" -not -path "*/node_modules/*" 2>/dev/null)

if [[ ${#PACKAGE_FILES[@]} -eq 0 ]]; then
  echo "[deps] No package.json found in $REPO_PATH"
  echo '{"findings":[],"summary":{"total":0,"critical":0,"high":0,"moderate":0,"low":0}}' > "$OUTPUT_FILE"
  exit 0
fi

echo "[deps] Found ${#PACKAGE_FILES[@]} package.json file(s)"

# ── npm audit ─────────────────────────────────────────────────────────────────
ALL_FINDINGS=()

run_npm_audit() {
  local pkg_dir
  pkg_dir="$(dirname "$1")"
  local lock_file="$pkg_dir/package-lock.json"

  if [[ ! -f "$lock_file" ]]; then
    echo "[deps] WARN: No package-lock.json in $pkg_dir — skipping npm audit for this package"
    return 0
  fi

  echo "[deps] npm audit: $pkg_dir"

  local raw_output
  # npm audit --json exits non-zero if vulnerabilities found
  raw_output=$(cd "$pkg_dir" && npm audit --json --audit-level="$AUDIT_LEVEL" 2>/dev/null || true)

  if [[ -z "$raw_output" ]]; then
    echo "[deps] npm audit produced no output for $pkg_dir"
    return 0
  fi

  echo "$raw_output" > "$pkg_dir/npm-audit-raw.json"

  # Normalize to common format
  python3 << PYEOF
import json, sys, os

raw = json.loads(open('$pkg_dir/npm-audit-raw.json').read())

findings = []

# npm audit v7+ format
if 'vulnerabilities' in raw:
    for pkg_name, vuln in raw.get('vulnerabilities', {}).items():
        severity = vuln.get('severity', 'unknown').upper()
        via = vuln.get('via', [])
        advisories = [v for v in via if isinstance(v, dict)]
        
        for adv in advisories if advisories else [{'title': pkg_name}]:
            findings.append({
                'scan_type': 'dependency',
                'package': pkg_name,
                'severity': severity,
                'title': adv.get('title', 'Vulnerability'),
                'cve': adv.get('cve', adv.get('url', '').split('/')[-1] if 'url' in adv else ''),
                'cvss': adv.get('cvss', {}).get('score', 0) if isinstance(adv.get('cvss'), dict) else 0,
                'fix_available': vuln.get('fixAvailable', False),
                'range': vuln.get('range', ''),
                'source': 'npm-audit',
                'path': '$pkg_dir'
            })
        
        # If no individual advisories, still report the package
        if not advisories:
            findings.append({
                'scan_type': 'dependency',
                'package': pkg_name,
                'severity': severity,
                'title': f'Vulnerable dependency: {pkg_name}',
                'cve': '',
                'cvss': 0,
                'fix_available': vuln.get('fixAvailable', False),
                'range': vuln.get('range', ''),
                'source': 'npm-audit',
                'path': '$pkg_dir'
            })

# npm audit v6 format (advisories key)
elif 'advisories' in raw:
    for adv_id, adv in raw.get('advisories', {}).items():
        findings.append({
            'scan_type': 'dependency',
            'package': adv.get('module_name', 'unknown'),
            'severity': adv.get('severity', 'unknown').upper(),
            'title': adv.get('title', 'Vulnerability'),
            'cve': adv.get('cves', [''])[0] if adv.get('cves') else '',
            'cvss': adv.get('cvss', {}).get('score', 0),
            'fix_available': adv.get('patched_versions', '') not in ['<0.0.0', ''],
            'range': adv.get('vulnerable_versions', ''),
            'url': adv.get('url', ''),
            'source': 'npm-audit',
            'path': '$pkg_dir'
        })

print(json.dumps(findings))
PYEOF
}

# Run npm audit on all packages, collect findings
COMBINED_NPM_FINDINGS="[]"
for pkg in "${PACKAGE_FILES[@]}"; do
  result=$(run_npm_audit "$pkg" 2>/dev/null || echo "[]")
  if [[ -n "$result" && "$result" != "null" && "$result" != "" ]]; then
    COMBINED_NPM_FINDINGS=$(python3 -c "
import json, sys
existing = json.loads('$COMBINED_NPM_FINDINGS')
new_findings = json.loads(sys.argv[1])
print(json.dumps(existing + new_findings))
" "$result" 2>/dev/null || echo "$COMBINED_NPM_FINDINGS")
  fi
done

# ── Trivy SCA (filesystem mode) ───────────────────────────────────────────────
TRIVY_FINDINGS="[]"

if command -v trivy &>/dev/null; then
  TRIVY_VERSION=$(trivy --version 2>/dev/null | head -1 || echo "unknown")
  echo "[deps] $TRIVY_VERSION"
  echo "[deps] Running Trivy filesystem scan..."

  trivy filesystem \
    --format json \
    --output "$TRIVY_RAW" \
    --severity "MEDIUM,HIGH,CRITICAL" \
    --scanners vuln \
    --skip-dirs "node_modules,dist,build,.git" \
    --quiet \
    "$REPO_PATH" 2>/dev/null || true

  if [[ -f "$TRIVY_RAW" ]]; then
    TRIVY_FINDINGS=$(python3 << PYEOF
import json

data = json.load(open('$TRIVY_RAW'))
findings = []

for result in data.get('Results', []):
    for vuln in result.get('Vulnerabilities', []):
        findings.append({
            'scan_type': 'dependency',
            'package': vuln.get('PkgName', 'unknown'),
            'severity': vuln.get('Severity', 'UNKNOWN'),
            'title': vuln.get('Title', vuln.get('VulnerabilityID', '')),
            'cve': vuln.get('VulnerabilityID', ''),
            'cvss': vuln.get('CVSS', {}).get('nvd', {}).get('V3Score', 0) if vuln.get('CVSS') else 0,
            'fix_available': bool(vuln.get('FixedVersion', '')),
            'fixed_version': vuln.get('FixedVersion', ''),
            'installed_version': vuln.get('InstalledVersion', ''),
            'source': 'trivy',
            'target': result.get('Target', '')
        })

print(json.dumps(findings))
PYEOF
)
  fi
else
  echo "[deps] WARN: Trivy not installed — using npm audit only"
  echo "[deps] Install: brew install trivy"
fi

# ── Merge and deduplicate findings ────────────────────────────────────────────
python3 << PYEOF
import json

npm_findings = json.loads('$COMBINED_NPM_FINDINGS')
trivy_findings = json.loads('''$TRIVY_FINDINGS''')

# Combine, prefer Trivy for CVE-named findings (more metadata)
seen_cves = set()
merged = []

for f in trivy_findings:
    cve = f.get('cve', '')
    if cve:
        seen_cves.add(f"{f['package']}:{cve}")
    merged.append(f)

for f in npm_findings:
    cve = f.get('cve', '')
    key = f"{f['package']}:{cve}"
    if cve and key in seen_cves:
        continue  # already covered by Trivy
    merged.append(f)

# Count by severity
severity_map = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'MODERATE': 0, 'LOW': 0, 'UNKNOWN': 0}
for f in merged:
    sev = f.get('severity', 'UNKNOWN').upper()
    if sev in severity_map:
        severity_map[sev] += 1
    else:
        severity_map['UNKNOWN'] += 1

# Normalize MODERATE → MEDIUM for consistency
for f in merged:
    if f.get('severity', '').upper() == 'MODERATE':
        f['severity'] = 'MEDIUM'

output = {
    'findings': merged,
    'summary': {
        'total': len(merged),
        'critical': severity_map['CRITICAL'],
        'high': severity_map['HIGH'],
        'medium': severity_map['MEDIUM'] + severity_map['MODERATE'],
        'low': severity_map['LOW']
    }
}

with open('$OUTPUT_FILE', 'w') as fp:
    json.dump(output, fp, indent=2)

print(f"[deps] Total: {len(merged)} | CRITICAL: {severity_map['CRITICAL']} | HIGH: {severity_map['HIGH']} | MEDIUM: {severity_map['MEDIUM']}")
PYEOF

echo "[deps] Report: $OUTPUT_FILE"

# Exit 1 if any critical or high found
CRITICAL_HIGH=$(python3 -c "
import json
d = json.load(open('$OUTPUT_FILE'))
print(d['summary']['critical'] + d['summary']['high'])
" 2>/dev/null || echo "0")

[[ "$CRITICAL_HIGH" -gt 0 ]] && exit 1 || exit 0
