#!/usr/bin/env bash
# =============================================================================
# report-merge.sh — Merge all scan JSONs into unified summary.json
# Applies blocking logic based on mode and fail-on level.
#
# Usage: ./scripts/report-merge.sh --input <dir> --scan-id <id> ...
# Output: <input>/summary.json
# Exit:   0=not blocked, 1=blocked
# =============================================================================

set -euo pipefail

INPUT_DIR="./security-reports"
SCAN_ID="unknown"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REPO="unknown"
BRANCH="unknown"
SCAN_MODE="local"
FAIL_ON="high"

while [[ $# -gt 0 ]]; do
  case $1 in
    --input)     INPUT_DIR="$2";  shift 2 ;;
    --scan-id)   SCAN_ID="$2";    shift 2 ;;
    --timestamp) TIMESTAMP="$2";  shift 2 ;;
    --repo)      REPO="$2";       shift 2 ;;
    --branch)    BRANCH="$2";     shift 2 ;;
    --mode)      SCAN_MODE="$2";  shift 2 ;;
    --fail-on)   FAIL_ON="$2";    shift 2 ;;
    *) shift ;;
  esac
done

python3 << PYEOF
import json, os, sys

input_dir = "$INPUT_DIR"
scan_id   = "$SCAN_ID"
timestamp = "$TIMESTAMP"
repo      = "$REPO"
branch    = "$BRANCH"
mode      = "$SCAN_MODE"
fail_on   = "$FAIL_ON"  # critical | high | medium

SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'MODERATE', 'LOW', 'UNKNOWN']

def normalize_severity(s):
    s = (s or 'UNKNOWN').upper()
    return 'MEDIUM' if s == 'MODERATE' else s

def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        return json.load(open(path))
    except:
        return default

# ── Load scan outputs ─────────────────────────────────────────────────────────
sast_raw    = load_json(f"{input_dir}/sast-results.json",          {"results": []})
secret_raw  = load_json(f"{input_dir}/secret-results.json",        [])
dep_raw     = load_json(f"{input_dir}/dep-results.json",           {"findings": []})
slop_raw    = load_json(f"{input_dir}/slopsquatting-results.json", {"findings": []})

all_findings = []

# ── Normalize SAST (Semgrep format) ──────────────────────────────────────────
sast_results = sast_raw.get('results', []) if isinstance(sast_raw, dict) else []
for r in sast_results:
    extra = r.get('extra', {})
    metadata = extra.get('metadata', {})
    severity_raw = extra.get('severity', metadata.get('severity', 'INFO'))
    # Semgrep: ERROR→HIGH, WARNING→MEDIUM, INFO→LOW
    sev_map = {'ERROR': 'HIGH', 'WARNING': 'MEDIUM', 'INFO': 'LOW', 'CRITICAL': 'CRITICAL'}
    severity = sev_map.get(severity_raw.upper(), normalize_severity(severity_raw))

    all_findings.append({
        'scan_type': 'sast',
        'severity': severity,
        'rule_id': r.get('check_id', ''),
        'title': extra.get('message', r.get('check_id', 'SAST Finding')),
        'file': r.get('path', ''),
        'line_start': r.get('start', {}).get('line', 0),
        'line_end': r.get('end', {}).get('line', 0),
        'code_snippet': extra.get('lines', '').strip(),
        'cwe': metadata.get('cwe', []),
        'owasp': metadata.get('owasp', []),
        'references': metadata.get('references', []),
        'fix_guidance': metadata.get('message', extra.get('fix', '')),
        'source': 'semgrep'
    })

# ── Normalize Secrets (Gitleaks format) ──────────────────────────────────────
secrets_list = secret_raw if isinstance(secret_raw, list) else []
for s in secrets_list:
    all_findings.append({
        'scan_type': 'secret',
        'severity': 'CRITICAL',  # All secrets = CRITICAL
        'rule_id': s.get('RuleID', s.get('ruleId', 'secret-detected')),
        'title': s.get('Description', s.get('description', 'Secret detected')),
        'file': s.get('File', s.get('file', '')),
        'line_start': s.get('StartLine', s.get('line', 0)),
        'commit': s.get('Commit', ''),
        'author': s.get('Author', ''),
        'secret_redacted': '[REDACTED]',
        'tags': s.get('Tags', []),
        'source': 'gitleaks'
    })

# ── Normalize Deps ────────────────────────────────────────────────────────────
dep_findings = dep_raw.get('findings', dep_raw) if isinstance(dep_raw, dict) else dep_raw
dep_findings = dep_findings if isinstance(dep_findings, list) else []
for d in dep_findings:
    all_findings.append({
        'scan_type': 'dependency',
        'severity': normalize_severity(d.get('severity', 'UNKNOWN')),
        'package': d.get('package', ''),
        'title': d.get('title', f"Vulnerability in {d.get('package','')}"),
        'cve': d.get('cve', ''),
        'cvss': d.get('cvss', 0),
        'fix_available': d.get('fix_available', False),
        'fixed_version': d.get('fixed_version', ''),
        'installed_version': d.get('installed_version', ''),
        'source': d.get('source', 'audit')
    })

# ── Normalize Slopsquatting ───────────────────────────────────────────────────
slop_findings = slop_raw.get('findings', []) if isinstance(slop_raw, dict) else []
for s in slop_findings:
    layer = s.get('layer', 1)
    signals = s.get('signals', [])
    signal_summary = '; '.join(sig.get('detail', '') for sig in signals) if signals else ''
    all_findings.append({
        'scan_type': 'slopsquatting',
        'severity': normalize_severity(s.get('severity', 'HIGH')),
        'package': s.get('package', ''),
        'title': s.get('title', ''),
        'issue': s.get('issue', ''),
        'layer': layer,
        'signals': signals,
        'signal_summary': signal_summary,
        'recommendation': s.get('recommendation', ''),
        'npm_url': s.get('npm_url', ''),
        'source_file': s.get('source_file', ''),
        'source': f'slopsquat-layer{layer}'
    })

# ── Count by severity ─────────────────────────────────────────────────────────
counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
for f in all_findings:
    sev = f.get('severity', 'LOW').upper()
    if sev in counts:
        counts[sev] += 1
    elif sev in ('MODERATE',):
        counts['MEDIUM'] += 1

# ── Blocking logic ────────────────────────────────────────────────────────────
# Secrets → always CRITICAL → always block
# MR mode:
#   - CRITICAL (any) → block
#   - HIGH SAST/secret → block
#   - HIGH dep with fix_available → block
#   - HIGH dep no fix → warn only
# Pre-deploy:
#   - Any CRITICAL → block
# Local / on-demand:
#   - Never auto-block (report only)

blocked = False
block_reason = ""

if mode in ('mr', 'predeploy'):
    if counts['CRITICAL'] > 0:
        blocked = True
        block_reason = f"{counts['CRITICAL']} CRITICAL finding(s) detected"
    elif fail_on in ('high',) and counts['HIGH'] > 0:
        # For deps, only block if fix is available
        high_non_dep = [f for f in all_findings 
                        if f.get('severity','').upper() == 'HIGH' 
                        and f.get('scan_type') != 'dependency']
        high_dep_fixable = [f for f in all_findings 
                            if f.get('severity','').upper() == 'HIGH' 
                            and f.get('scan_type') == 'dependency'
                            and f.get('fix_available', False)]
        if high_non_dep or high_dep_fixable:
            blocked = True
            block_reason = f"{len(high_non_dep + high_dep_fixable)} HIGH finding(s) with available remediation"
    elif fail_on == 'medium' and counts['MEDIUM'] > 0:
        blocked = True
        block_reason = f"{counts['MEDIUM']} MEDIUM finding(s) detected"

# ── Sort findings: CRITICAL first ────────────────────────────────────────────
sev_order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
all_findings.sort(key=lambda f: sev_order.get(f.get('severity','UNKNOWN').upper(), 99))

# ── Write summary.json ────────────────────────────────────────────────────────
summary = {
    'scan_id': scan_id,
    'timestamp': timestamp,
    'repo': repo,
    'branch': branch,
    'mode': mode,
    'summary': {
        'critical': counts['CRITICAL'],
        'high': counts['HIGH'],
        'medium': counts['MEDIUM'],
        'low': counts['LOW'],
        'total': len(all_findings),
        'blocked': blocked,
        'block_reason': block_reason,
        'scans_run': [
            'sast' if sast_results else None,
            'secrets' if secrets_list else None,
            'deps' if dep_findings else None
        ]
    },
    'findings': all_findings
}

output_path = f"{input_dir}/summary.json"
with open(output_path, 'w') as fp:
    json.dump(summary, fp, indent=2)

# Print summary table
print(f"[merge] Scan complete: {len(all_findings)} total findings")
print(f"[merge] CRITICAL={counts['CRITICAL']} HIGH={counts['HIGH']} MEDIUM={counts['MEDIUM']} LOW={counts['LOW']}")
if blocked:
    print(f"[merge] BLOCKED: {block_reason}")
    sys.exit(1)
else:
    print("[merge] PASSED: No blocking findings")
    sys.exit(0)
PYEOF
