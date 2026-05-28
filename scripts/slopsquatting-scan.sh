#!/usr/bin/env bash
# =============================================================================
# slopsquatting-scan.sh — Detect hallucinated & suspicious npm packages
#
# Layer 1: Check if package actually exists on npm registry
# Layer 2: Check package reputation signals (new, low downloads, typosquat)
#
# Usage: ./scripts/slopsquatting-scan.sh --path <repo> --output <dir>
# Output: <output>/slopsquatting-results.json
# Exit:   0=clean, 1=suspicious found, 2=tool error
# =============================================================================

set -euo pipefail

REPO_PATH="."
OUTPUT_DIR="./security-reports"
SCAN_MODE="local"
# Layer 2 thresholds
MIN_WEEKLY_DOWNLOADS=100      # packages below this are suspicious
MAX_PACKAGE_AGE_DAYS=30       # packages newer than this are suspicious
MAX_EDIT_DISTANCE=2           # Levenshtein distance for typosquat detection
USE_SOCKET=false              # set true if socket.dev CLI available

while [[ $# -gt 0 ]]; do
  case $1 in
    --path)   REPO_PATH="$2";  shift 2 ;;
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    --mode)   SCAN_MODE="$2";  shift 2 ;;
    --socket) USE_SOCKET=true; shift ;;
    *) shift ;;
  esac
done

mkdir -p "$OUTPUT_DIR"
REPO_PATH="$(realpath "$REPO_PATH")"
OUTPUT_FILE="$OUTPUT_DIR/slopsquatting-results.json"

echo "[slopsquat] Scanning dependencies in $REPO_PATH"

# ── Find all package.json files ───────────────────────────────────────────────
PACKAGE_FILES=()
while IFS= read -r f; do
  [[ "$f" != *node_modules* && "$f" != */dist/* ]] && PACKAGE_FILES+=("$f")
done < <(find "$REPO_PATH" -name "package.json" -not -path "*/node_modules/*" 2>/dev/null)

if [[ ${#PACKAGE_FILES[@]} -eq 0 ]]; then
  echo "[slopsquat] No package.json found"
  echo '{"findings":[],"summary":{"total":0,"layer1_fake":0,"layer2_suspicious":0}}' > "$OUTPUT_FILE"
  exit 0
fi

# ── Layer 2: Socket.dev CLI (if available) ────────────────────────────────────
run_socket_scan() {
  if ! command -v socket &>/dev/null; then
    echo "[slopsquat] socket CLI not installed — skipping"
    echo "[slopsquat] Install: npm install -g @socketsecurity/cli"
    return 0
  fi

  echo "[slopsquat] Running Socket.dev supply chain scan..."
  local pkg_dir
  pkg_dir="$(dirname "$1")"

  socket scan create \
    --outputFormat json \
    --outputFile "$OUTPUT_DIR/socket-raw.json" \
    "$pkg_dir/package.json" 2>/dev/null || true

  echo "[slopsquat] Socket scan complete"
}

# ── Main Python scan logic ────────────────────────────────────────────────────
python3 << PYEOF
import json, urllib.request, urllib.error, os, sys, time
from datetime import datetime, timezone

REPO_PATH        = "$REPO_PATH"
OUTPUT_DIR       = "$OUTPUT_DIR"
OUTPUT_FILE      = "$OUTPUT_FILE"
MIN_DOWNLOADS    = $MIN_WEEKLY_DOWNLOADS
MAX_AGE_DAYS     = $MAX_PACKAGE_AGE_DAYS
MAX_EDIT_DIST    = $MAX_EDIT_DISTANCE

# ── Top 200 npm packages for typosquat comparison ───────────────────────────
TOP_NPM_PACKAGES = [
    "lodash","express","react","react-dom","axios","moment","chalk","commander",
    "typescript","webpack","babel-core","eslint","prettier","jest","mocha",
    "nodemon","dotenv","cors","helmet","morgan","body-parser","jsonwebtoken",
    "bcrypt","bcryptjs","passport","mongoose","sequelize","typeorm","prisma",
    "nestjs","@nestjs/core","@nestjs/common","@nestjs/platform-express",
    "rxjs","reflect-metadata","class-validator","class-transformer",
    "pg","pg-pool","redis","ioredis","bull","bullmq",
    "uuid","nanoid","dayjs","date-fns","luxon",
    "multer","sharp","jimp","nodemailer","twilio",
    "winston","pino","morgan","debug",
    "supertest","sinon","chai","nock","faker","@faker-js/faker",
    "socket.io","ws","http-proxy","http-proxy-middleware",
    "compression","cookie-parser","express-session","connect-flash",
    "tslib","tsconfig-paths","ts-node","ts-jest",
    "cross-env","rimraf","concurrently","husky","lint-staged",
    "semver","glob","minimatch","micromatch","chokidar",
    "tar","archiver","adm-zip","jszip","node-cron","cron",
    "aws-sdk","@aws-sdk/client-s3","@aws-sdk/client-ses",
    "firebase","firebase-admin","googleapis",
    "stripe","paypal-rest-sdk","qrcode","speakeasy",
]

def levenshtein(s1, s2):
    """Calculate edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(c1!=c2)))
        prev = curr
    return prev[-1]

def fetch_npm_info(package_name):
    """Fetch package metadata from npm registry."""
    # Handle scoped packages (@org/pkg)
    encoded = package_name.replace('/', '%2F') if package_name.startswith('@') else package_name
    url = f"https://registry.npmjs.org/{encoded}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'security-scanner/1.0'})
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read()), None
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, "NOT_FOUND"
        return None, f"HTTP_{e.code}"
    except Exception as e:
        return None, str(e)

def fetch_npm_downloads(package_name):
    """Fetch weekly download count from npm API."""
    encoded = package_name.replace('/', '%2F') if package_name.startswith('@') else package_name
    url = f"https://api.npmjs.org/downloads/point/last-week/{encoded}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'security-scanner/1.0'})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
            return data.get('downloads', 0)
    except:
        return -1  # -1 = unknown

def get_package_deps(pkg_json_path):
    """Extract all dependencies from package.json."""
    try:
        data = json.load(open(pkg_json_path))
        deps = {}
        deps.update(data.get('dependencies', {}))
        deps.update(data.get('devDependencies', {}))
        return deps, data.get('name', os.path.dirname(pkg_json_path))
    except:
        return {}, 'unknown'

def find_typosquat_targets(pkg_name):
    """Find known packages this name might be squatting."""
    # Strip scope for comparison
    clean_name = pkg_name.split('/')[-1] if '/' in pkg_name else pkg_name
    targets = []
    for known in TOP_NPM_PACKAGES:
        clean_known = known.split('/')[-1] if '/' in known else known
        dist = levenshtein(clean_name.lower(), clean_known.lower())
        if 0 < dist <= MAX_EDIT_DIST and len(clean_name) > 3:
            targets.append({'package': known, 'distance': dist})
    return sorted(targets, key=lambda x: x['distance'])

# ── Collect all unique packages ────────────────────────────────────────────────
all_packages = {}
PACKAGE_FILES = "$OUTPUT_DIR/../".replace("../", "")

pkg_files = []
for root, dirs, files in os.walk(REPO_PATH):
    dirs[:] = [d for d in dirs if d not in ('node_modules', 'dist', 'build', '.git')]
    for f in files:
        if f == 'package.json':
            pkg_files.append(os.path.join(root, f))

for pkg_path in pkg_files:
    deps, source = get_package_deps(pkg_path)
    for name, version in deps.items():
        if name not in all_packages:
            all_packages[name] = {'version': version, 'source': pkg_path}

print(f"[slopsquat] Found {len(all_packages)} unique packages to check")
print(f"[slopsquat] Layer 1: existence check | Layer 2: reputation signals")

findings = []
layer1_fake = 0
layer2_suspicious = 0
checked = 0

for pkg_name, pkg_info in all_packages.items():
    checked += 1
    if checked % 10 == 0:
        print(f"[slopsquat] Progress: {checked}/{len(all_packages)}")

    # Small delay to avoid rate limiting
    if checked > 1:
        time.sleep(0.1)

    # ── Layer 1: Does the package exist? ─────────────────────────────────────
    npm_data, error = fetch_npm_info(pkg_name)

    if error == "NOT_FOUND":
        layer1_fake += 1
        # Check for typosquat targets
        typo_targets = find_typosquat_targets(pkg_name)
        findings.append({
            'layer': 1,
            'scan_type': 'slopsquatting',
            'severity': 'CRITICAL',
            'package': pkg_name,
            'version': pkg_info['version'],
            'source_file': pkg_info['source'],
            'issue': 'PACKAGE_NOT_FOUND',
            'title': f"Package '{pkg_name}' does not exist on npm registry",
            'description': (
                f"This package is not registered on npm. It may be an AI hallucination "
                f"(slopsquatting risk). A malicious actor could register this name with malware. "
                + (f"Similar known packages: {[t['package'] for t in typo_targets[:3]]}" if typo_targets else "")
            ),
            'recommendation': f"Verify '{pkg_name}' is the correct package name. Check npmjs.com manually.",
            'typosquat_targets': typo_targets[:3]
        })
        continue

    if error:
        print(f"[slopsquat] WARN: Could not check {pkg_name}: {error}")
        continue

    # Package exists — Layer 2 checks
    signals = []

    # Signal 1: Publication date (new package)
    try:
        created_str = npm_data.get('time', {}).get('created', '')
        if created_str:
            created = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
            age_days = (datetime.now(timezone.utc) - created).days
            if age_days < MAX_AGE_DAYS:
                signals.append({
                    'type': 'new_package',
                    'detail': f"Published {age_days} days ago (threshold: {MAX_AGE_DAYS} days)"
                })
    except:
        pass

    # Signal 2: Weekly downloads (low popularity)
    weekly_downloads = fetch_npm_downloads(pkg_name)
    if 0 <= weekly_downloads < MIN_DOWNLOADS:
        signals.append({
            'type': 'low_downloads',
            'detail': f"Only {weekly_downloads} downloads/week (threshold: {MIN_DOWNLOADS})"
        })

    # Signal 3: Typosquatting similarity to known packages
    typo_targets = find_typosquat_targets(pkg_name)
    if typo_targets:
        best_match = typo_targets[0]
        signals.append({
            'type': 'typosquat_candidate',
            'detail': f"Edit distance {best_match['distance']} from '{best_match['package']}'"
        })

    # Signal 4: No dependents (nobody uses this package)
    dependents_count = len(npm_data.get('users', {}))
    if dependents_count == 0 and weekly_downloads < 1000:
        signals.append({
            'type': 'no_dependents',
            'detail': "Package has 0 known dependents and low download count"
        })

    # Signal 5: Single maintainer + new account (can't check account age via public API easily)
    maintainers = npm_data.get('maintainers', [])
    if len(maintainers) == 1:
        signals.append({
            'type': 'single_maintainer',
            'detail': f"Single maintainer: {maintainers[0].get('name', 'unknown')}"
        })

    # Evaluate combined signal score
    # Need 2+ signals to flag (reduce false positives)
    HIGH_RISK_SIGNALS = {'typosquat_candidate', 'new_package', 'no_dependents'}
    high_risk_count = sum(1 for s in signals if s['type'] in HIGH_RISK_SIGNALS)
    total_signals = len(signals)

    if high_risk_count >= 2 or (high_risk_count >= 1 and total_signals >= 3):
        layer2_suspicious += 1
        severity = 'HIGH' if high_risk_count >= 2 else 'MEDIUM'
        findings.append({
            'layer': 2,
            'scan_type': 'slopsquatting',
            'severity': severity,
            'package': pkg_name,
            'version': pkg_info['version'],
            'source_file': pkg_info['source'],
            'issue': 'SUSPICIOUS_PACKAGE',
            'title': f"Suspicious package '{pkg_name}' — {total_signals} risk signal(s)",
            'signals': signals,
            'recommendation': (
                f"Manually verify '{pkg_name}' on npmjs.com. "
                f"Check: is this the real package? Is the maintainer legitimate? "
                f"Review source code at: https://npmjs.com/package/{pkg_name}"
            ),
            'npm_url': f"https://npmjs.com/package/{pkg_name}",
            'weekly_downloads': weekly_downloads
        })

# ── Output ────────────────────────────────────────────────────────────────────
summary = {
    'findings': findings,
    'summary': {
        'total': len(findings),
        'packages_checked': len(all_packages),
        'layer1_fake': layer1_fake,
        'layer2_suspicious': layer2_suspicious,
    }
}

with open(OUTPUT_FILE, 'w') as fp:
    json.dump(summary, fp, indent=2)

print(f"[slopsquat] Complete: {layer1_fake} fake packages, {layer2_suspicious} suspicious packages")
print(f"[slopsquat] Report: {OUTPUT_FILE}")

# Exit 1 if any findings
sys.exit(1 if findings else 0)
PYEOF

SCAN_EXIT=$?

# ── Optional: Socket.dev Layer 2 supplement ───────────────────────────────────
if [[ "$USE_SOCKET" == "true" ]]; then
  for pkg in "${PACKAGE_FILES[@]}"; do
    run_socket_scan "$pkg"
  done
fi

exit $SCAN_EXIT
