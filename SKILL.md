---
name: security-scan
description: >
  Automated security scanning suite for GitLab CI/CD pipelines and pre-commit hooks.
  Covers SAST (Semgrep), secret detection (Gitleaks/TruffleHog), and dependency audit
  (npm audit / Trivy). Generates structured reports for MR blocking and pre-deploy gates.
allowed-tools: Read, Write, Bash, Glob, Grep
---

# Security Scan Skill

> Shift-left security: catch it before it ships, not after it burns.

## 📁 Skill Structure

```
security-scan-skill/
├── SKILL.md                        ← This file (entry point)
├── references/
│   ├── tools.md                    ← Tool selection guide & config references
│   ├── severity-matrix.md          ← Severity classification + blocking rules
│   └── false-positive-guide.md     ← Common FP patterns & suppression
├── scripts/
│   ├── scan-all.sh                 ← Master scan runner (calls all tools)
│   ├── sast-scan.sh                ← Semgrep SAST runner
│   ├── secret-scan.sh              ← Gitleaks + TruffleHog runner
│   ├── dep-audit.sh                ← npm audit + Trivy SCA runner
│   └── report-merge.sh             ← Merge JSON reports → unified output
├── templates/
│   ├── gitlab-ci.yml               ← GitLab CI job templates (MR + deploy)
│   ├── semgrep.yml                 ← Semgrep ruleset config
│   ├── gitleaks.toml               ← Gitleaks custom rules
│   ├── trivy.yaml                  ← Trivy scan config
│   └── .nvmrc-audit                ← Node version pin for audit jobs
└── hooks/
    ├── pre-commit                  ← Git pre-commit hook script
    └── install-hooks.sh            ← Hook installer for local dev
```

---

## 🎯 When to Use This Skill

| Trigger | Script/Config to Use | Blocking? |
|---------|---------------------|-----------|
| GitLab MR opened/updated | `templates/gitlab-ci.yml` → `security:mr-scan` job | CRITICAL/HIGH blocks merge |
| Pre-deploy to production | `templates/gitlab-ci.yml` → `security:pre-deploy` job | Any CRITICAL blocks deploy |
| Claude Code on-demand | `scripts/scan-all.sh` | Report only |
| Local pre-commit | `hooks/pre-commit` | Secrets only (fast) |

---

## 🔧 Tool Stack

| Scan Type | Primary Tool | Fallback | Format |
|-----------|-------------|---------|--------|
| SAST | Semgrep OSS | ESLint security plugins | SARIF + JSON |
| Secret Detection | Gitleaks | TruffleHog | JSON |
| Dependency CVE | `npm audit` | Trivy (filesystem) | JSON |
| IaC (future) | Trivy config | Checkov | JSON |

> **Why this stack?** All tools are OSS, no SaaS dependency, run offline in K8s pods,
> and output structured JSON suitable for GitLab Security Dashboard.

---

## 🚀 Quick Start

### 1. Install tools (once per runner/machine)

```bash
# Semgrep
pip install semgrep

# Gitleaks
brew install gitleaks         # macOS
# or
curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/main/scripts/install.sh | sh

# Trivy
brew install trivy            # macOS
# or
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# TruffleHog (optional fallback)
pip install trufflehog
```

### 2. Run full scan locally

```bash
chmod +x scripts/*.sh
./scripts/scan-all.sh --path . --output ./security-reports
```

### 3. Install pre-commit hook

```bash
chmod +x hooks/install-hooks.sh
./hooks/install-hooks.sh
```

### 4. Add to GitLab CI

```yaml
# In your .gitlab-ci.yml
include:
  - local: '.gitlab/security-scan.yml'
```

---

## 📊 Report Output

All scans produce a unified JSON report at `security-reports/summary.json`:

```json
{
  "scan_id": "gitlab-pipeline-12345",
  "timestamp": "2025-05-13T10:00:00Z",
  "repo": "giakho/oms",
  "branch": "feature/payment-v2",
  "summary": {
    "critical": 0,
    "high": 2,
    "medium": 5,
    "low": 12,
    "blocked": true,
    "block_reason": "2 HIGH findings in dependency audit"
  },
  "findings": [ ... ]
}
```

---

## 🚦 Blocking Logic

```
Pre-commit hook:
  └── Any secret detected → BLOCK commit

GitLab MR job:
  ├── CRITICAL (any scan) → BLOCK merge
  ├── HIGH (SAST or secret) → BLOCK merge
  └── HIGH (dep CVE, no fix available) → WARN only (not block)

Pre-deploy job:
  └── CRITICAL (any scan) → BLOCK deploy
```

> Rationale: HIGH dep CVE with no fix available should not perma-block MRs —
> create a tracking issue instead. Override with `SECURITY_OVERRIDE=true` env var
> (requires maintainer role, logged in audit trail).

---

## 🔕 Suppression / False Positive Handling

Inline suppression (use sparingly, requires justification comment):

```typescript
// nosemgrep: typescript.lang.security.audit.something
const result = dangerousButIntentional();
```

```bash
# gitleaks:allow
EXAMPLE_API_KEY="not-a-real-key-just-docs"
```

For systematic FPs → see `references/false-positive-guide.md`

---

## 📋 Claude Code Agent Instructions

When invoked as a Claude Code agent for security scanning:

### Phase 1 — Recon
1. Read `package.json` / `package-lock.json` to understand dep tree
2. Glob for `.env*`, `*.config.*`, `*.yaml`, `*.yml` files
3. Identify entry points: controllers, resolvers, middleware

### Phase 2 — Automated Scan
```bash
./scripts/scan-all.sh --path <repo_root> --output ./security-reports
```

### Phase 3 — AI Analysis
For each finding in `security-reports/summary.json`:
1. Read the flagged file + surrounding context (±20 lines)
2. Determine: real vulnerability or false positive?
3. Assess exploitability in THIS codebase's context
4. Generate remediation diff if fixable

### Phase 4 — Report
Output structured findings to `security-reports/claude-analysis.md` using
the template in `templates/claude-report-template.md`

### DO NOT
- Auto-fix CRITICAL findings without human review
- Suppress findings without documented justification
- Run `npm install` or modify `package-lock.json` during scan
