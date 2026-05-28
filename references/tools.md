# Tools Reference Guide

## Tool Selection Rationale

| Tool | Version | Purpose | Why This Tool |
|------|---------|---------|---------------|
| **Semgrep OSS** | Latest | SAST | Free, offline, excellent TS/NestJS rules, SARIF output for GitLab |
| **Gitleaks** | 8.x | Secret detection | Fast, git-native, highly configurable, no SaaS required |
| **TruffleHog** | 3.x | Secret fallback | Deep entropy analysis, handles encoded secrets |
| **npm audit** | Built-in | Dependency CVE | Zero setup, uses npm advisory DB |
| **Trivy** | Latest | SCA + IaC | OSS, Aqua DB, excellent CVE coverage, works offline |

## Tool Install Reference

### macOS (Apple Silicon — your setup)

```bash
# Semgrep
pip3 install semgrep

# Gitleaks
brew install gitleaks
# verify: gitleaks version

# Trivy
brew install trivy
# or from script:
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# TruffleHog (optional)
brew install trufflehog
# or: pip3 install trufflehog
```

### GitLab CI Runner (Debian/Ubuntu)

```bash
# Semgrep
pip install semgrep

# Gitleaks — from GitHub releases
GITLEAKS_VERSION="8.18.2"
curl -sSfL \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
  | tar -xz -C /usr/local/bin gitleaks

# Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin

# Verify all
semgrep --version
gitleaks version
trivy --version
```

### Docker image for CI (fastest option)

Use `aquasec/trivy` or build a custom image:

```dockerfile
FROM python:3.11-slim
RUN pip install semgrep && \
    apt-get update && apt-get install -y curl && \
    # Gitleaks
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks && \
    # Trivy
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin
```

---

## Semgrep Ruleset Reference

| Ruleset | Coverage | MR | Pre-deploy |
|---------|---------|-----|-----------|
| `p/typescript` | TS-specific vulnerabilities | ✅ | ✅ |
| `p/nodejs` | Node.js-specific patterns | ✅ | ✅ |
| `p/owasp-top-ten` | OWASP A01–A10 | ✅ | ✅ |
| `p/jwt` | JWT misconfiguration | ✅ | ✅ |
| `p/secrets` | Hardcoded secrets | ✅ | ✅ |
| `p/sql-injection` | SQLi patterns | ❌ | ✅ |
| `p/xss` | XSS patterns | ❌ | ✅ |
| `p/injection` | General injection | ❌ | ✅ |
| `templates/semgrep.yml` | Custom NestJS rules | ✅ | ✅ |

## Trivy DB Update

```bash
# Cache Trivy vulnerability DB in CI
# Add to .gitlab-ci.yml cache:
cache:
  key: trivy-db
  paths:
    - .trivy-cache/
  
# In script:
trivy --cache-dir .trivy-cache filesystem .
```

## Gitleaks vs TruffleHog

| Feature | Gitleaks | TruffleHog |
|---------|---------|-----------|
| Git history scan | ✅ | ✅ |
| Staged files | ✅ (--staged) | ❌ |
| Entropy analysis | ✅ | ✅✅ (better) |
| Custom rules | TOML config | Detectors |
| Speed | ⚡ Fast | 🐢 Slower |
| CI integration | ✅ | ✅ |

**Recommendation**: Use Gitleaks as primary. TruffleHog as secondary scan for high-security repos.
