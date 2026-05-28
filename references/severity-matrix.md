# Severity Matrix & Blocking Rules

## Severity Classification

| Severity | CVSS Range | Examples | SLA |
|----------|-----------|---------|-----|
| **CRITICAL** | 9.0–10.0 | RCE, auth bypass, exposed DB credentials, leaked prod secrets | Block immediately |
| **HIGH** | 7.0–8.9 | SQL injection, SSRF, hardcoded JWT secret, CVE with fix available | Block MR / 24h fix |
| **MEDIUM** | 4.0–6.9 | Missing security headers, verbose error messages, weak crypto | 7-day fix cycle |
| **LOW** | 0.1–3.9 | Informational, best practice deviation, code quality | Next sprint |

---

## Blocking Logic by Trigger

### Pre-commit Hook

| Finding Type | Blocking? | Reason |
|-------------|-----------|--------|
| Secret (any severity) | **YES — always** | Secrets in git = permanent exposure |
| SAST CRITICAL/ERROR | YES | Block before commit |
| SAST WARNING | No | Warning only |
| Dep CVE | No | Not run in pre-commit (slow) |

### GitLab MR Job (`security:mr-scan`)

| Finding Type | Severity | Blocking? | Notes |
|-------------|----------|-----------|-------|
| Secret detected | CRITICAL | **YES** | Always block |
| SAST finding | CRITICAL | YES | |
| SAST finding | HIGH | YES | |
| SAST finding | MEDIUM | NO | Comment on MR |
| Dep CVE | CRITICAL | YES | |
| Dep CVE | HIGH + fix available | YES | Fix exists → must fix |
| Dep CVE | HIGH + no fix | NO | Create issue, warn |
| Dep CVE | MEDIUM | NO | Comment on MR |

### Pre-deploy Pipeline (`security:pre-deploy`)

| Finding Type | Severity | Blocking? |
|-------------|----------|-----------|
| Any scan | CRITICAL | **YES — always** |
| SAST/Secret | HIGH | YES |
| Dep CVE | HIGH | YES (regardless of fix availability) |
| Any | MEDIUM | NO (logged) |

---

## Override Policy

```
SECURITY_OVERRIDE=true
```

**Who can use**: Maintainer role only (enforce via GitLab protected variable)
**When allowed**:
- CVE with no available fix AND business deadline
- False positive confirmed by security review
- Emergency hotfix (must be followed by proper fix in ≤48h)

**What happens**:
- Override is logged with username + timestamp in CI job
- Creates automatic issue: "Security override used — pipeline: #XXX"
- Requires comment in MR explaining override rationale

**Who cannot use**:
- Developer role — override rejected at CI level

---

## Severity Mapping by Tool

### Semgrep → Unified

| Semgrep Severity | Unified Severity |
|-----------------|-----------------|
| `ERROR` | HIGH |
| `WARNING` | MEDIUM |
| `INFO` | LOW |

> Note: Semgrep doesn't emit CRITICAL natively. Custom rules in `semgrep.yml`
> can use `severity: CRITICAL` which maps 1:1.

### npm audit → Unified

| npm audit | Unified |
|-----------|---------|
| `critical` | CRITICAL |
| `high` | HIGH |
| `moderate` | MEDIUM |
| `low` | LOW |

### Trivy → Unified

| Trivy | Unified |
|-------|---------|
| `CRITICAL` | CRITICAL |
| `HIGH` | HIGH |
| `MEDIUM` | MEDIUM |
| `LOW` | LOW |
| `UNKNOWN` | LOW |

### Gitleaks → Unified

All secret findings = **CRITICAL** (no exceptions).
