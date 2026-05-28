# False Positive Guide

> FPs waste dev time and erode trust in the scan system.
> Suppress carefully, document always.

---

## Common False Positives by Tool

### Semgrep

| Pattern Triggering | Likely FP? | How to Handle |
|-------------------|-----------|---------------|
| `crypto.randomBytes()` flagged as weak random | Yes | Add to `semgrep.yml` allowlist |
| Test files with hardcoded credentials | Yes | Exclude `*.spec.ts`, `*.test.ts` (already in config) |
| `@Public()` on health check endpoints | Yes | Inline `# nosemgrep` |
| JWT decode (not verify) for logging only | Context | Add comment explaining intent |
| `eval()` in generated code / VM sandbox | Context | Review + inline suppress |

**Inline suppression:**
```typescript
// nosemgrep: nestjs-missing-auth-guard
@Controller('health')
export class HealthController { ... }
```

### Gitleaks

| Triggering Pattern | Likely FP? | How to Handle |
|-------------------|-----------|---------------|
| API keys in `.env.example` | Yes | Add `# gitleaks:allow` |
| High-entropy base64 in test fixtures | Yes | Add to `gitleaks.toml` allowlist by path |
| Client IDs (not secrets) | Sometimes | Check: is this actually a secret? |
| Hardcoded "test" JWT tokens | Yes | `# gitleaks:allow` + confirm non-prod |

**Inline suppression:**
```bash
# .env.example
KIOTVIET_SECRET="your-secret-here"  # gitleaks:allow
JWT_SECRET="example-jwt-secret-replace-in-production"  # gitleaks:allow
```

**Path allowlist in `gitleaks.toml`:**
```toml
[allowlist]
  paths = [
    '''fixtures/''',
    '''__tests__/''',
    '''\.env\.example$''',
  ]
```

### npm audit / Trivy

| Scenario | Recommended Action |
|---------|-------------------|
| Transitive dep CVE, no fix, low EPSS | Create tracking issue, suppress in `.nsprc` |
| Dev-only dep (`devDependencies`) CVE | Only block if also in production bundle |
| CVE in package not used at runtime | Review bundle, suppress with comment |
| False CVSS from advisory DB | Check NVD directly; if confirmed FP, suppress |

**Trivy ignorefile (`.trivyignore`):**
```
# CVE-2024-XXXXX — dev dependency only, not in production bundle
# Ticket: SECURITY-42
CVE-2024-XXXXX
```

---

## Suppression Governance Rules

1. **Never suppress without a comment** explaining why
2. **Link to a ticket** for non-trivial suppressions
3. **Review suppressions quarterly** — they may become valid over time
4. **CRITICAL findings cannot be suppressed** inline — require override policy
5. **CI jobs log all suppressed findings** for audit trail

---

## Entropy Tuning

Gitleaks uses Shannon entropy to detect high-randomness strings (likely secrets).

| Entropy Threshold | Effect |
|-----------------|--------|
| 3.0 (low) | More findings, more FPs |
| 3.5 (default) | Balanced |
| 4.5 (high) | Fewer findings, may miss short secrets |

Adjust per rule in `gitleaks.toml`:
```toml
[[rules]]
  id = "my-rule"
  entropy = 4.0  # increase if too many FPs
```

---

## Escalation Process

```
FP detected by dev
    ↓
Add inline suppression with comment
    ↓
Create MR → security team reviews
    ↓
If systematic FP → update gitleaks.toml or semgrep.yml allowlist
    ↓
Merge → applies to all future scans
```
