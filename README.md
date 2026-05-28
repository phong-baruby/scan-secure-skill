# 🔐 security-scan-skill

> A Claude Code skill for automated security scanning — catch vulnerabilities before they ship.

---

**Language / Ngôn ngữ:** &nbsp; [🇻🇳 Tiếng Việt](#tiếng-việt) &nbsp;|&nbsp; [🇬🇧 English](#english)

---

<a id="tiếng-việt"></a>

Bộ skill này cho phép Claude Code agent tự động scan bảo mật toàn bộ repository, tích hợp vào GitLab CI pipeline, và chạy như một pre-commit hook ở local. Được thiết kế theo hướng **shift-left**: phát hiện lỗi càng sớm càng tốt, không phải sau khi deploy.

---

## 🎯 Phù hợp với ai?

| Tiêu chí | Chi tiết |
|---------|---------|
| **Ngôn ngữ** | TypeScript, JavaScript (Node.js) |
| **Framework** | NestJS, Express, Fastify |
| **ORM** | TypeORM, Prisma, Sequelize |
| **CI/CD** | GitLab CI (template có sẵn), adaptable cho GitHub Actions |
| **Package manager** | npm, pnpm, yarn |
| **Database** | PostgreSQL, Redis |
| **Workflow** | Agentic coding với Claude Code, vibe coding, solo dev, small team |

Nếu mày đang dùng **NestJS + TypeScript + PostgreSQL** thì bộ này fit nhất. Các stack khác vẫn dùng được phần SAST và secret detection, chỉ một số NestJS-specific rules sẽ không trigger.

---

## 🔍 Scan được gì?

Bộ này cover **20 lỗi bảo mật phổ biến**, chia 3 lớp:

### 🛠 SAST — Static Code Analysis (Semgrep)
| # | Lỗi | Ví dụ phát hiện |
|---|-----|----------------|
| 1 | Hardcoded Secret | JWT secret nhúng thẳng vào `JwtModule.register()` |
| 2 | SQL Injection | `repo.query("SELECT * FROM t WHERE id = " + input)` |
| 3 | XSS | Render HTML từ input người dùng chưa sanitize |
| 4 | IDOR | GET `:id` endpoint thiếu ownership check |
| 6 | Brute Force | `/login`, `/verify-otp` thiếu `@Throttle()` |
| 7 | Mass Assignment | `@Body() body: any` spread thẳng vào `repo.save({...body})` |
| 8 | Insecure Deserialization | `yaml.load()` không safe, `eval(userInput)` |
| 9 | SSRF | `axios.get(req.body.url)` — URL do user kiểm soát |
| 10 | Path Traversal | `fs.readFile(req.params.file)`, `res.sendFile(userPath)` |
| 11 | CSRF | Cookie thiếu `SameSite`, thiếu CSRF middleware |
| 12 | Broken Access Control | Controller thiếu `@UseGuards`, route `/admin` không có guard *(warning only)* |
| 13 | Weak Password Hashing | `crypto.createHash('md5')` |
| 14 | JWT None Algorithm | `JwtModule.register({ secret: 'hardcoded' })` |
| 15 | CORS Misconfiguration | `app.enableCors({ origin: '*' })` |
| 16 | Unrestricted File Upload | `FileInterceptor` thiếu `fileFilter` và `limits.fileSize` |
| 17 | Verbose Error | `res.json({ stack: err.stack })` |
| 18 | Missing Rate Limit | Endpoint nặng thiếu throttle guard |
| 19 | Race Condition | Read-then-write balance/inventory không có atomic lock |

### 🔑 Secret Detection (Gitleaks + TruffleHog fallback)
Phát hiện API keys, tokens, passwords, connection strings bị commit nhầm. Có custom rules cho: Firebase, Cloudflare, Stripe, Shopee Open Platform, TikTok Shop, Maps APIs, PostgreSQL/Redis connection strings.

### 📦 Dependency CVE (npm audit + Trivy)
- Scan `package.json` / `package-lock.json` so với advisory database
- Trivy bổ sung SCA coverage, dedup kết quả
- Phân biệt CVE *có fix* vs *chưa có fix* → blocking logic khác nhau

### 🎭 Slopsquatting Detection (script riêng)
- **Layer 1**: Check package có thật trên npm registry không (AI hay hallucinate tên thư viện)
- **Layer 2**: Score reputation signals — package mới < 30 ngày, downloads < 100/tuần, tên gần giống top npm packages (Levenshtein ≤ 2), 0 dependents
- Optional: tích hợp Socket.dev CLI cho behavior analysis

---

## 📁 Cấu trúc

```
security-scan-skill/
├── SKILL.md                        ← Entry point cho Claude Code agent
├── README.md                       ← File này
├── references/
│   ├── tools.md                    ← Hướng dẫn cài tools, chọn ruleset
│   ├── severity-matrix.md          ← Blocking rules theo severity × trigger
│   └── false-positive-guide.md     ← Cách suppress FP đúng cách
├── scripts/
│   ├── scan-all.sh                 ← Master runner
│   ├── sast-scan.sh                ← Semgrep SAST
│   ├── secret-scan.sh              ← Gitleaks / TruffleHog
│   ├── dep-audit.sh                ← npm audit + Trivy
│   ├── slopsquatting-scan.sh       ← Npm package existence + reputation check
│   └── report-merge.sh             ← Merge → unified summary.json
├── templates/
│   ├── gitlab-ci.yml               ← GitLab CI job templates
│   ├── semgrep.yml                 ← Custom Semgrep rules (NestJS/TS)
│   ├── gitleaks.toml               ← Custom Gitleaks rules
│   └── trivy.yaml                  ← Trivy config
└── hooks/
    ├── pre-commit                  ← Git pre-commit hook
    └── install-hooks.sh            ← Hook installer
```

---

## 🚀 Cài đặt

### Prerequisites

```bash
# Semgrep (SAST)
pip install semgrep

# Gitleaks (secret detection)
brew install gitleaks          # macOS
# Linux: xem https://github.com/gitleaks/gitleaks/releases

# Trivy (dependency scan)
brew install trivy             # macOS
# Linux: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# TruffleHog (optional fallback)
brew install trufflehog
```

---

## 🤖 Cài vào Claude Code (CLI / Terminal)

Claude Code đọc skills từ thư mục `~/.claude/skills/` (hoặc `.claude/skills/` trong repo).

### Option A — Global skill (dùng cho mọi project)

```bash
# Clone hoặc copy bộ skill vào thư mục global
mkdir -p ~/.claude/skills
cp -r security-scan-skill ~/.claude/skills/

# Verify
ls ~/.claude/skills/security-scan-skill/SKILL.md
```

Claude Code sẽ tự load skill khi mày nhắc đến security scanning trong bất kỳ project nào.

### Option B — Per-project skill

```bash
# Copy vào repo hiện tại
mkdir -p .claude/skills
cp -r security-scan-skill .claude/skills/

# Commit vào repo để cả team dùng chung
git add .claude/skills/security-scan-skill
git commit -m "chore: add security scan skill for Claude Code"
```

### Cách trigger trong Claude Code

```
# Scan toàn bộ repo
"Scan this repo for security vulnerabilities"

# Scan trước khi tạo MR
"Run security scan on my changes before I create the merge request"

# Scan on-demand một file cụ thể
"Check src/auth/auth.controller.ts for security issues"

# Xem report
"Show me the security scan summary"
```

---

## 🖥 Cài vào Claude Desktop (MCP)

Claude Desktop dùng qua **MCP (Model Context Protocol)**. Skill này chạy scripts bash, nên cần MCP server có khả năng execute commands.

### Bước 1 — Cài MCP filesystem server

```bash
npm install -g @modelcontextprotocol/server-filesystem
```

### Bước 2 — Config Claude Desktop

Mở file config Claude Desktop:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Thêm vào:

```json
{
  "mcpServers": {
    "security-scan": {
      "command": "npx",
      "args": [
        "@modelcontextprotocol/server-filesystem",
        "/path/to/your/repo"
      ],
      "env": {
        "SECURITY_SKILL_PATH": "/path/to/security-scan-skill"
      }
    }
  }
}
```

> **Lưu ý**: Claude Desktop với MCP filesystem server có thể đọc files và suggest commands, nhưng để chạy scripts tự động thì cần MCP server hỗ trợ `exec`. Với Claude Desktop, workflow phổ biến hơn là để Claude *hướng dẫn* mày chạy lệnh, thay vì tự chạy.

### Workflow thực tế với Claude Desktop

1. Mở Claude Desktop
2. Attach file hoặc paste code cần review
3. Hỏi: *"Review this code for the security issues listed in the security-scan-skill"*
4. Claude sẽ dùng SKILL.md làm reference để phân tích và đưa ra findings

---

## 🔧 Tích hợp GitLab CI

### Bước 1 — Copy scripts vào repo

```bash
mkdir -p .gitlab/security-scripts
cp scripts/*.sh .gitlab/security-scripts/
chmod +x .gitlab/security-scripts/*.sh

cp templates/gitlab-ci.yml .gitlab/security-scan.yml
cp templates/semgrep.yml .semgrep.yml
cp templates/gitleaks.toml .gitleaks.toml
```

### Bước 2 — Include vào `.gitlab-ci.yml`

```yaml
# .gitlab-ci.yml
stages:
  - test
  - pre-deploy
  - deploy

include:
  - local: '.gitlab/security-scan.yml'

# Jobs của bạn...
build:
  stage: test
  script:
    - npm run build
```

### Bước 3 — Configure variables (GitLab CI/CD Settings)

| Variable | Default | Mô tả |
|---------|---------|-------|
| `SECURITY_FAIL_ON` | `high` | Block ở severity nào: `critical` / `high` / `medium` |
| `SECURITY_OVERRIDE` | `false` | Set `true` để bypass block (maintainer only) |

### Jobs có sẵn

| Job | Trigger | Block? |
|-----|---------|--------|
| `security:mr-scan` | Mọi MR | CRITICAL + HIGH SAST/secret |
| `security:pre-deploy` | Push lên `main`/`master` hoặc tag | CRITICAL |
| `security:dep-check` | MR có thay đổi `package.json` | HIGH CVE có fix |
| `security:scheduled-full-scan` | CI schedule | Warn only |

---

## 🪝 Cài pre-commit hook (local)

```bash
# Cài hook vào repo hiện tại
chmod +x hooks/install-hooks.sh
./hooks/install-hooks.sh

# Verify
cat .git/hooks/pre-commit
```

Hook sẽ tự chạy mỗi lần `git commit`:
- **Secret detection** (Gitleaks) → block commit nếu tìm thấy secret
- **Quick SAST** trên staged `.ts`/`.js` files → block nếu có CRITICAL finding

```bash
# Skip hook trong trường hợp khẩn cấp (có log lại)
git commit --no-verify -m "hotfix: ..."
```

---

## 📊 Report output

Sau mỗi lần scan, kết quả được merge vào `security-reports/summary.json`:

```json
{
  "scan_id": "pipeline-12345",
  "timestamp": "2025-05-14T10:00:00Z",
  "repo": "<your-repo>",
  "branch": "feature/your-branch",
  "mode": "mr",
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 3,
    "low": 8,
    "total": 12,
    "blocked": true,
    "block_reason": "1 HIGH finding(s) with available remediation"
  },
  "findings": [
    {
      "scan_type": "sast",
      "severity": "HIGH",
      "rule_id": "nestjs-missing-auth-guard",
      "title": "Controller has no @UseGuards decorator",
      "file": "src/orders/orders.controller.ts",
      "line_start": 12,
      "fix_guidance": "Add @UseGuards(JwtAuthGuard) or mark as @Public()"
    }
  ]
}
```

---

## 🔕 Suppress false positives

### Semgrep inline
```typescript
// nosemgrep: nestjs-missing-auth-guard
@Controller('health')
export class HealthController { ... }
```

### Gitleaks inline
```bash
# .env.example
EXAMPLE_API_KEY="not-a-real-key"  # gitleaks:allow
```

### Trivy ignorefile (`.trivyignore`)
```
# CVE-2024-XXXXX — dev dependency only, not in production bundle
# Ticket: SECURITY-42, revisit on 2025-08-01
CVE-2024-XXXXX
```

Xem thêm: [`references/false-positive-guide.md`](references/false-positive-guide.md)

---

## 🚦 Blocking logic

```
Pre-commit hook:
  Any secret → BLOCK

GitLab MR:
  CRITICAL (bất kỳ scan) → BLOCK
  HIGH SAST / secret → BLOCK
  HIGH dep CVE có fix → BLOCK
  HIGH dep CVE chưa có fix → WARN (tạo issue)
  MEDIUM → comment, không block

Pre-deploy (main/master):
  CRITICAL → BLOCK
  HIGH → BLOCK
```

> Broken Access Control (#12) luôn là WARNING — không bao giờ block, vì static scan không thể xác định chắc chắn access control có được enforce ở tầng khác hay không.

---

## 🔧 Customize

### Thêm custom Semgrep rules
Mở `templates/semgrep.yml`, thêm rule theo format:
```yaml
rules:
  - id: your-custom-rule
    pattern: your_dangerous_function($INPUT)
    message: "Why this is dangerous and how to fix"
    languages: [typescript]
    severity: ERROR  # ERROR | WARNING | INFO
    metadata:
      cwe: ["CWE-XXX"]
```

### Thêm custom Gitleaks rules
Mở `templates/gitleaks.toml`, copy template ở cuối file và điền thông tin service của bạn.

### Thay đổi blocking threshold
```bash
# Chỉ block CRITICAL, bỏ qua HIGH
./scripts/scan-all.sh --fail-on critical

# Hoặc qua GitLab CI variable
SECURITY_FAIL_ON=critical
```

---

## 📦 Slopsquatting scan riêng

```bash
# Chạy độc lập (có gọi npm registry API — cần internet)
./scripts/slopsquatting-scan.sh --path . --output ./security-reports

# Với Socket.dev CLI (cần cài: npm i -g @socketsecurity/cli)
./scripts/slopsquatting-scan.sh --path . --output ./security-reports --socket
```

> ⚠️ Slopsquatting scan gọi npm API để check từng package. Với repo có nhiều dependencies, có thể mất 1-2 phút. Nên chạy trong CI scheduled job thay vì mọi MR.

---

## 🤝 Contributing

PR welcome. Một số hướng có thể contribute:

- Thêm rules cho framework khác (Fastify, Hono, tRPC)
- GitHub Actions template (hiện chỉ có GitLab CI)
- Rules cho ngôn ngữ khác (Python/FastAPI, Go/Gin)
- Cải thiện Layer 2 slopsquatting detection

---

## 📄 License

MIT — dùng thoải mái, commercial hay open source đều được.

---

## 🙏 Credits

Tool stack: [Semgrep](https://semgrep.dev) · [Gitleaks](https://github.com/gitleaks/gitleaks) · [Trivy](https://github.com/aquasecurity/trivy) · [Socket.dev](https://socket.dev)

OWASP reference: [OWASP Top 10:2021](https://owasp.org/Top10/)

---

<a id="english"></a>

# 🔐 security-scan-skill — English

> A Claude Code skill for automated security scanning — catch vulnerabilities before they ship.

**Language / Ngôn ngữ:** &nbsp; [🇻🇳 Tiếng Việt](#tiếng-việt) &nbsp;|&nbsp; [🇬🇧 English](#english)

---

## 🎯 Who is this for?

| Criteria | Details |
|---------|---------|
| **Language** | TypeScript, JavaScript (Node.js) |
| **Framework** | NestJS, Express, Fastify |
| **ORM** | TypeORM, Prisma, Sequelize |
| **CI/CD** | GitLab CI (template included), adaptable for GitHub Actions |
| **Package manager** | npm, pnpm, yarn |
| **Database** | PostgreSQL, Redis |
| **Workflow** | Agentic coding with Claude Code, vibe coding, solo dev, small team |

Best fit: **NestJS + TypeScript + PostgreSQL**. Other stacks still benefit from SAST and secret detection; NestJS-specific rules simply won't trigger.

---

## 🔍 What does it scan?

Covers **20 common security vulnerabilities** across 3 layers:

### 🛠 SAST — Static Code Analysis (Semgrep)

| # | Vulnerability | Example detected |
|---|--------------|-----------------|
| 1 | Hardcoded Secret | JWT secret hardcoded in `JwtModule.register()` |
| 2 | SQL Injection | `repo.query("SELECT * FROM t WHERE id = " + input)` |
| 3 | XSS | Rendering unsanitized user input as HTML |
| 4 | IDOR | GET `:id` endpoint missing ownership check |
| 6 | Brute Force | `/login`, `/verify-otp` missing `@Throttle()` |
| 7 | Mass Assignment | `@Body() body: any` spread directly into `repo.save({...body})` |
| 8 | Insecure Deserialization | `yaml.load()` (unsafe), `eval(userInput)` |
| 9 | SSRF | `axios.get(req.body.url)` — URL controlled by user |
| 10 | Path Traversal | `fs.readFile(req.params.file)`, `res.sendFile(userPath)` |
| 11 | CSRF | Cookie missing `SameSite`, missing CSRF middleware |
| 12 | Broken Access Control | Controller missing `@UseGuards`, `/admin` route without guard *(warning only)* |
| 13 | Weak Password Hashing | `crypto.createHash('md5')` |
| 14 | JWT None Algorithm | `JwtModule.register({ secret: 'hardcoded' })` |
| 15 | CORS Misconfiguration | `app.enableCors({ origin: '*' })` |
| 16 | Unrestricted File Upload | `FileInterceptor` missing `fileFilter` and `limits.fileSize` |
| 17 | Verbose Error | `res.json({ stack: err.stack })` |
| 18 | Missing Rate Limit | Heavy endpoint missing throttle guard |
| 19 | Race Condition | Read-then-write on balance/inventory without atomic lock |

### 🔑 Secret Detection (Gitleaks + TruffleHog fallback)

Detects accidentally committed API keys, tokens, passwords, and connection strings. Custom rules for: Firebase, Cloudflare, Stripe, Shopee Open Platform, TikTok Shop, Maps APIs, PostgreSQL/Redis connection strings.

### 📦 Dependency CVE (npm audit + Trivy)

- Scans `package.json` / `package-lock.json` against advisory databases
- Trivy adds SCA coverage and deduplicates results
- Distinguishes CVEs *with a fix* vs *without a fix* → different blocking logic

### 🎭 Slopsquatting Detection (dedicated script)

- **Layer 1**: Checks whether a package actually exists on the npm registry (AI models frequently hallucinate package names)
- **Layer 2**: Scores reputation signals — package younger than 30 days, downloads < 100/week, name within Levenshtein distance ≤ 2 of top npm packages, 0 dependents
- Optional: Socket.dev CLI integration for behavior analysis

---

## 📁 Structure

```
security-scan-skill/
├── SKILL.md                        ← Entry point for Claude Code agent
├── README.md                       ← This file
├── references/
│   ├── tools.md                    ← Tool installation guide, ruleset selection
│   ├── severity-matrix.md          ← Blocking rules by severity × trigger
│   └── false-positive-guide.md     ← How to suppress false positives correctly
├── scripts/
│   ├── scan-all.sh                 ← Master runner
│   ├── sast-scan.sh                ← Semgrep SAST
│   ├── secret-scan.sh              ← Gitleaks / TruffleHog
│   ├── dep-audit.sh                ← npm audit + Trivy
│   ├── slopsquatting-scan.sh       ← Npm package existence + reputation check
│   └── report-merge.sh             ← Merge → unified summary.json
├── templates/
│   ├── gitlab-ci.yml               ← GitLab CI job templates
│   ├── semgrep.yml                 ← Custom Semgrep rules (NestJS/TS)
│   ├── gitleaks.toml               ← Custom Gitleaks rules
│   └── trivy.yaml                  ← Trivy config
└── hooks/
    ├── pre-commit                  ← Git pre-commit hook
    └── install-hooks.sh            ← Hook installer
```

---

## 🚀 Installation

### Prerequisites

```bash
# Semgrep (SAST)
pip install semgrep

# Gitleaks (secret detection)
brew install gitleaks          # macOS
# Linux: see https://github.com/gitleaks/gitleaks/releases

# Trivy (dependency scan)
brew install trivy             # macOS
# Linux: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# TruffleHog (optional fallback)
brew install trufflehog
```

---

## 🤖 Install into Claude Code (CLI / Terminal)

Claude Code reads skills from `~/.claude/skills/` (or `.claude/skills/` inside the repo).

### Option A — Global skill (available in every project)

```bash
mkdir -p ~/.claude/skills
cp -r security-scan-skill ~/.claude/skills/

# Verify
ls ~/.claude/skills/security-scan-skill/SKILL.md
```

Claude Code will load the skill automatically whenever you mention security scanning in any project.

### Option B — Per-project skill

```bash
mkdir -p .claude/skills
cp -r security-scan-skill .claude/skills/

# Commit so the whole team can use it
git add .claude/skills/security-scan-skill
git commit -m "chore: add security scan skill for Claude Code"
```

### How to trigger in Claude Code

```
# Scan the entire repo
"Scan this repo for security vulnerabilities"

# Scan before creating an MR
"Run security scan on my changes before I create the merge request"

# On-demand scan of a specific file
"Check src/auth/auth.controller.ts for security issues"

# View the report
"Show me the security scan summary"
```

---

## 🖥 Install into Claude Desktop (MCP)

Claude Desktop uses **MCP (Model Context Protocol)**. This skill runs bash scripts, so you need an MCP server capable of executing commands.

### Step 1 — Install MCP filesystem server

```bash
npm install -g @modelcontextprotocol/server-filesystem
```

### Step 2 — Configure Claude Desktop

Open the Claude Desktop config file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Add:

```json
{
  "mcpServers": {
    "security-scan": {
      "command": "npx",
      "args": [
        "@modelcontextprotocol/server-filesystem",
        "/path/to/your/repo"
      ],
      "env": {
        "SECURITY_SKILL_PATH": "/path/to/security-scan-skill"
      }
    }
  }
}
```

> **Note**: Claude Desktop with the MCP filesystem server can read files and suggest commands, but running scripts automatically requires an MCP server that supports `exec`. The common workflow with Claude Desktop is to let Claude *guide you* through the commands rather than running them autonomously.

### Practical workflow with Claude Desktop

1. Open Claude Desktop
2. Attach a file or paste code to review
3. Ask: *"Review this code for the security issues listed in the security-scan-skill"*
4. Claude uses SKILL.md as a reference to analyze the code and report findings

---

## 🔧 GitLab CI Integration

### Step 1 — Copy scripts into your repo

```bash
mkdir -p .gitlab/security-scripts
cp scripts/*.sh .gitlab/security-scripts/
chmod +x .gitlab/security-scripts/*.sh

cp templates/gitlab-ci.yml .gitlab/security-scan.yml
cp templates/semgrep.yml .semgrep.yml
cp templates/gitleaks.toml .gitleaks.toml
```

### Step 2 — Include in `.gitlab-ci.yml`

```yaml
stages:
  - test
  - pre-deploy
  - deploy

include:
  - local: '.gitlab/security-scan.yml'

build:
  stage: test
  script:
    - npm run build
```

### Step 3 — Configure variables (GitLab CI/CD Settings)

| Variable | Default | Description |
|---------|---------|-------------|
| `SECURITY_FAIL_ON` | `high` | Block at this severity: `critical` / `high` / `medium` |
| `SECURITY_OVERRIDE` | `false` | Set `true` to bypass the block (maintainer only) |

### Available jobs

| Job | Trigger | Blocks? |
|-----|---------|---------|
| `security:mr-scan` | Every MR | CRITICAL + HIGH SAST/secret |
| `security:pre-deploy` | Push to `main`/`master` or tag | CRITICAL |
| `security:dep-check` | MR with `package.json` changes | HIGH CVE with fix available |
| `security:scheduled-full-scan` | CI schedule | Warn only |

---

## 🪝 Install pre-commit hook (local)

```bash
chmod +x hooks/install-hooks.sh
./hooks/install-hooks.sh

# Verify
cat .git/hooks/pre-commit
```

The hook runs automatically on every `git commit`:
- **Secret detection** (Gitleaks) → blocks commit if a secret is found
- **Quick SAST** on staged `.ts`/`.js` files → blocks if a CRITICAL finding exists

```bash
# Skip the hook in an emergency (logged)
git commit --no-verify -m "hotfix: ..."
```

---

## 📊 Report output

After each scan, results are merged into `security-reports/summary.json`:

```json
{
  "scan_id": "pipeline-12345",
  "timestamp": "2025-05-14T10:00:00Z",
  "repo": "<your-repo>",
  "branch": "feature/your-branch",
  "mode": "mr",
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 3,
    "low": 8,
    "total": 12,
    "blocked": true,
    "block_reason": "1 HIGH finding(s) with available remediation"
  },
  "findings": [
    {
      "scan_type": "sast",
      "severity": "HIGH",
      "rule_id": "nestjs-missing-auth-guard",
      "title": "Controller has no @UseGuards decorator",
      "file": "src/orders/orders.controller.ts",
      "line_start": 12,
      "fix_guidance": "Add @UseGuards(JwtAuthGuard) or mark as @Public()"
    }
  ]
}
```

---

## 🔕 Suppressing false positives

### Semgrep inline
```typescript
// nosemgrep: nestjs-missing-auth-guard
@Controller('health')
export class HealthController { ... }
```

### Gitleaks inline
```bash
# .env.example
EXAMPLE_API_KEY="not-a-real-key"  # gitleaks:allow
```

### Trivy ignorefile (`.trivyignore`)
```
# CVE-2024-XXXXX — dev dependency only, not in production bundle
# Ticket: SECURITY-42, revisit on 2025-08-01
CVE-2024-XXXXX
```

See also: [`references/false-positive-guide.md`](references/false-positive-guide.md)

---

## 🚦 Blocking logic

```
Pre-commit hook:
  Any secret → BLOCK

GitLab MR:
  CRITICAL (any scan) → BLOCK
  HIGH SAST / secret  → BLOCK
  HIGH dep CVE with fix    → BLOCK
  HIGH dep CVE without fix → WARN (create issue)
  MEDIUM → comment, no block

Pre-deploy (main/master):
  CRITICAL → BLOCK
  HIGH     → BLOCK
```

> Broken Access Control (#12) is always a WARNING — it never blocks, because static analysis cannot determine with certainty whether access control is enforced at another layer.

---

## 🔧 Customization

### Add custom Semgrep rules
Open `templates/semgrep.yml` and add a rule:
```yaml
rules:
  - id: your-custom-rule
    pattern: your_dangerous_function($INPUT)
    message: "Why this is dangerous and how to fix"
    languages: [typescript]
    severity: ERROR  # ERROR | WARNING | INFO
    metadata:
      cwe: ["CWE-XXX"]
```

### Add custom Gitleaks rules
Open `templates/gitleaks.toml`, copy the template at the bottom, and fill in your service details.

### Change the blocking threshold
```bash
# Block only CRITICAL, ignore HIGH
./scripts/scan-all.sh --fail-on critical

# Or via GitLab CI variable
SECURITY_FAIL_ON=critical
```

---

## 📦 Run slopsquatting scan standalone

```bash
# Run independently (calls the npm registry API — requires internet)
./scripts/slopsquatting-scan.sh --path . --output ./security-reports

# With Socket.dev CLI (install first: npm i -g @socketsecurity/cli)
./scripts/slopsquatting-scan.sh --path . --output ./security-reports --socket
```

> ⚠️ The slopsquatting scan calls the npm API for each package. Repos with many dependencies may take 1–2 minutes. Recommended to run in a CI scheduled job rather than on every MR.

---

## 🤝 Contributing

PRs welcome. Possible contribution areas:

- Rules for other frameworks (Fastify, Hono, tRPC)
- GitHub Actions template (currently GitLab CI only)
- Rules for other languages (Python/FastAPI, Go/Gin)
- Improved Layer 2 slopsquatting detection

---

## 📄 License

MIT — free to use in commercial or open-source projects.

---

## 🙏 Credits

Tool stack: [Semgrep](https://semgrep.dev) · [Gitleaks](https://github.com/gitleaks/gitleaks) · [Trivy](https://github.com/aquasecurity/trivy) · [Socket.dev](https://socket.dev)

OWASP reference: [OWASP Top 10:2021](https://owasp.org/Top10/)
