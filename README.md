# 🛡️ Bug Finder Kit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/badge/npm-v1.2.0-red.svg)](https://www.npmjs.com/package/@souvik65/bug-finder-kit)
[![Platform](https://img.shields.io/badge/platform-Cursor%20%7C%20Windsurf%20%7C%20Claude%20%7C%20Antigravity%20%7C%20VS%20Code-brightgreen.svg)]()

> **Universal Security & Vulnerability Detection Skills Suite for AI Coding Agents.**  
> Turn your favorite AI code editor (Cursor, Windsurf, Claude Code, Antigravity, VS Code Copilot, Cline, etc.) into an automated application security auditor.

---

## ⚡ Quick Start

Run in your project root — **by default, it automatically installs all security skills in one command without asking you to choose one by one**:

```bash
npx @souvik65/bug-finder-kit init
```

Or install globally to use across any terminal:

```bash
npm install -g @souvik65/bug-finder-kit
bug-finder init
```

---

## 📦 What Gets Installed? (Full Suite by Default)

When you run `bug-finder init` or `npx @souvik65/bug-finder-kit init`, **the complete kit of 10+ specialized skills is installed automatically**:

| Skill | Focus / Detection Scope | Chat Invocation Command |
|---|---|---|
| **`security-audit`** | Full OWASP Top 10 + STRIDE + secrets + CI/CD scan | `"Use the security-audit skill on this project"` |
| **`vulnerability-detector`** | Multi-language static code analysis (CWE-89, 78, 22, 502) | `"Use the vulnerability-detector skill to inspect src/"` |
| **`secrets-scanner`** | Detects leaked API keys, tokens, and hardcoded credentials | `"Use the secrets-scanner skill before pushing to GitHub"` |
| **`dependency-audit`** | Supply chain CVE analysis (npm, pip, cargo, go, maven) | `"Use the dependency-audit skill on this project"` |
| **`sql-injection-detector`** | SQLi, NoSQL injection, and ORM query misuse | `"Use the sql-injection-detector skill to inspect database queries"` |
| **`xss-detector`** | DOM sinks, `innerHTML`, reflected/stored XSS, template flaws | `"Use the xss-detector skill on frontend components"` |
| **`auth-security`** | JWT, OAuth flows, IDOR, session fixation, RBAC bypasses | `"Use the auth-security skill to review login and permissions"` |
| **`api-security-review`** | REST & GraphQL endpoints, rate limits, CORS, mass assignment | `"Use the api-security-review skill on all API endpoints"` |
| **`threat-modeler`** | STRIDE threat modeling, trust boundaries, DREAD scoring | `"Use the threat-modeler skill to create a STRIDE analysis"` |
| **`crypto-auditor`** | Weak ciphers (MD5/SHA1/DES), static IVs, insecure random | `"Use the crypto-auditor skill to review encryption and hashing"` |

---

## 💻 Installing in Any Code Editor

The CLI supports all modern AI code editors out of the box via the `--target` flag or `--dir` for custom folder setups:

### 1. Cursor IDE
Installs skills into `.cursor/skills/`:
```bash
# In your current project
npx @souvik65/bug-finder-kit init --target cursor

# Or globally for all Cursor projects:
npx @souvik65/bug-finder-kit init --target cursor --global
```

### 2. Windsurf IDE
Installs skills into `.windsurf/skills/`:
```bash
# In your current project
npx @souvik65/bug-finder-kit init --target windsurf

# Or globally for all Windsurf projects:
npx @souvik65/bug-finder-kit init --target windsurf --global
```

### 3. Claude Code
Installs skills into `.claude/skills/`:
```bash
# In your current project
npx @souvik65/bug-finder-kit init --target claude

# Or globally for Claude Code:
npx @souvik65/bug-finder-kit init --target claude --global
```

### 4. Google Antigravity / Gemini CLI
Installs skills into `.agents/skills/`:
```bash
# In your current project
npx @souvik65/bug-finder-kit init --target agents

# Or globally across your system:
npx @souvik65/bug-finder-kit init --target agents --global
```

### 5. VS Code / GitHub Copilot
Installs skills into `.github/skills/`:
```bash
npx @souvik65/bug-finder-kit init --target vscode
```

### 6. Cline / Roo Code
Installs skills into `.cline/skills/`:
```bash
npx @souvik65/bug-finder-kit init --target cline
```

### 7. Any Custom Editor / Custom Path
Point directly to any folder with `--dir`:
```bash
npx @souvik65/bug-finder-kit init --dir ./my-custom-skills
```

---

## 🤖 How to Use: Asking Your Agent in Chat

Once installed, restart your editor's AI session. Then copy and paste any of the following commands directly into your AI chat window:

### 1. Comprehensive Full Audit
```markdown
Use the security-audit skill on this codebase and generate an OWASP Top 10 report.
```
> *The agent maps your codebase against the OWASP Top 10, identifies high-risk endpoints, verifies inputs/secrets, and outputs a complete remediation plan with severity ratings.*

### 2. Static Vulnerability Hunting
```markdown
Use the vulnerability-detector skill to inspect src/ for security flaws and code bugs.
```
> *Scans for injection vulnerabilities, command execution risks, path traversals, unsafe deserialization, and prototype pollution.*

### 3. Pre-Push Secrets Check
```markdown
Use the secrets-scanner skill before pushing to GitHub.
```
> *Scans all staged files, `.env` files, Dockerfiles, and git commits to make sure no live API keys, credentials, or private certificates are committed.*

### 4. Third-Party Dependency Audit
```markdown
Use the dependency-audit skill to check all project dependencies for CVEs.
```
> *Inspects lockfiles (`package-lock.json`, `poetry.lock`, `Cargo.lock`, `go.sum`), detects vulnerable transitive packages, and recommends safe versions.*

### 5. Database & SQL Query Audit
```markdown
Use the sql-injection-detector skill to check all database queries and ORM calls.
```
> *Inspects raw SQL, query builder strings, string concatenations, and NoSQL operators ($where, $gt) for bypass vulnerabilities.*

### 6. Frontend & DOM XSS Protection
```markdown
Use the xss-detector skill on the frontend templates and components.
```
> *Finds unescaped variables, dangerous DOM sinks (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `eval`), and missing Content Security Policies (CSP).*

### 7. Auth, Session & Permission Review
```markdown
Use the auth-security skill to review login, JWT tokens, and access control.
```
> *Checks token validation, secret entropy, algorithm confusion, session cookie settings (HttpOnly, Secure, SameSite), IDOR flaws, and role escalation paths.*

### 8. API & Microservice Endpoint Review
```markdown
Use the api-security-review skill on all REST and GraphQL endpoints.
```
> *Audits missing authorization middleware, excessive data exposure, CORS misconfigurations, rate limit gaps, and mass assignment.*

### 9. System Threat Modeling
```markdown
Use the threat-modeler skill to generate a STRIDE analysis for this system architecture.
```
> *Builds trust boundaries, attack trees, and threat profiles (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).*

### 10. Cryptography & Hashing Verification
```markdown
Use the crypto-auditor skill to audit encryption, hashing, and random number generation.
```
> *Flags deprecated algorithms (MD5, SHA-1, DES, 3DES, AES-ECB), hardcoded initialization vectors (IVs), `Math.random()` in security contexts, and timing attack risks.*

---

## 🛠️ CLI Command Reference

```
Usage:
  bug-finder init                 Interactive setup (detects editor, installs all skills)
  bug-finder add <skill...>       Install all skills (or specific ones)
  bug-finder remove <skill...>    Uninstall specific skills
  bug-finder list                 Show all available skills and descriptions

Options:
  -t, --target <name>  agents | claude | cursor | windsurf | cline | vscode (default: agents)
  -d, --dir <path>     Install to any custom directory
  -g, --global         Install globally for all projects (User profile)
  -s, --skill <name>   Install only specific skill(s) instead of all
  -y, --yes            Skip prompts, install all skills with defaults (CI-friendly)
  -f, --force          Overwrite existing skill files
  -h, --help           Show help information
  -v, --version        Show version
```

### Examples:

```bash
# Fast 1-second install for Cursor
bug-finder add --target cursor --yes

# Fast 1-second install for Windsurf
bug-finder add --target windsurf --yes

# Install globally for Claude Code
bug-finder add --target claude --global --yes

# Install only secrets-scanner for a lightweight repo
bug-finder add secrets-scanner --target cursor

# Uninstall a skill
bug-finder remove xss-detector --target cursor
```

---

## 🔒 Security & Privacy Guarantee

- **Zero Telemetry**: Bug Finder Kit does not send any code, tokens, or telemetry to external servers.
- **Local Execution**: All skills execute locally within your configured AI editor.
- **Safe Secrets Handling**: The secrets scanner redacts any matched credential values automatically in its outputs.

---

## 📄 License

MIT © [Souvik](https://github.com/Souvik65)