<div align="center">

# 🛡️ Bug Finder Kit

**The Enterprise-Grade Security & Vulnerability Detection Suite for AI Coding Agents**

Turn any modern AI code editor or autonomous coding agent into a continuous, elite Application Security Auditor.

[![npm version](https://img.shields.io/npm/v/@souvik65/bug-finder-kit.svg?style=flat-square&color=cb3837)](https://www.npmjs.com/package/@souvik65/bug-finder-kit)
[![npm downloads](https://img.shields.io/npm/dm/@souvik65/bug-finder-kit.svg?style=flat-square&color=blue)](https://www.npmjs.com/package/@souvik65/bug-finder-kit)
[![Skills Count](https://img.shields.io/badge/skills-32%20specialized-8A2BE2?style=flat-square)](https://github.com/Souvik65/bug-finder-kit)
[![Platform Matrix](https://img.shields.io/badge/agents-Cursor%20%7C%20Claude%20%7C%20Windsurf%20%7C%20Antigravity%20%7C%20Copilot%20%7C%20Cline-success?style=flat-square)](https://github.com/Souvik65/bug-finder-kit)
[![License: MIT](https://img.shields.io/badge/license-MIT-informational?style=flat-square)](LICENSE)
[![Zero Telemetry](https://img.shields.io/badge/telemetry-zero%20(100%25%20local)-brightgreen?style=flat-square)](https://github.com/Souvik65/bug-finder-kit)

[Quick Start](#-quick-start) • [Supported Editors](#-supported-editors--environments) • [Full Skills Catalog (32)](#-comprehensive-skills-catalog-32-skills) • [Agent Workflows](#-agent-workflows--prompt-examples) • [Architecture](#-skill-architecture--specification) • [CLI Reference](#-cli-reference)

</div>

---

## 💡 Why Bug Finder Kit?

Modern AI coding agents write code faster than ever—but without specialized security context, they frequently introduce **OWASP Top 10 vulnerabilities, leaked secrets, authorization bypasses, and supply-chain flaws**.

**Bug Finder Kit** installs **32 specialized security skills** directly into your agent's context runtime. Whether you are using **Cursor, Windsurf, Claude Code, Google Antigravity, VS Code Copilot, or Cline**, your agent instantly gains:

- 🎯 **Deep Domain Expertise:** 32 targeted skills covering everything from AST taint analysis to CORS bypasses and business logic flaws.
- ⚡ **Zero-Friction CLI:** Install the entire audited suite or cherry-pick specific skills in a single command.
- 🔒 **100% Local & Private:** Zero network telemetry, zero third-party API dependencies. All analysis executes locally in your workspace.
- 📋 **Production-Ready Deliverables:** Standardized finding templates with Severity, CWE/CVSS, vulnerable vs. remediated code diffs, and validation commands.

---

## ⚡ Quick Start

### 1. Instant Setup (Installs All 32 Skills)

Run inside your project root to auto-configure your editor:

```bash
npx @souvik65/bug-finder-kit init
```

Or install globally across your workstation:

```bash
npm install -g @souvik65/bug-finder-kit
bug-finder init
```

### 2. Invoke in Your Agent Chat

Once installed, restart your editor's AI session and talk to your agent naturally:

```text
"Use the security-audit skill on this codebase and generate an OWASP Top 10 report."
"Use the business-logic-audit skill to check our checkout flow for price tampering."
"Use the pr-security-gate skill to review changes before merging."
```

---

## 💻 Supported Editors & Environments

Bug Finder Kit automatically maps skills to the native skill and rules directory of your chosen agent:

| Platform / IDE | Target Flag | Target Installation Path | Scope |
|---|---|---|---|
| **Google Antigravity / Gemini CLI** | `--target agents` *(Default)* | `.agents/skills/<skill>` | Workspace or Global |
| **Claude Code** | `--target claude` | `.claude/skills/<skill>` | Workspace or Global |
| **Cursor IDE** | `--target cursor` | `.cursor/skills/<skill>` | Workspace or Global |
| **Windsurf IDE** | `--target windsurf` | `.windsurf/skills/<skill>` | Workspace or Global |
| **VS Code / GitHub Copilot** | `--target vscode` | `.github/skills/<skill>` | Workspace or Global |
| **Cline / Roo Code** | `--target cline` | `.cline/skills/<skill>` | Workspace or Global |
| **Custom Path / Any Agent** | `--dir <path>` | Custom directory | Configurable |

#### Non-Interactive / CI Installation:
```bash
# Install all skills into Cursor without interactive prompts
npx @souvik65/bug-finder-kit init --target cursor --yes

# Install globally for Claude Code
npx @souvik65/bug-finder-kit init --target claude --global --yes
```

---

## 📚 Comprehensive Skills Catalog (32 Skills)

All 32 skills include actionable detection heuristics, framework-specific code patterns (Node/TS, Python, Go, Java, PHP), and verified mitigation strategies.

```
bug-finder-kit/skills
├── 🌐 Web & API Security (7)
├── 💥 Vulnerability & Exploit Detection (8)
├── 🔐 Auth, Session & Secrets Security (5)
├── 📦 Supply Chain & Third-Party Code (3)
├── ⚙️ DevSecOps, Review & SDLC Gates (7)
└── 📱 Client & Mobile Security (2)
```

### 1. 🌐 Web & API Security

| Skill | Focus & Detection Scope | Primary Triggers |
|---|---|---|
| [`api-security-review`](skills/api-security-review) | REST & GraphQL API security: broken object-level auth (BOLA/IDOR), missing rate limits, mass assignment, and excessive data exposure. | `"review API security"`, `"GraphQL security"`, `"API rate limiting"` |
| [`cors-deep-dive`](skills/cors-deep-dive) | Advanced CORS misconfigurations: regex origin bypasses, null origin abuse, credential exposure, and preflight cache poisoning. | `"audit CORS"`, `"CORS misconfiguration"`, `"Access-Control-Allow-Origin"` |
| [`csp-auditor`](skills/csp-auditor) | Content Security Policy analysis: strict nonce/hash validation, unsafe-inline bypasses, Trusted Types, and exfiltration sinks. | `"audit CSP"`, `"Content Security Policy"`, `"CSP bypass"` |
| [`spa-security`](skills/spa-security) | Modern SPA frameworks (React, Vue, Angular, Next.js, Nuxt): SSR injection, hydration tampering, and client-side route guard bypasses. | `"SPA security review"`, `"Next.js security"`, `"hydration attack"` |
| [`subresource-integrity`](skills/subresource-integrity) | SRI verification for CDN assets, script hash generation (sha384), and CDN compromise mitigation. | `"check SRI"`, `"subresource integrity"`, `"CDN script security"` |
| [`web-app-security`](skills/web-app-security) | Comprehensive reconnaissance, architecture threat review, and defensive hardening based on verified web application guidelines. | `"web app security"`, `"recon audit"`, `"hardening review"` |
| [`web-security`](skills/web-security) | Defensive web review and testing methodology support for authorized audits and OWASP alignment. | `"web security review"`, `"OWASP checklist"`, `"pentest review"` |

### 2. 💥 Vulnerability & Exploit Detection

| Skill | Focus & Detection Scope | Primary Triggers |
|---|---|---|
| [`business-logic-audit`](skills/business-logic-audit) | High-impact logic vulnerabilities: price tampering, workflow step bypasses, coupon stacking, and transaction limit evasion. | `"business logic audit"`, `"price manipulation"`, `"workflow bypass"` |
| [`race-condition-detector`](skills/race-condition-detector) | Concurrency bugs: TOCTOU race windows, database transaction isolation level flaws, double-spend vulnerabilities, and atomic locking. | `"find race conditions"`, `"TOCTOU audit"`, `"concurrency bug"` |
| [`sql-injection-detector`](skills/sql-injection-detector) | SQL injection, NoSQL injection ($where, $gt), and modern ORM bypasses (Prisma, TypeORM, SQLAlchemy, Hibernate). | `"check SQL injection"`, `"audit database queries"`, `"NoSQL injection"` |
| [`xss-detector`](skills/xss-detector) | Reflected, stored, and DOM-based Cross-Site Scripting. Flags unescaped sinks (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`). | `"find XSS"`, `"audit frontend XSS"`, `"DOM sink check"` |
| [`file-upload-security`](skills/file-upload-security) | Insecure file upload flaws: double extensions, MIME sniffing bypass, path traversal via filenames, zip slips, and SVG XSS. | `"audit file upload"`, `"secure file upload"`, `"upload path traversal"` |
| [`deserialization-detector`](skills/deserialization-detector) | Insecure object deserialization in Python (`pickle`), Java (`ObjectInputStream`), PHP (`unserialize`), and Node (`node-serialize`). | `"check deserialization"`, `"unsafe pickle"`, `"unserialize flaw"` |
| [`vulnerability-detector`](skills/vulnerability-detector) | Universal static taint and sink detection across CWE-89, CWE-78, CWE-22, CWE-502, and CWE-79. | `"vulnerability detector"`, `"static code scan"`, `"sink analysis"` |
| [`bug-finder`](skills/bug-finder) | Root-cause analysis engine for reproducing edge-case regressions, logic contradictions, and memory leaks. | `"find bug"`, `"root cause analysis"`, `"debug issue"` |

### 3. 🔐 Auth, Session & Secrets Security

| Skill | Focus & Detection Scope | Primary Triggers |
|---|---|---|
| [`auth-security`](skills/auth-security) | Authentication & authorization mechanisms: JWT signing flaws, OAuth2 redirect leaks, session fixation, and RBAC privilege escalation. | `"audit auth"`, `"JWT security"`, `"OAuth review"`, `"IDOR check"` |
| [`cookie-security`](skills/cookie-security) | HTTP cookie hygiene: `SameSite`, `HttpOnly`, `Secure` flags, `__Host-` and `__Secure-` prefix enforcement, and session hijacking. | `"audit cookies"`, `"cookie flags"`, `"SameSite security"` |
| [`secrets-scanner`](skills/secrets-scanner) | Detection of committed API keys, private keys, database credentials, tokens, and high-entropy strings across code and git history. | `"scan secrets"`, `"check API keys"`, `"pre-commit credentials"` |
| [`frontend-secret-scanner`](skills/frontend-secret-scanner) | Frontend-specific credential leaks: exposed `.env` in JS bundles, leaked production source maps, and localStorage credential abuse. | `"scan frontend secrets"`, `"check JS bundle keys"`, `"source map leak"` |
| [`crypto-auditor`](skills/crypto-auditor) | Cryptographic verification: flags broken ciphers (MD5, SHA1, DES, ECB), static IVs, weak PRNGs (`Math.random()`), and timing attacks. | `"audit crypto"`, `"weak cipher check"`, `"insecure randomness"` |

### 4. 📦 Supply Chain & Third-Party Code

| Skill | Focus & Detection Scope | Primary Triggers |
|---|---|---|
| [`supply-chain-security`](skills/supply-chain-security) | Software supply chain integrity: dependency confusion, typosquatting, post-install script abuse, lockfile poisoning, and SBOM audits. | `"supply chain audit"`, `"dependency confusion"`, `"SBOM review"` |
| [`dependency-audit`](skills/dependency-audit) | Automated CVE vulnerability auditing across package manifests (`npm`, `pip`, `cargo`, `go.mod`, `maven`). | `"audit dependencies"`, `"check CVEs"`, `"vulnerable packages"` |
| [`third-party-script-audit`](skills/third-party-script-audit) | Third-party tag risk: Google Tag Manager abuse, Meta Pixel data leakage, Magecart e-skimming, and Shadow DOM boundary bypass. | `"audit third party scripts"`, `"GTM security"`, `"Magecart risk"` |

### 5. ⚙️ DevSecOps, Review & SDLC Gates

| Skill | Focus & Detection Scope | Primary Triggers |
|---|---|---|
| [`pr-security-gate`](skills/pr-security-gate) | Automated Pull Request security gate: structured approval criteria, PR blocker checklists, and diff risk classification. | `"review PR security"`, `"PR security gate"`, `"pre-merge checklist"` |
| [`code-review-security`](skills/code-review-security) | Structured secure code review: trust boundary mapping, taint tracing from sources to dangerous sinks, and hardening diffs. | `"secure code review"`, `"is this safe"`, `"harden code"` |
| [`sast-scanner`](skills/sast-scanner) | Static Application Security Testing orchestration: Semgrep, Bandit, CodeQL, ESLint rules, and SARIF output triage. | `"run SAST"`, `"Semgrep rules"`, `"SARIF triage"` |
| [`secure-sdlc`](skills/secure-sdlc) | Shift-left security engineering: threat modeling intake, abuse case user stories, security acceptance criteria, and PR templates. | `"secure SDLC"`, `"threat modeling template"`, `"security stories"` |
| [`security-audit`](skills/security-audit) | End-to-end repository security audit evaluating OWASP Top 10, STRIDE threat models, secret posture, and CI/CD defenses. | `"security audit"`, `"full audit"`, `"OWASP posture"` |
| [`error-handling-audit`](skills/error-handling-audit) | Error handling & logging hygiene: stack trace leaks, verbose database error responses, sensitive data in logs, and CWE-209. | `"audit error handling"`, `"stack trace leak"`, `"log hygiene"` |
| [`threat-modeler`](skills/threat-modeler) | Architecture threat modeling using STRIDE, DREAD scoring, data flow diagrams, and attack mitigation trees. | `"threat model"`, `"STRIDE analysis"`, `"DREAD score"` |

### 6. 📱 Client & Mobile Security

| Skill | Focus & Detection Scope | Primary Triggers |
|---|---|---|
| [`client-side-security`](skills/client-side-security) | Advanced browser-side attacks: DOM clobbering, prototype pollution, `postMessage` origin validation, clickjacking, and iframe sandboxing. | `"client side security"`, `"DOM clobbering"`, `"postMessage check"` |
| [`mobile-security-review`](skills/mobile-security-review) | iOS and Android security: Keychain / Keystore storage, deep link hijacking, exported Android components, WebView settings, and cert pinning. | `"mobile security review"`, `"iOS security"`, `"Android security audit"` |

---

## 🤖 Agent Workflows & Prompt Examples

Here is how you can command your agent to perform multi-stage security workflows:

### Workflow 1: Pre-Release Comprehensive Audit
```markdown
Run a full security audit on this repository:
1. Use the security-audit skill to baseline our OWASP Top 10 posture.
2. Use the secrets-scanner and frontend-secret-scanner skills to verify no credentials exist in code or client bundles.
3. Use the dependency-audit skill to flag all high and critical CVEs.
Output a prioritized remediation roadmap with exact file locations and code fixes.
```

### Workflow 2: Automated Pull Request Security Review
```markdown
Use the pr-security-gate skill to analyze the git diff on this branch against main:
- Check for newly introduced endpoints without auth middleware.
- Check for unparameterized database queries using sql-injection-detector.
- Issue a PASS, PASS_WITH_WARNINGS, or BLOCK decision with justification.
```

### Workflow 3: FinTech & E-Commerce Business Logic Hardening
```markdown
Use the business-logic-audit and race-condition-detector skills to audit our payment and coupon checkout handler in src/services/checkout.ts:
- Test for quantity manipulation and negative balances.
- Check for race conditions in promo code redemptions.
- Provide a patch utilizing database row locking or distributed Redis mutexes.
```

---

## 🏗️ Skill Architecture & Specification

Every skill in Bug Finder Kit follows a standardized agent-readable specification designed for predictable execution across autonomous coding runtimes:

```
skills/<skill-name>/
├── SKILL.md                  # Main agent instructions, frontmatter, & phased audit methodology
├── README.md                 # Human documentation, scope boundaries, & invocation triggers
└── references/
    └── detailed-guide.md     # In-depth technical guide, vulnerability theory, & remediation guides
```

### Validated YAML Frontmatter Standard:
```yaml
---
name: business-logic-audit
description: >
  Comprehensive business logic vulnerability auditing skill. Identifies flaws in application
  logic, state machine enforcement, financial transactions, pricing manipulation, workflow
  bypasses, and authorization edge cases.
triggers:
  - "business logic audit"
  - "price manipulation"
  - "workflow bypass"
  - "coupon stacking"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
tags: ["business-logic", "owasp-a04", "race-conditions", "workflow-security"]
date_added: "2026-10-26"
---
```

---

## 🛠️ CLI Reference

```text
@souvik65/bug-finder-kit v1.2.2

Usage:
  bug-finder init                 Interactive setup (detects editor, installs all skills)
  bug-finder add <skill...>       Install specific skills or entire suite
  bug-finder remove <skill...>    Uninstall specific skills
  bug-finder list                 Show all 32 available skills and descriptions

Options:
  -s, --skill <name>   Skill to install (repeatable)
  -t, --target <name>  agents | claude | cursor | windsurf | cline | vscode (default: agents)
  -d, --dir <path>     Install to any custom directory
  -g, --global         Install globally for all projects in your user profile
  -y, --yes            Skip prompts, install with sensible defaults (CI/CD friendly)
  -f, --force          Overwrite existing skill directories
  -h, --help           Show help
  -v, --version        Show version
```

### Common CLI Recipes:

```bash
# Install everything into Cursor in 2 seconds:
npx @souvik65/bug-finder-kit init --target cursor --yes

# Install only specific skills for a lightweight frontend project:
npx @souvik65/bug-finder-kit add spa-security csp-auditor frontend-secret-scanner --target cursor

# Install globally for Claude Code:
npx @souvik65/bug-finder-kit init --target claude --global --yes

# Verify installed skills:
npx @souvik65/bug-finder-kit list
```

---

## 🔒 Security & Privacy Statement

- **100% Offline & Local Execution:** Bug Finder Kit does not send code, tokens, or repository content to any external API or server.
- **No Telemetry:** No analytics, tracking, or network callbacks are included in the CLI or skill files.
- **Safe by Default:** All scanning rules are strictly read-only and designed for defensive code inspection and remediation.

---

## 🤝 Contributing

We welcome contributions of new agent skills, remediation templates, and rule enhancements!

1. Fork the repository: `https://github.com/Souvik65/bug-finder-kit`
2. Create a feature branch: `git checkout -b skill/my-new-skill`
3. Add your skill into `skills/<skill-name>/` following the [Tri-File Architecture](#-skill-architecture--specification).
4. Validate your skill with `node ./bin/cli.js list`.
5. Open a Pull Request with a clear description of detection rules and test cases.

---

## 📄 License

MIT © [Souvik](https://github.com/Souvik65) • Free to use in open-source and commercial projects.