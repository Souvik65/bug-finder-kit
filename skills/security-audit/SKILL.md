---
name: security-audit
description: >
  Comprehensive security audit skill for codebases. Performs OWASP Top 10 checks,
  STRIDE threat modeling, secrets archaeology, dependency supply chain analysis,
  CI/CD pipeline security, authentication review, and active vulnerability scanning.
  Activate when the user asks for a "security audit", "security review", "pentest review",
  "threat model", "OWASP check", "find security issues", or "harden the code".
triggers:
  - "security audit"
  - "security review"
  - "pentest review"
  - "threat model"
  - "OWASP"
  - "find security issues"
  - "harden"
  - "security scan"
  - "CSO review"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
---

# Security Audit — Comprehensive Codebase Security Review

> A structured, evidence-driven security audit framework covering OWASP Top 10,
> STRIDE threat modeling, secrets detection, dependency analysis, and more.
> Follow every phase in order. Do not skip steps without documented justification.

---

## Audit Modes

| Mode | When to use | Confidence gate |
|---|---|---|
| **Quick** | PR review, fast check | 8/10 — high-confidence findings only |
| **Comprehensive** | Monthly deep scan, pre-release | 2/10 — include speculative risks |
| **Targeted** | Specific component or CVE | Scope defined by user |

Ask the user which mode to use if not specified. Default: **Quick**.

---

## Phase 0 — Scope & Context

Before scanning, establish the audit perimeter.

### Collect
- [ ] Primary language(s) and frameworks
- [ ] Entry points: HTTP routes, CLI commands, message queues, file parsers
- [ ] Authentication mechanisms: sessions, JWT, OAuth, API keys
- [ ] Data stores: SQL, NoSQL, files, caches
- [ ] Third-party integrations: payment, SSO, cloud services
- [ ] Deployment target: cloud, on-prem, serverless, container
- [ ] Known threat actors and abuse scenarios

### Inventory
```
1. List all public entry points (routes, endpoints, exports).
2. List all data stores and their sensitivity level.
3. List all external service integrations.
4. Identify trust boundaries between components.
```

> **Rule:** Document scope explicitly before proceeding. Out-of-scope items
> must be noted, not silently ignored.

---

## Phase 1 — Secrets Archaeology

Find hardcoded credentials, tokens, and sensitive values committed to the codebase.

### Patterns to search
```
- API keys: [A-Za-z0-9]{20,} assigned to variables named *key*, *token*, *secret*, *password*, *credential*
- AWS: AKIA[0-9A-Z]{16}
- GitHub tokens: ghp_[A-Za-z0-9]{36}, ghs_, gho_, github_pat_
- Private keys: -----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----
- Connection strings: mongodb://, postgresql://, mysql:// with embedded credentials
- JWT secrets: secret: "...", JWT_SECRET=, jwtSecret =
- Slack/Discord webhooks: hooks.slack.com, discord.com/api/webhooks
- .env files committed: check git log for .env, secrets.json, credentials.json
```

### How to search
```bash
# Search for common secret patterns (print file and line only to prevent secret leakage in terminal/logs)
grep -rn "password\s*=\s*['\"][^'\"]\+['\"]" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" . \
    | awk -F: '{print $1 ":" $2 " [POTENTIAL_PASSWORD: REDACTED]"}'
grep -rn "secret\s*=\s*['\"][^'\"]\+['\"]" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" . \
    | awk -F: '{print $1 ":" $2 " [POTENTIAL_SECRET: REDACTED]"}'
grep -rn "AKIA[0-9A-Z]\{16\}" . | awk -F: '{print $1 ":" $2 " [AWS_KEY_ID: REDACTED]"}'
grep -rn -e "-----BEGIN.*PRIVATE KEY-----" . | awk -F: '{print $1 ":" $2 " [PRIVATE_KEY: REDACTED]"}'
git log --all --full-history --name-only -- "*.env" "**/.env" "**/secrets.*" "**/credentials.*"
```

### Report format
| File | Line | Type | Severity | Finding |
|---|---|---|---|---|
| config/db.js | 12 | Hardcoded password | CRITICAL | DB password in plaintext |

---

## Phase 2 — OWASP Top 10 Scan

Systematically check each OWASP category.

### A01 — Broken Access Control
- [ ] Verify all routes/endpoints enforce authorization (not just authentication)
- [ ] Check for insecure direct object references (IDOR): numeric IDs accessible by any user
- [ ] Confirm admin endpoints are gated behind role checks
- [ ] Test for path traversal: `../`, `%2e%2e%2f` in file-serving endpoints
- [ ] Check CORS policy: `Access-Control-Allow-Origin: *` with credentials

### A02 — Cryptographic Failures
- [ ] Identify sensitive data in transit: is TLS enforced everywhere?
- [ ] Identify sensitive data at rest: passwords hashed (bcrypt/argon2/scrypt)? PII encrypted?
- [ ] Weak algorithms: MD5, SHA1, DES, ECB mode — flag all uses
- [ ] Random number generation: `Math.random()` or `rand()` for security tokens
- [ ] Hard-coded encryption keys or IVs

### A03 — Injection
- [ ] SQL injection: raw string concatenation in queries
- [ ] Command injection: `exec()`, `eval()`, `subprocess.shell=True` with user input
- [ ] LDAP injection, XPath injection, template injection
- [ ] NoSQL injection: MongoDB `$where`, `$regex` with user input
- [ ] Log injection: user input written directly to logs without sanitization

### A04 — Insecure Design
- [ ] Missing rate limiting on login, registration, password reset endpoints
- [ ] No account lockout after repeated failures
- [ ] Sensitive operations without re-authentication (e.g., changing email/password)
- [ ] Business logic flaws: can a user buy items at negative price, skip steps?

### A05 — Security Misconfiguration
- [ ] Default credentials in databases, admin panels, frameworks
- [ ] Debug mode / verbose errors exposed in production
- [ ] Unnecessary features enabled (directory listing, unused services)
- [ ] Security headers missing: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- [ ] Overly permissive file permissions

### A06 — Vulnerable and Outdated Components
- [ ] Run dependency audit (see Phase 3)
- [ ] Flag packages with known CVEs
- [ ] Identify end-of-life runtimes or frameworks

### A07 — Identification and Authentication Failures
- [ ] Weak password policy (min length < 8, no complexity)
- [ ] Brute force not prevented on login
- [ ] Password reset via predictable tokens or user-controlled parameters
- [ ] Session IDs in URLs, not rotated after login, long expiry
- [ ] Multi-factor authentication: available? enforced for sensitive roles?

### A08 — Software and Data Integrity Failures
- [ ] Deserialization of untrusted data (pickle, Java serialization, YAML.load, eval)
- [ ] CI/CD pipeline: are steps authenticated? Is the pipeline itself auditable?
- [ ] Package integrity: lockfiles present and committed? Checksum verification?

### A09 — Security Logging and Monitoring Failures
- [ ] Authentication events logged (success and failure)
- [ ] Logs contain user ID, timestamp, IP address, action
- [ ] Sensitive data NOT logged (passwords, tokens, PII)
- [ ] Log injection prevented (user input sanitized before logging)
- [ ] Alerts defined for anomalous patterns

### A10 — Server-Side Request Forgery (SSRF)
- [ ] URL parameters that trigger server-side HTTP requests
- [ ] Webhooks, redirects, or file-fetch features with user-supplied URLs
- [ ] Cloud metadata endpoint accessible: `169.254.169.254`
- [ ] Allowlist for permitted destinations?

---

## Phase 3 — Dependency Supply Chain

### Steps
1. Identify all package managers in use (npm, pip, cargo, go.mod, maven, gem).
2. Check for a lockfile — absence is itself a risk.
3. Run the appropriate audit tool:

```bash
# JavaScript/TypeScript
npm audit --json
yarn audit --json

# Python
pip-audit --json
safety check --json

# Go
govulncheck ./...

# Ruby
bundler-audit check

# Java/Maven
mvn dependency-check:check
```

4. Triage results:
   - CRITICAL/HIGH with a known exploit path → **must fix before release**
   - MEDIUM → fix within sprint
   - LOW/INFO → document and schedule

5. Check for dependency confusion attack surface:
   - Internal package names that could be squatted on public registries
   - Wildcard version ranges (`*`, `>=0.0.0`, `latest`)

---

## Phase 4 — Authentication & Session Security

Trace the complete auth flow end-to-end.

### Checklist
- [ ] Password hashing: bcrypt (cost ≥12), argon2id, or scrypt — never MD5/SHA1
- [ ] Session tokens: cryptographically random, ≥128 bits entropy
- [ ] Session fixation: session ID regenerated after login
- [ ] Session expiry: idle timeout and absolute timeout configured
- [ ] Secure cookie flags: `HttpOnly`, `Secure`, `SameSite=Strict` (or `Lax`)
- [ ] JWT: algorithm not `none`, secret not weak, expiry set, audience validated
- [ ] OAuth: state parameter present, redirect_uri strictly validated
- [ ] Password reset: token single-use, short-lived (≤1 hour), invalidated after use

---

## Phase 5 — API Security

### REST APIs
- [ ] All endpoints require authentication except documented public ones
- [ ] Authorization checked at the resource level (not just route level)
- [ ] Input validation on every parameter (type, length, format)
- [ ] Rate limiting on write operations and expensive reads
- [ ] Sensitive fields excluded from responses (password hash, internal IDs)
- [ ] Error responses don't leak stack traces or internal paths in production

### GraphQL (if present)
- [ ] Introspection disabled in production
- [ ] Depth limiting to prevent nested query DoS
- [ ] Field-level authorization (not just resolver-level)
- [ ] Batching limits to prevent amplification attacks

---

## Phase 6 — Infrastructure & CI/CD

### CI/CD Pipeline
- [ ] Secrets stored in CI secret store, not in pipeline YAML or scripts
- [ ] Pipeline runs as least-privilege service account
- [ ] Third-party actions pinned to commit hash (not floating tag)
- [ ] Artifact integrity: builds signed or checksummed
- [ ] Pull request validation: external contributors cannot access secrets

### Infrastructure
- [ ] Principle of least privilege on IAM roles/policies
- [ ] Public storage buckets: none exist without explicit justification
- [ ] Network segmentation: databases not publicly accessible
- [ ] Monitoring and alerting configured for authentication failures

---

## Phase 7 — Report Generation

### Structure
```markdown
# Security Audit Report — [Project Name]
**Date:** YYYY-MM-DD  **Mode:** Quick | Comprehensive  **Auditor:** bug-finder-kit

## Executive Summary
<2-3 sentences: overall security posture, critical count, top risk>

## Findings

### CRITICAL (must fix before release)
#### SEC-001: [Title]
- **OWASP Category:** A01 / A03 / ...
- **Location:** `path/to/file.ext:LINE`
- **Description:** What the vulnerability is and how it can be exploited
- **Impact:** What an attacker can achieve
- **Remediation:** Specific code change required

### HIGH
...

### MEDIUM
...

### LOW / INFORMATIONAL
...

## Positive Findings
<What the codebase does well>

## Recommendations (not bugs, but improvements)
...
```

### Severity definitions
| Severity | Criteria |
|---|---|
| **CRITICAL** | Unauthenticated RCE, auth bypass, full data exfiltration possible |
| **HIGH** | Authenticated exploit with significant impact, stored XSS, SQLi |
| **MEDIUM** | Limited scope exploit, missing security header, outdated dependency with known CVE |
| **LOW** | Defense-in-depth missing, best practice deviation, no known exploit |

---

## Rules of Engagement

1. **Cite every finding** with file path, line number, and exact code snippet.
2. **No speculation** — only report confirmed or high-confidence findings in Quick mode.
3. **Redact secrets** found during the audit — write `<REDACTED>` and report location only.
4. **Minimal intrusion** — do not exploit vulnerabilities, just document them.
5. **Prioritize by impact** — a developer must know what to fix first.
6. **Include remediation** — every finding must include a specific, actionable fix.
7. **Track trends** — if previous audit reports exist, note new vs. resolved vs. regressed findings.
