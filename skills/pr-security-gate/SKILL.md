---
name: pr-security-gate
description: >
  Automated pull request security review and approval gate skill. Provides a structured,
  risk-weighted security verification framework for PRs touching new API endpoints,
  authentication/authorization flows, cryptographic implementations, sensitive data
  handling, third-party dependencies, and database migrations. Enforces pre-merge checklists,
  diff classification, risk-scoring heuristics, and automated CI/CD gating. Activate when
  the user asks to "audit PR for security", "PR security review", "pull request security checklist",
  "security review gate", "diff security scan", "pre-merge security check", or "merge approval checklist".
triggers:
  - "PR security review"
  - "pull request security checklist"
  - "PR security gate"
  - "pre-merge security check"
  - "diff security scan"
  - "audit PR for security"
  - "pull request gate"
  - "endpoint change review"
  - "auth change review"
  - "code review security checklist"
  - "merge approval checklist"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
tags: "[pr-security, code-review, ci-cd, gate, pre-merge, diff-analysis, security-checklist, pull-request]"
date_added: "2026-10-23"
---

# Pull Request (PR) Security Gate & Pre-Merge Verification

> The pull request boundary is the single most critical checkpoint in the Software
> Development Lifecycle (SDLC). Security bugs caught during PR review cost a fraction
> of post-deployment incidents to fix and never reach customer-facing production systems.
>
> This skill establishes a **deterministic, risk-weighted security gate** for evaluating
> git diffs before merging. It flags high-risk modifications—such as new API routes,
> middleware changes, cryptographic alterations, schema migrations, and dependency
> updates—and provides actionable pass/fail gating criteria.

---

## PR Security Gate Framework & Risk Scoring Matrix

Every pull request must be classified into a risk tier based on modified file paths and code semantics:

```
PR Risk Classification
  ├── Tier 1: Critical (Mandatory AppSec Review & 2 Approvals)
  │     ├── Authentication & session management (OAuth, JWT, passwords, cookies)
  │     ├── Authorization & access control middleware / RBAC decorators
  │     ├── Cryptographic algorithms, hashing, signing, key management
  │     └── Direct raw SQL queries or database permission migrations
  │
  ├── Tier 2: High (Automated SAST Pass + Peer Security Checklist)
  │     ├── New public or internal API endpoints and routing tables
  │     ├── File upload, serialization/deserialization handlers
  │     ├── Network integrations (HTTP clients, webhooks, SSRF sinks)
  │     └── Third-party dependency additions or lockfile updates
  │
  ├── Tier 3: Medium (Standard Peer Review + Automated Linter Pass)
  │     ├── Business logic updates, state machine changes
  │     ├── Sensitive data models, logging, analytics events
  │     └── Frontend rendering sinks (dangerouslySetInnerHTML, v-html)
  │
  └── Tier 4: Low (Automated CI Pass)
        ├── CSS/styling updates, static asset changes, documentation
        └── Unit test additions without production code changes
```

---

## Phase 1: High-Risk Diff Triggers & Automatic Merge Blockers

When evaluating a PR diff, immediately trigger an **AUTOMATIC MERGE BLOCK** if any of the
following patterns are detected:

| Trigger Pattern | File / Code Signature | Risk | Remediation Required |
|---|---|---|---|
| **Hardcoded Secrets** | API keys, private keys, connection strings in diff | Credential Leak | Revoke key, rotate, move to secrets vault, scrub git history |
| **Auth Bypass / Disabled Security** | `@SecurityRequirement(null)`, `verify=False`, `@PermitAll` on sensitive route | Unauthorized Access | Enforce explicit authentication and role checks |
| **Raw SQL String Interpolation** | `f"SELECT * FROM users WHERE id = '{user_id}'"` | SQL Injection | Replace with parameterized query or ORM bindings |
| **Disabled TLS / Certificate Checks** | `NODE_TLS_REJECT_UNAUTHORIZED='0'`, `CURLOPT_SSL_VERIFYPEER => 0` | MITM Attack | Remove debug override; restore strict TLS verification |
| **Permissive CORS Wildcard with Credentials** | `ACAO: *` combined with `ACAC: true` | Credential Leak | Enforce strict origin allowlist |
| **Unsanitized Raw HTML Sink** | `dangerouslySetInnerHTML`, `v-html` without DOMPurify | Cross-Site Scripting | Add contextual sanitization or use standard text bindings |

---

## Phase 2: New API Endpoints & Route Modifications

When a PR adds new endpoints (`app.post('/api/...')`, `@PostMapping`, `@router.get`):

### Audit Verification Checklist
1. **Authentication Requirement:**
   - [ ] Is the endpoint explicitly marked as public or private?
   - [ ] If private, does it pass through the authentication middleware/guard?
   - [ ] Does it check the authenticated caller's identity (no blind acceptance of client-supplied user IDs)?
2. **Authorization & Multi-Tenancy:**
   - [ ] Is role-based or attribute-based access control (RBAC/ABAC) verified?
   - [ ] Does the query enforce tenancy scoping (`WHERE tenant_id = session.tenant_id`) to prevent BOLA/IDOR?
3. **Input Validation & Parsing:**
   - [ ] Is request body, query parameter, and path parameter data parsed through a strict schema validator (Zod, Pydantic, Joi, Bean Validation)?
   - [ ] Are unexpected/extra fields stripped or rejected (preventing Mass Assignment)?
4. **Rate Limiting & Abuse Prevention:**
   - [ ] Is there rate limiting applied to brute-force-sensitive endpoints (login, OTP, reset password, export)?

### Diff Comparison: Vulnerable vs Gated Endpoint

```diff
// ❌ VULNERABLE: Direct route addition missing auth, schema, and IDOR validation
+ app.post('/api/documents/:id/delete', async (req, res) => {
+   // IDOR: No check if req.session.userId owns req.params.id!
+   await db.documents.delete({ where: { id: req.params.id } });
+   res.json({ success: true });
+ });

// ✅ GATED & SECURE: Authenticated, authorized, and schema-validated
+ app.delete('/api/documents/:id', requireAuth, validate(DocumentIdParamSchema), async (req, res) => {
+   const doc = await db.documents.findUnique({ where: { id: req.params.id } });
+   if (!doc || doc.organizationId !== req.user.organizationId) {
+     return res.status(404).json({ error: 'Document not found' });
+   }
+   await db.documents.delete({ where: { id: req.params.id } });
+   res.status(204).send();
+ });
```

---

## Phase 3: Authentication & Authorization Flow Changes

Any pull request touching auth configuration, token generation, password hashing, or middleware
must satisfy the following gates:

### Mandatory Verification Gates
- **Session & Token Regeneration:** When login occurs, is the session ID or JWT regenerated to prevent session fixation?
- **Token Scope & Expiry:** Are JWT expiration claims (`exp`) enforced? Are secret keys read from environment secrets, never defaults?
- **Middleware Ordering:** If middleware chain order is modified (e.g. Express `app.use()`, Spring Security filter chain), ensure auth runs **before** route handlers and body parsers.
- **Fail-Closed Principle:** If an authorization check encounters an error, does it fail closed (default deny) rather than permitting execution?

```python
# ❌ VULNERABLE: Fail-open authorization logic in PR
def check_permission(user, resource):
    try:
        return permissions_service.verify(user.id, resource.id)
    except TimeoutError:
        logger.warning("Auth service down, allowing request")
        return True # CRITICAL FLAW: Fails open!

# ✅ GATED: Strict fail-closed authorization
def check_permission(user, resource):
    try:
        return permissions_service.verify(user.id, resource.id)
    except Exception as exc:
        logger.error(f"Authorization service failed: {exc}")
        return False # Safe: Fails closed
```

---

## Phase 4: Cryptography & Secret Handling Changes

Check for cryptographic algorithms and randomness sources:

### Cryptographic Verification Gate
- [ ] **No Legacy Ciphers:** No use of MD5, SHA-1, DES, 3DES, or RC4 for security purposes.
- [ ] **Secure Password Hashing:** Use Argon2id, bcrypt (work factor >= 12), or PBKDF2 (>= 600,000 iterations). Never use plain SHA-256 for passwords.
- [ ] **Cryptographic Randomness:** Use `crypto.randomBytes()`, `secrets.token_hex()`, or `SecureRandom`. Disallow `Math.random()`, `random.random()`, or `rand()`.
- [ ] **Constant-Time Comparison:** Use `crypto.timingSafeEqual()` or `hmac.compare_digest()` for tokens, signatures, and hashes.

```javascript
// ❌ VULNERABLE: Timing attack on webhook secret in PR diff
+ if (req.headers['x-signature'] === calculateHmac(req.body)) { ... }

// ✅ GATED: Constant-time comparison
+ const expectedSig = Buffer.from(calculateHmac(req.body));
+ const actualSig = Buffer.from(req.headers['x-signature'] || '');
+ if (expectedSig.length === actualSig.length && crypto.timingSafeEqual(expectedSig, actualSig)) { ... }
```

---

## Phase 5: Sensitive Data, PII & Database Migrations

### Sensitive Data Audit Checklist
- [ ] **Logging Sanitization:** Are passwords, credit card numbers, SSNs, API tokens, or session IDs scrubbed from application logs?
- [ ] **Database Schema Migrations:** Does any new database migration add plaintext columns for sensitive data that require encryption at rest?
- [ ] **Data Export Limits:** Do new export or listing queries include pagination and limit bounds to prevent data scraping or memory exhaustion?

---

## Phase 6: Dependency, Lockfile & Supply Chain Changes

When `package.json`, `package-lock.json`, `requirements.txt`, or `pom.xml` changes:

### Dependency Verification Gate
- [ ] **No Unpinned Versions:** Disallow open ranges (`*`, `latest`) in production dependencies.
- [ ] **Lockfile Consistency:** Both manifest (`package.json`) and lockfile (`package-lock.json`) must be committed together.
- [ ] **Automated CVE Audit:** Run `npm audit`, `pip-audit`, or `govulncheck`. Block merge on High/Critical vulnerabilities.
- [ ] **Typosquatting Check:** Check newly introduced packages against official registry download counts and creation dates.

---

## Phase 7: Automated PR Diff Scanner Script

This PowerShell script inspects the current git diff against the target branch (e.g. `main`)
and flags high-risk changes:

```powershell
# PowerShell PR Security Gate Scanner
param([string]$TargetBranch = "origin/main")

Write-Host "=== Analyzing PR Diff Against $TargetBranch ===" -ForegroundColor Cyan

$diff = git diff $TargetBranch...HEAD

$blockersFound = 0

function Check-Pattern($pattern, $description, $severity) {
    param($pattern, $description, $severity)
    $matches = [regex]::Matches($diff, "^\+.*($pattern)", [System.Text.RegularExpressions.RegexOptions]::Multiline)
    if ($matches.Count -gt 0) {
        Write-Host "[$severity] $description (Occurrences: $($matches.Count))" -ForegroundColor Red
        foreach ($m in $matches | Select-Object -First 3) {
            Write-Host "  Line: $($m.Value.Trim())" -ForegroundColor Gray
        }
        $script:blockersFound += $matches.Count
    }
}

# 1. Hardcoded Secrets
Check-Pattern "(?i)(api[_-]?key|secret[_-]?key|password|jwt_secret)\s*=\s*['\"][A-Za-z0-9_\-]{8,}['\"]" "Potential Hardcoded Secret" "CRITICAL"

# 2. Disabled Security Controls
Check-Pattern "NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0['\"]?" "Disabled Node TLS Verification" "CRITICAL"
Check-Pattern "verify\s*=\s*False" "Disabled SSL Verification in Python" "CRITICAL"
Check-Pattern "dangerouslySetInnerHTML" "Unsanitized Raw HTML Sink in React" "HIGH"
Check-Pattern "v-html" "Unsanitized Raw HTML Sink in Vue" "HIGH"

# 3. SQL Injection Sinks
Check-Pattern "execute\s*\(\s*f['\"].*\{" "Python Raw SQL f-string Interpolation" "CRITICAL"
Check-Pattern "query\s*\(\s*`SELECT.*\$\{" "JavaScript Raw SQL Template String" "CRITICAL"

# 4. Insecure Randomness
Check-Pattern "Math\.random\(\)" "Insecure Pseudo-Random Number Generator" "MEDIUM"

Write-Host "`n=== PR Scan Summary ===" -ForegroundColor Cyan
if ($blockersFound -gt 0) {
    Write-Host "❌ PR SECURITY GATE FAILED: $blockersFound potential security issues detected." -ForegroundColor Red
    exit 1
} else {
    Write-Host "✅ PR SECURITY GATE PASSED: No automated blocker patterns detected." -ForegroundColor Green
    exit 0
}
```

---

## Phase 8: PR Review Sign-Off Template & Blocking Report

When reviewing pull requests, post this structured sign-off report as a PR comment:

### PR Security Gate Comment Template

```markdown
## 🛡️ Pull Request Security Gate Evaluation

**Status:** ❌ ACTION REQUIRED / ✅ APPROVED

### 1. Risk Tier Classification
- [ ] Tier 1 (Critical) — Auth, Crypto, Middleware, Raw Database
- [x] Tier 2 (High) — New API Endpoints, File Handling, External Network
- [ ] Tier 3 (Medium) — Business Logic, Data Model Changes
- [ ] Tier 4 (Low) — Frontend Styling, Docs, Tests

### 2. Verification Gate Checklist
- [x] **Authentication:** All new routes require verified session credentials.
- [x] **Authorization:** Tenant isolation validated (`WHERE tenant_id = current_tenant`).
- [ ] **Input Validation:** ⚠️ *FAIL* — `src/api/reports.ts:32` accepts raw query string into file path without sanitization.
- [x] **Secrets:** No hardcoded tokens or API keys committed.
- [x] **Dependencies:** Lockfile integrity validated; 0 Critical/High CVEs.

### 3. Required Remediations Before Approval
1. **File Path Sanitization:** In `src/api/reports.ts`, replace raw path concatenation with `path.basename()` and validate against an allowlist of allowed report identifiers.

---
*Reviewed by Bug-Finder-Kit Security Gate*
```
