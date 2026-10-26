---
name: csp-auditor
description: >
  Content Security Policy (CSP) analysis, bypass detection, and hardening skill.
  Evaluates CSP header strength, detects policy weaknesses (unsafe-inline, unsafe-eval,
  wildcard sources, missing directives), identifies known CSP bypass techniques via
  JSONP, Angular/React template injection, open redirects, and CDN allowlist abuse.
  Analyzes nonce-based vs. hash-based vs. allowlist-based policy approaches, reviews
  Trusted Types adoption to prevent DOM XSS, and validates CSP report-uri/report-to
  monitoring setup. Activate when the user asks to "audit CSP", "review Content Security
  Policy", "check CSP bypass", "unsafe-inline CSP", "nonce-based CSP", "Trusted Types",
  "CSP report-uri", or "strengthen CSP headers".
triggers:
  - "CSP"
  - "Content Security Policy"
  - "unsafe-inline"
  - "unsafe-eval"
  - "nonce CSP"
  - "CSP bypass"
  - "Trusted Types"
  - "report-uri"
  - "CSP header"
  - "script-src"
  - "default-src"
  - "CSP audit"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
tags: "[csp, xss, content-security-policy, trusted-types, nonce, bypass-detection, frontend-security]"
date_added: "2026-10-22"
---

# CSP Auditor — Content Security Policy Analysis & Hardening

> Content Security Policy (CSP) is the primary browser-enforced defence against
> Cross-Site Scripting (XSS), clickjacking, and data injection attacks. However, a
> misconfigured or overly permissive CSP can provide a false sense of security while
> leaving every bypass route open.

> This skill systematically evaluates CSP effectiveness, detects bypass-enablers,
> recommends nonce/hash-based hardening, and validates Trusted Types adoption for
> DOM XSS prevention.

---

## CSP Threat Model

```
Browser Document
  └── CSP Header (from server or <meta> tag)
        ├── Directive Completeness
        │     ├── Missing directives (default-src fallback chain)
        │     └── Uncovered resource types (workers, frames, forms)
        ├── Source Expression Weaknesses
        │     ├── Wildcards (* / https:)
        │     ├── unsafe-inline (disables inline script blocking)
        │     ├── unsafe-eval (allows eval(), Function(), setTimeout(string))
        │     └── data: / blob: URIs in script-src
        ├── Allowlist Bypass Vectors
        │     ├── JSONP endpoints on allowlisted domains
        │     ├── Open redirectors on allowlisted domains
        │     ├── Angular/React CDN DOMPurify bypass via whitelisted CDN
        │     └── Subdomain wildcards (*.trusted.com) hosting attacker content
        ├── Nonce/Hash Implementation Gaps
        │     ├── Nonce reuse across requests
        │     ├── Nonce predictability (not cryptographically random)
        │     └── Hash mismatch (inline scripts not covered)
        └── DOM XSS (Trusted Types Gap)
              ├── document.write(), innerHTML, eval() sinks uncovered
              └── Framework-specific DOM sinks (React dangerouslySetInnerHTML)
```

---

## Phase 1 — CSP Discovery & Baseline Collection

### 1.1 Locate CSP Delivery Mechanisms

```bash
# Check HTTP response header (server-delivered)
curl -s -I https://target.example.com | grep -i "content-security-policy"

# Check for report-only mode (no enforcement — only logging!)
curl -s -I https://target.example.com | grep -i "content-security-policy-report-only"

# Check for CSP inside HTML <meta> tag (less secure — cannot protect headers, cookies)
grep -rn "http-equiv.*Content-Security-Policy" .
grep -rn "Content-Security-Policy" src/ public/ templates/
```

> ⚠️ **`Content-Security-Policy-Report-Only`** mode **does not block** any resources.
> Confirm whether the live policy is enforcing or merely reporting.

### 1.2 Parse and Structure the Policy

Split the CSP into individual directives for analysis:

```javascript
// Quick CSP parser (Node.js / browser console)
const csp = `default-src 'self'; script-src 'self' https://cdn.example.com 'unsafe-inline'; ...`;
const directives = Object.fromEntries(
    csp.split(';').map(d => d.trim().split(/\s+/)).map(([k, ...v]) => [k, v])
);
console.table(directives);
```

---

## Phase 2 — Directive Completeness Audit

### 2.1 CSP Directive Coverage Matrix

| Directive | Controls | Risk if Missing |
|---|---|---|
| `default-src` | Fallback for unlisted resource types | All unspecified types default to unrestricted |
| `script-src` | JavaScript execution | XSS via script injection |
| `style-src` | CSS stylesheets | CSS injection, data exfiltration via CSS |
| `img-src` | Image loads | Data exfiltration via pixel-tracking, SSRF via `<img>` tags |
| `connect-src` | XHR, Fetch, WebSocket | Data exfil via JavaScript-initiated requests |
| `font-src` | Web fonts | Timing side-channels via font loads |
| `frame-src` | `<iframe>` embeds | Clickjacking if not using `X-Frame-Options` too |
| `object-src` | Flash, plugins | Plugin-based XSS (always set to `'none'`) |
| `base-uri` | `<base href>` | Base hijacking allows relative URL redirection |
| `form-action` | `<form>` submission targets | Data phishing via form submission to attacker URL |
| `frame-ancestors` | Who may embed this page | Clickjacking (replaces `X-Frame-Options`) |
| `worker-src` | Web Workers, ServiceWorkers | Service worker hijacking |
| `manifest-src` | Web App Manifests | PWA manifest injection |
| `upgrade-insecure-requests` | Auto-upgrade HTTP to HTTPS | Mixed content attacks |

### 2.2 High-Priority Missing Directive Flags

```
[CRITICAL] script-src not defined → falls back to default-src → check default-src
[HIGH]     object-src not set to 'none' → allows Flash/plugin-based XSS bypasses
[HIGH]     base-uri not set to 'self' or 'none' → base tag injection redirects all relative URLs
[HIGH]     form-action not defined → forms can submit to arbitrary external origins
[MEDIUM]   frame-ancestors not set → use alongside X-Frame-Options: DENY for clickjacking defense
[MEDIUM]   worker-src not defined → Service Workers can be injected from allowed script-src origins
```

---

## Phase 3 — Source Expression Weakness Detection

### 3.1 Instant Fail Patterns

The following source expressions in `script-src` completely defeat CSP XSS protection:

| Expression | Risk Level | Why It Fails |
|---|---|---|
| `'unsafe-inline'` | 🔴 Critical | Allows all inline `<script>` and event handler attributes |
| `'unsafe-eval'` | 🔴 Critical | Allows `eval()`, `Function()`, `setTimeout('code')` |
| `*` (wildcard) | 🔴 Critical | Allows scripts from any origin |
| `https:` | 🔴 Critical | Allows scripts from any HTTPS origin |
| `data:` | 🔴 Critical | Allows `data:text/javascript,...` script URIs |
| `http:` | 🔴 Critical | Allows any insecure origin |
| `blob:` | 🔴 High | Allows dynamically-created JavaScript blobs |

### 3.2 Subdomain Wildcard Risks

```
# RISKY: Attacker can host content at attacker.trusted.com
script-src https://*.trusted.com

# RISKY: Broad CDN path allowances that include attacker-uploadable paths
script-src https://storage.googleapis.com https://user-content.githubusercontent.com
```

### 3.3 `unsafe-inline` Necessity & Nonce Migration

If a codebase currently relies on `'unsafe-inline'`:

```bash
# Find all inline event handlers in templates and HTML files
grep -rn "on[a-z]*\s*=" templates/ src/ public/ --include="*.html" --include="*.jsx" --include="*.tsx"

# Find all inline <script> blocks
grep -rn "<script>" templates/ src/ public/ --include="*.html"

# Find eval() and setTimeout(string) usage in JS
grep -rn "eval(\|setTimeout(\s*['\"]" src/ --include="*.js" --include="*.ts"
```

---

## Phase 4 — CSP Bypass Detection via Allowlisted Domains

Even a strict allowlist CSP can be bypassed if any allowlisted domain serves a
JSONP callback endpoint, an open redirector, or user-uploadable executable content.

### 4.1 JSONP Endpoint Bypass

If `script-src` allowlists a domain that hosts a JSONP endpoint, attackers inject
JavaScript via the callback parameter:

```html
<!-- CSP allows cdn.example.com — cdn.example.com also has a JSONP endpoint -->
<script src="https://cdn.example.com/api?callback=alert(document.cookie)//"></script>
```

**Detection:**
```bash
# Check allowlisted domains for JSONP endpoints
for domain in $(grep 'script-src' csp_policy.txt | tr ' ' '\n' | grep "^http"); do
    curl -s "$domain/api/user?callback=test" | head -5
done
```

**Known JSONP-providing CDNs / services:**
- Google APIs (`ajax.googleapis.com/ajax/libs/...?callback=`)
- jQuery CDN (`code.jquery.com`)
- Various analytics and payment SDK endpoints

### 4.2 Open Redirect Bypass

If an allowlisted domain has an open redirect (`/redirect?url=https://attacker.com`),
the `script-src` allowlist can be exploited:

```html
<script src="https://trusted.com/redirect?url=https://attacker.com/evil.js"></script>
```

### 4.3 Angular / Polymer Framework CDN Bypass

When Angular, Polymer, or older library CDNs are allowlisted, their template expression
evaluation can bypass CSP:

```html
<!-- If angularjs.org is in script-src, Angular expressions execute even without unsafe-eval -->
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js"></script>
<div ng-app>{{ $eval('alert(1)') }}</div>
```

**CSP Evaluator:**
```bash
# Google's CSP Evaluator API
curl "https://csp-evaluator.withgoogle.com/getCSPEvaluation?csp=script-src%20https%3A%2F%2Fajax.googleapis.com"
```

---

## Phase 5 — Nonce-Based & Hash-Based CSP Implementation

### 5.1 Nonce-Based CSP (Recommended for Dynamic Content)

A nonce is a cryptographically random, per-request, single-use value included in
both the CSP header and each `<script>` tag. Inline scripts without the valid nonce
are blocked.

**Requirements:**
- Nonce must be cryptographically random (minimum 128 bits / 16 bytes of entropy).
- Nonce must be **different for every HTTP response** (not static, not cached!).
- `'unsafe-inline'` is **ignored** by browsers that support nonces — safe to include for legacy compatibility but nonces take precedence.

```python
# Server-side nonce generation (Python/Flask)
import secrets, base64

@app.before_request
def generate_nonce():
    g.csp_nonce = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')

@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{g.csp_nonce}'; "
        f"style-src 'self' 'nonce-{g.csp_nonce}'; "
        f"object-src 'none'; "
        f"base-uri 'self';"
    )
    return response
```

```html
<!-- Template: inject nonce into every inline script -->
<script nonce="{{ g.csp_nonce }}">
    // This script is permitted by the nonce
    initializeApp();
</script>
```

**Nonce Audit Checks:**
```
□ Nonce generated per-request using CSPRNG (secrets.token_bytes, crypto.randomUUID, etc.)
□ Nonce NOT shared across cached responses or SSG static pages
□ Nonce NOT predictable (no sequential counter, no timestamp-based value)
□ 'strict-dynamic' included to propagate trust to dynamically-loaded scripts
□ No nonce value hardcoded in source code or configuration files
```

### 5.2 Hash-Based CSP (For Static Inline Scripts)

When inline scripts are static and do not change at runtime, compute their SHA-256
hash and include it in the policy:

```bash
# Generate SHA-256 hash for inline script content
echo -n 'console.log("app initialized");' | openssl sha256 -binary | base64
# Output: RFWVAbc1234XYZ...

# Include in CSP:
# script-src 'sha256-RFWVAbc1234XYZ='
```

### 5.3 `'strict-dynamic'` (Modern Trusted Script Propagation)

`'strict-dynamic'` permits scripts loaded dynamically by trusted (nonce/hash-approved)
scripts to also load sub-scripts, without maintaining an ever-growing allowlist:

```
Content-Security-Policy:
  script-src 'nonce-{random}' 'strict-dynamic' 'unsafe-inline' https:;
  object-src 'none';
  base-uri 'self';
```

> ⚠️ `'strict-dynamic'` overrides host allowlists in supporting browsers. The fallback
> `'unsafe-inline'` and `https:` are ignored in browsers that understand `'strict-dynamic'`.

---

## Phase 6 — Trusted Types (DOM XSS Prevention)

Trusted Types prevent **DOM-based XSS** by requiring all dangerous sink assignments
to use verified Trusted Type objects instead of raw strings.

### 6.1 Dangerous DOM Sinks Protected by Trusted Types

| DOM Sink | JavaScript Example |
|---|---|
| `innerHTML` | `element.innerHTML = userInput` |
| `outerHTML` | `div.outerHTML = data` |
| `document.write()` | `document.write('<script>...')` |
| `eval()` | `eval(dynamicCode)` |
| `script.src` | `scriptEl.src = untrustedUrl` |
| `scriptEl.text` | `scriptEl.text = payload` |

### 6.2 Enabling Trusted Types via CSP

```http
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types default;
```

### 6.3 Implementing a Trusted Types Policy

```javascript
// Define an explicit sanitizing Trusted Types policy
const sanitizePolicy = trustedTypes.createPolicy('default', {
    createHTML: (input) => {
        // DOMPurify integration
        return DOMPurify.sanitize(input, { RETURN_TRUSTED_TYPE: true });
    },
    createScriptURL: (input) => {
        // Only permit URLs from your own CDN
        const url = new URL(input);
        if (url.hostname !== 'assets.example.com') {
            throw new Error('Untrusted script URL blocked by Trusted Types policy');
        }
        return input;
    }
});

// Usage: explicit policy call required — raw strings fail
element.innerHTML = sanitizePolicy.createHTML(userInput);
```

---

## Phase 7 — Reporting & Monitoring (`report-uri` / `report-to`)

CSP violation reports give real-time visibility into injection attempts, allowlist
gaps, and third-party script changes.

### 7.1 Report-To Header Configuration

```http
Report-To: {"group":"csp-endpoint","max_age":10886400,"endpoints":[{"url":"https://reporting.example.com/csp"}]}

Content-Security-Policy:
  default-src 'self';
  script-src 'nonce-{random}' 'strict-dynamic';
  object-src 'none';
  base-uri 'self';
  report-to csp-endpoint;
```

### 7.2 CSP-Only vs. Report-Only Strategy

Deploy new or changed CSP policies in **Report-Only** mode first, monitor violation
reports for at least 2 weeks, resolve legitimate breakage, then promote to enforcing.

```
□ report-uri or report-to endpoint configured and receiving reports
□ Alert on spike in violation reports (potential XSS attempt or broken deploy)
□ Separate CSP Report-Only policy for testing new directives before enforcement
□ Reports reviewed regularly for new allowlist requirements (new 3rd party scripts)
```

---

## Phase 8 — Recommended Strong CSP Template

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'nonce-{RANDOM_PER_REQUEST}' 'strict-dynamic' 'unsafe-inline' https:;
  style-src 'self' 'nonce-{RANDOM_PER_REQUEST}';
  img-src 'self' data: https://trusted-cdn.example.com;
  font-src 'self' https://fonts.gstatic.com;
  connect-src 'self' https://api.example.com;
  frame-src 'none';
  frame-ancestors 'none';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  upgrade-insecure-requests;
  require-trusted-types-for 'script';
  trusted-types default dompurify;
  report-to csp-endpoint;
```

---

## Phase 9 — Finding Format & Severity Guide

### Severity Classification

| Severity | Condition |
|---|---|
| **Critical** | `script-src *`, `default-src *`, or no CSP present — complete XSS protection absent |
| **High** | `'unsafe-inline'` or `'unsafe-eval'` in `script-src` without nonce override; no `object-src 'none'` |
| **High** | Confirmed JSONP or open-redirect bypass vector on allowlisted domain |
| **Medium** | Missing `base-uri`, `form-action`, or `frame-ancestors` directives |
| **Medium** | Subdomain wildcard (`*.example.com`) in `script-src` |
| **Low** | `report-uri`/`report-to` not configured (no visibility into violations) |
| **Info** | CSP in Report-Only mode — not enforcing |

### Finding Template

```
### [Severity] CSP Weakness: <Title>
- Location: HTTP Response Header / <meta> tag / framework middleware
- Directive Affected: <e.g., script-src, object-src, base-uri>
- Weakness: <'unsafe-inline' present | wildcard | JSONP bypass | missing directive>
- Bypass Scenario:
    Attacker injects: <example XSS or JSONP payload>
    Reason permitted by policy: <why the current CSP allows it>
- Evidence:
    Current CSP: <paste directive>
- Remediation:
    - Migrate to nonce-based script-src with 'strict-dynamic'
    - Add: <missing directive and safe value>
    - Before & After CSP snippet
- Confidence: Confirmed | Likely | Requires Browser Testing
```
