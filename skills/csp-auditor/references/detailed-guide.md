# CSP Auditor — Technical Reference Guide

## 1. CSP Directive Inheritance Chain

When a specific directive is absent, the browser falls back through this chain.
Attackers exploit missing specific directives to load disallowed resources
via the overly-permissive `default-src`.

```
script-src → default-src
style-src  → default-src
img-src    → default-src
font-src   → default-src
connect-src → default-src
media-src  → default-src
object-src → default-src   ← Always override to 'none'
frame-src  → child-src → default-src
worker-src → child-src → default-src
manifest-src → default-src

base-uri     (NO fallback — if absent, all base URIs are allowed)
form-action  (NO fallback — if absent, all form targets are allowed)
frame-ancestors (NO fallback — must be set explicitly)
```

> **Key Implication:** Even if `default-src 'none'` is set, missing `base-uri`
> allows `<base href="//attacker.com/">` to redirect all relative URLs.

---

## 2. Google CSP Evaluator Integration

Google provides a free public CSP evaluation API and web tool:

```bash
# CLI Usage
CSP_HEADER="default-src 'self'; script-src 'self' 'unsafe-inline'"
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$CSP_HEADER'))")
curl "https://csp-evaluator.withgoogle.com/getCSPEvaluation?csp=$ENCODED" | jq .

# Web UI (paste raw CSP)
# https://csp-evaluator.withgoogle.com/
```

**Score Interpretation:**
- 🔴 High-severity findings: `unsafe-inline`, wildcard hosts, missing `object-src`
- 🟡 Medium findings: missing `base-uri`, `report-uri` absent
- 🟢 Clean: nonce/hash-based, `strict-dynamic`, no bypasses detected

---

## 3. Known CSP Bypass Endpoints by CDN (Reference)

| CDN / Service | Bypass Type | Example Path |
|---|---|---|
| `ajax.googleapis.com` | JSONP | `/ajax/libs/...?callback=alert(1)` |
| `maps.googleapis.com` | JSONP | `/maps/api/...?callback=eval` |
| `accounts.google.com` | Open Redirect | `/o/oauth2/revoke?callback=...` |
| `www.googleapis.com` | JSONP | `/...?callback=alert` |
| `yandex.ru` | JSONP | Various endpoints |
| GitHub `raw.githubusercontent.com` | User content | Attacker uploads `.js` to public repo |
| `cdnjs.cloudflare.com` | Library CDN | AngularJS 1.x, Prototype.js (template bypass) |

> ⚠️ Use this table as a checklist for allowed domains. If any of these appear
> in `script-src`, CSP protection is severely weakened.

---

## 4. Nonce Implementation Checklist (Framework-Specific)

### Next.js (App Router)
```javascript
// middleware.ts — Generate per-request nonce
import { NextResponse } from 'next/server';
import crypto from 'crypto';

export function middleware(request) {
    const nonce = Buffer.from(crypto.randomBytes(16)).toString('base64');
    const csp = `script-src 'nonce-${nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'self';`;

    const requestHeaders = new Headers(request.headers);
    requestHeaders.set('x-nonce', nonce);
    requestHeaders.set('Content-Security-Policy', csp);

    const response = NextResponse.next({ request: { headers: requestHeaders } });
    response.headers.set('Content-Security-Policy', csp);
    return response;
}
```

### Django (Python)
```python
# django-csp package
MIDDLEWARE = ['csp.middleware.CSPMiddleware']

CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)  # Nonces auto-injected by {% csp_nonce %} template tag
CSP_INCLUDE_NONCE_IN = ['script-src']
CSP_OBJECT_SRC = ("'none'",)
CSP_BASE_URI = ("'self'",)
```

### Nginx Nonce Generation (Lua/OpenResty)
```nginx
set_by_lua_block $nonce {
    local bytes = {}
    for i = 1, 16 do bytes[i] = string.char(math.random(0, 255)) end
    return require("resty.base64").encode(table.concat(bytes))
}

add_header Content-Security-Policy "script-src 'nonce-$nonce' 'strict-dynamic'; object-src 'none';" always;
```

---

## 5. Trusted Types Browser Support & Polyfill

| Browser | Trusted Types Support |
|---|---|
| Chrome 83+ | ✅ Full native support |
| Edge 83+ | ✅ Full native support |
| Firefox | ⚠️ Behind flag (no stable support as of 2024) |
| Safari | ⚠️ Not yet implemented |

**Polyfill for cross-browser compatibility:**
```html
<script src="https://w3c.github.io/trusted-types/dist/es5/trustedtypes.build.js" data-csp-hash="sha256-..."></script>
```

**Feature Detection:**
```javascript
if (window.trustedTypes && window.trustedTypes.createPolicy) {
    const policy = trustedTypes.createPolicy('default', {
        createHTML: (html) => DOMPurify.sanitize(html, { RETURN_TRUSTED_TYPE: true })
    });
}
```
