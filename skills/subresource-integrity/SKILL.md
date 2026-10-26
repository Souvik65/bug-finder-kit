---
name: subresource-integrity
description: >
  Comprehensive Subresource Integrity (SRI) and external CDN asset security audit skill.
  Evaluates web applications for missing or invalid integrity hashes on external scripts
  and stylesheets, missing or misconfigured crossorigin attributes, CDN compromise
  vulnerability (Magecart attacks, DNS/BGP hijacking, CDN vendor breaches), dynamic
  third-party script risks (tag managers, analytics, payment iframes), automated SRI
  generation in build pipelines, and SRI monitoring/hash-drift detection. Activate when
  the user asks to "audit SRI", "subresource integrity review", "CDN script security",
  "Magecart defense", "integrity attribute check", "crossorigin anonymous audit", or
  "CDN asset hash validation".
triggers:
  - "subresource integrity"
  - "SRI"
  - "SRI audit"
  - "integrity attribute"
  - "CDN security"
  - "crossorigin anonymous"
  - "Magecart defense"
  - "third-party script risk"
  - "CDN compromise"
  - "hash drift"
  - "webpack-subresource-integrity"
  - "CDN script audit"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
tags: "[subresource-integrity, sri, cdn-security, magecart, integrity-hash, crossorigin, supply-chain, third-party-scripts]"
date_added: "2026-10-23"
---

# Subresource Integrity (SRI) & CDN Asset Security Audit

> Modern web applications heavily rely on Content Delivery Networks (CDNs) to deliver
> third-party libraries (jQuery, Bootstrap, React, Lodash, FontAwesome, analytics, and polyfills).
> However, loading executable JavaScript or stylesheets from third-party domains introduces an
> enormous attack surface: if the CDN is breached, an attacker can modify the hosted files to
> inject credential stealers, formjackers (Magecart), cryptominers, or session hijacking scripts.
>
> **Subresource Integrity (SRI)** allows browsers to cryptographically verify that fetched assets
> match an exact, predetermined cryptographic hash before executing or parsing them.

---

## SRI Threat Model & Taxonomy

```
Subresource Integrity Attack Surface
  ├── 1. CDN & Network Compromise Scenarios
  │     ├── Third-party CDN provider account takeover or server compromise
  │     ├── BGP routing hijack / DNS cache poisoning redirecting CDN traffic
  │     ├── Malicious or rogue CDN updates pushing trojanized library versions
  │     └── Magecart formjacking attacks targeting payment pages
  ├── 2. Implementation Flaws
  │     ├── External script or stylesheet loaded without integrity attribute
  │     ├── Missing crossorigin="anonymous" (causing silent load failures or bypass)
  │     ├── Weak hash algorithm (sha1 or md5 instead of sha384/sha512)
  │     └── Multiple conflicting integrity hashes
  ├── 3. Dynamic Third-Party Scripts & Limitations
  │     ├── Unpinnable dynamic tags (Google Tag Manager, Hubspot, Intercom, Zendesk)
  │     ├── CDNs serving rolling versions (/latest/ or @latest)
  │     └── Polyfill services delivering user-agent tailored content (e.g. polyfill.io supply chain attack)
  └── 4. Modern Architecture & Pipeline Challenges
        ├── ES Modules and dynamic import() missing import map integrity
        ├── Missing fallback logic when CDN or integrity checks fail
        └── Lack of automated hash generation in CI/CD build pipelines
```

---

## The Polyfill.io Lesson: Why SRI Matters

In June 2024, the popular CDN domain `polyfill.io` was acquired by a rogue entity. Within months,
the CDN began dynamically injecting malicious redirection and banking malware into over 100,000
websites that embedded scripts like:

```html
<!-- ❌ DISASTROUS: Trusted CDN turned malicious; no SRI to verify file contents! -->
<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>
```

If these sites had enforced Subresource Integrity (`integrity="sha384-..."`), browsers would have
calculated the SHA-384 hash of the malicious payload, detected that it did not match the expected
clean hash, and **refused to execute it**, neutralizing the attack entirely.

---

## Phase 1: Identifying Unprotected External Subresources

Audit every `<script>` and `<link rel="stylesheet">` tag loading assets from cross-origin domains.

### 1. Insecure CDN Script Inclusion
```html
<!-- ❌ VULNERABLE: No integrity verification -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
```

### 2. Hardened SRI Inclusion
```html
<!-- ✅ SECURE: Cryptographically locked to exact byte sequence -->
<script 
  src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js"
  integrity="sha384-hG3f3QpQxYFsmJ15C5G4t4s5wQyGz4r3N0l0Wv+P5FwR7S+X9/K2s3u4T1n2E4w"
  crossorigin="anonymous">
</script>

<link 
  rel="stylesheet" 
  href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
  integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM"
  crossorigin="anonymous">
```

---

## Phase 2: Cryptographic Hash Selection & Verification

The `integrity` attribute consists of one or more base64-encoded digests prefixed by the hash
algorithm name (`sha256-`, `sha384-`, `sha512-`).

### Hash Generation
To generate the SRI hash for any local or remote file, use OpenSSL or standard CLI utilities:

```bash
# Generate SHA-384 SRI hash for a remote asset:
curl -s https://code.jquery.com/jquery-3.7.1.min.js | \
  openssl dgst -sha384 -binary | \
  openssl base64 -A | \
  awk '{print "sha384-" $0}'
```

In PowerShell:
```powershell
# PowerShell SRI Hash Generator
$url = "https://code.jquery.com/jquery-3.7.1.min.js"
$bytes = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
$hasher = [System.Security.Cryptography.SHA384]::Create()
$hash = [Convert]::ToBase64String($hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($bytes)))
Write-Host "integrity=`"sha384-$hash`""
```

### Multiple Hashes & Algorithm Agility
Browsers select the **strongest supported algorithm** in the attribute:
```html
<!-- Browser prioritizes sha512 over sha384 -->
<script 
  src="https://example.cdn/lib.js" 
  integrity="sha384-dGVzdDE... sha512-dGVzdDI..."
  crossorigin="anonymous">
</script>
```
If multiple hashes are provided for the *same* algorithm, the browser accepts the resource if
it matches *any* one of those hashes (allowing graceful multi-CDN rollouts).

---

## Phase 3: The Mandatory `crossorigin="anonymous"` Pairing

**SRI requires CORS on the target server.**

When a browser encounters an `integrity` attribute on a cross-origin resource:
1. It requests the resource with CORS enabled (`Origin:` header sent).
2. The CDN server **must** respond with `Access-Control-Allow-Origin: *` (or matching origin).
3. If `crossorigin="anonymous"` is missing on the HTML tag, the browser blocks the resource
   execution and logs an error in DevTools:
   `Subresource Integrity: The resource '...' has an integrity attribute, but the resource requires the 'crossorigin' attribute to be set to 'anonymous'.`

```html
<!-- ❌ INVALID: Missing crossorigin attribute will cause browser failure -->
<script 
  src="https://cdn.example.com/app.js" 
  integrity="sha384-...">
</script>

<!-- ✅ VALID: Explicit crossorigin policy -->
<script 
  src="https://cdn.example.com/app.js" 
  integrity="sha384-..."
  crossorigin="anonymous">
</script>
```

---

## Phase 4: Third-Party Script Risk Classification

Not all third-party scripts can utilize static SRI hashes. Categorize third-party scripts
into three distinct risk tiers:

```
Third-Party Script Tiering
  ├── Tier 1: Static Third-Party Libraries (High Compatibility with SRI)
  │     ├── jQuery, Bootstrap, React, Lodash, Axios, Chart.js
  │     └── Action: MUST enforce SRI (sha384/sha512) + crossorigin="anonymous"
  │
  ├── Tier 2: Dynamic / Vendor-Managed Scripts (SRI Incompatible)
  │     ├── Google Analytics (gtag.js), Google Tag Manager, Intercom, Hotjar, Segment
  │     ├── Challenge: File contents change continuously without warning; static SRI breaks daily
  │     └── Mitigation: Strict CSP, sandbox iframes, self-hosting proxies, or Server-Side Tagging
  │
  └── Tier 3: Critical Security / Payment Dependencies (Extreme Risk)
        ├── Stripe.js, PayPal SDK, Adyen, Braintree
        ├── Challenge: Payment providers prohibit SRI because they push hotfixes and fraud heuristics
        └── Mitigation: Isolate on dedicated payment checkout domains; load via official sandbox iframes
```

---

## Phase 5: Client-Side Fallback Mechanisms

If a CDN suffers an outage or an integrity check intentionally blocks a compromised asset,
the application should gracefully fall back to a self-hosted copy.

### Inline Fallback Pattern:
```html
<!-- Load from CDN with SRI -->
<script 
  src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js" 
  integrity="sha384-mD7B3eJ6G5C/..." 
  crossorigin="anonymous">
</script>

<!-- Fallback: Check if window._ was defined; if not, load local asset -->
<script>
  window._ || document.write('<script src="/static/vendor/lodash.min.js"><\/script>');
</script>
```

For CSS stylesheets:
```html
<link 
  rel="stylesheet" 
  href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
  integrity="sha384-..." 
  crossorigin="anonymous">

<script>
  // Detect if stylesheet failed to load
  function checkStyleFallback() {
    var testElem = document.createElement('div');
    testElem.className = 'container';
    document.body.appendChild(testElem);
    // If Bootstrap failed to apply width styling:
    if (window.getComputedStyle(testElem).getPropertyValue('position') === '') {
      var localLink = document.createElement('link');
      localLink.rel = 'stylesheet';
      localLink.href = '/static/vendor/bootstrap.min.css';
      document.head.appendChild(localLink);
    }
    document.body.removeChild(testElem);
  }
  window.addEventListener('DOMContentLoaded', checkStyleFallback);
</script>
```

---

## Phase 6: Modern ES Modules & Import Maps Integrity

As applications migrate from monolithic bundles to native ES module imports (`import { ... } from '...'`),
standard `<script>` SRI does not cascade to sub-modules fetched by `import`.

### The W3C Import Maps Integrity Specification
Modern browsers support integrity specifications within `<script type="importmap">`:

```html
<script type="importmap">
{
  "imports": {
    "lodash": "https://cdn.jsdelivr.net/npm/lodash-es@4.17.21/lodash.js"
  },
  "integrity": {
    "https://cdn.jsdelivr.net/npm/lodash-es@4.17.21/lodash.js": "sha384-Z5Wq7..."
  }
}
</script>
```

---

## Phase 7: Build Pipeline Automation

Manually calculating and updating SRI hashes is prone to human error and breaks CI/CD deployments.
Automate SRI generation in your bundler:

### 1. Webpack: `webpack-subresource-integrity`
```javascript
// webpack.config.js
const { SubresourceIntegrityPlugin } = require('webpack-subresource-integrity');

module.exports = {
  output: {
    crossOriginLoading: 'anonymous', // Required for SRI
  },
  plugins: [
    new SubresourceIntegrityPlugin({
      hashFuncNames: ['sha384', 'sha512'],
      enabled: process.env.NODE_ENV === 'production',
    }),
  ],
};
```

### 2. Vite: `vite-plugin-manifest-sri`
```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import sri from 'vite-plugin-manifest-sri';

export default defineConfig({
  plugins: [
    sri({
      algorithms: ['sha384']
    })
  ]
});
```

---

## Phase 8: Hash Drift & CDN Compromise Detection

In production environments, external CDN assets can change unexpectedly. Implement automated
hash drift monitoring in CI/CD or health-check jobs.

### Hash Drift Monitor Script (Node.js)
```javascript
// scripts/check-sri-drift.js
const https = require('https');
const crypto = require('crypto');

const ASSETS_TO_CHECK = [
  {
    url: 'https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js',
    expectedHash: 'sha384-hG3f3QpQxYFsmJ15C5G4t4s5wQyGz4r3N0l0Wv+P5FwR7S+X9/K2s3u4T1n2E4w'
  }
];

async function verifyAsset(asset) {
  return new Promise((resolve) => {
    https.get(asset.url, (res) => {
      const hash = crypto.createHash('sha384');
      res.on('data', chunk => hash.update(chunk));
      res.on('end', () => {
        const calculated = `sha384-${hash.digest('base64')}`;
        if (calculated === asset.expectedHash) {
          console.log(`[PASS] ${asset.url}`);
          resolve(true);
        } else {
          console.error(`[CRITICAL DRIFT] Hash mismatch on ${asset.url}!`);
          console.error(`  Expected:   ${asset.expectedHash}`);
          console.error(`  Calculated: ${calculated}`);
          resolve(false);
        }
      });
    }).on('error', (err) => {
      console.error(`[FAIL] Could not fetch ${asset.url}:`, err.message);
      resolve(false);
    });
  });
}

(async () => {
  const results = await Promise.all(ASSETS_TO_CHECK.map(verifyAsset));
  if (results.includes(false)) {
    console.error('SRI verification failed for one or more CDN assets!');
    process.exit(1);
  }
})();
```

---

## Phase 9: Automated Audit Script

Run this PowerShell command to discover all external scripts and stylesheets missing SRI:

```powershell
# PowerShell SRI Scanner
Write-Host "=== Scanning for External Scripts/Stylesheets Missing SRI ===" -ForegroundColor Cyan

$files = Get-ChildItem -Recurse -Include *.html,*.htm,*.php,*.jsp,*.erb,*.jsx,*.tsx,*.vue

foreach ($file in $files) {
    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $content) { continue }

    # Find external scripts
    $scriptMatches = [regex]::Matches($content, '<script[^>]+src=["''](https?://[^"'']+)["''][^>]*>')
    foreach ($m in $scriptMatches) {
        $tag = $m.Value
        $url = $m.Groups[1].Value
        
        $hasIntegrity = $tag -match 'integrity='
        $hasCrossorigin = $tag -match 'crossorigin='

        if (-not $hasIntegrity) {
            Write-Host "❌ MISSING SRI: $($file.Name) -> $url" -ForegroundColor Red
        } elseif (-not $hasCrossorigin) {
            Write-Host "⚠️ MISSING CROSSORIGIN: $($file.Name) -> $url" -ForegroundColor Yellow
        }
    }

    # Find external stylesheets
    $styleMatches = [regex]::Matches($content, '<link[^>]+href=["''](https?://[^"'']+)["''][^>]*>')
    foreach ($m in $styleMatches) {
        $tag = $m.Value
        if ($tag -match 'rel=["'']stylesheet["'']') {
            $url = $m.Groups[1].Value
            $hasIntegrity = $tag -match 'integrity='
            if (-not $hasIntegrity) {
                Write-Host "❌ MISSING SRI STYLESHEET: $($file.Name) -> $url" -ForegroundColor Red
            }
        }
    }
}
```

---

## Phase 10: Finding Template & Remediation Checklist

### Finding Template
```markdown
### [VULN-SRI-001] Third-Party CDN Script Loaded Without Subresource Integrity

- **Severity:** High
- **Asset URL:** `https://cdn.example.org/libraries/payment-utils.min.js`
- **Location:** `public/index.html:18`
- **Flaw Description:** The application loads an executable JavaScript library directly from a
  third-party CDN without specifying the `integrity` and `crossorigin` attributes. If the CDN
  is breached, suffers DNS cache poisoning, or experiences a malicious supply-chain update
  (similar to the Polyfill.io compromise), an attacker can alter the JavaScript file to execute
  arbitrary malicious payloads, steal cookies, and exfiltrate user data.
- **Evidence / Code:**
  ```html
  <script src="https://cdn.example.org/libraries/payment-utils.min.js"></script>
  ```
- **Remediation:**
  1. Generate a SHA-384 cryptographic digest of the target script.
  2. Add the `integrity="sha384-..."` attribute to the `<script>` tag.
  3. Add `crossorigin="anonymous"` to satisfy browser CORS requirements.
  4. Consider bundling the dependency locally using npm/Vite instead of loading from external CDNs.
- **Confidence:** High
```

### Remediation Checklist
- [ ] Add `integrity="sha384-..."` to all static external CDN `<script>` tags.
- [ ] Add `crossorigin="anonymous"` to all tags utilizing SRI.
- [ ] Add `integrity` attributes to all external CDN `<link rel="stylesheet">` tags.
- [ ] Audit all third-party scripts; isolate dynamic tracking tags with strict Content Security Policies.
- [ ] Automate SRI hash generation in webpack, Vite, or Rollup build pipelines.
- [ ] Implement CI/CD hash drift verification to detect upstream CDN file modifications.
- [ ] Evaluate self-hosting critical vendor libraries instead of relying on external CDN infrastructure.
