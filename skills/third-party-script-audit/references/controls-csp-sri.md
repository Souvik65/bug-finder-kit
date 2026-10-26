# Controls: CSP, SRI, Trusted Types, Inventory

## 1. Subresource Integrity (SRI)
Use for **pinned, immutable** resources.
```html
<script src="https://cdn.example.net/lib@3.7.1/lib.min.js"
        integrity="sha384-BASE64HASH" crossorigin="anonymous"></script>
```
Generate: `curl -s URL | openssl dgst -sha384 -binary | openssl base64 -A` then prefix `sha384-`.
Notes:
- Not suitable for vendor URLs that change content (GTM, pixels, chat loaders). A failed hash blocks the script, so those need isolation/governance instead.
- The CDN must send CORS headers (`Access-Control-Allow-Origin`) for `crossorigin="anonymous"`.
- SRI does not cover scripts those scripts load later.
- Prefer self-hosting critical libs; bundlers can emit integrity attributes (webpack `SubresourceIntegrityPlugin`).

## 2. Content Security Policy (CSP)
Goals: limit which scripts run, and where data can go.
Baseline (adapt per site):
```
Content-Security-Policy:
  default-src 'self';
  script-src 'nonce-{RANDOM}' 'strict-dynamic' https: 'unsafe-inline';
  object-src 'none';
  base-uri 'none';
  connect-src 'self' https://www.google-analytics.com https://analytics.google.com;
  img-src 'self' data: https://www.google-analytics.com;
  frame-src https://www.youtube-nocookie.com;
  frame-ancestors 'none';
  form-action 'self';
  upgrade-insecure-requests
```
Explanation of the `script-src` line: modern browsers honor the nonce and `strict-dynamic` and ignore `https:`/`'unsafe-inline'`; those are fallbacks for old browsers. The nonce must be **unique per response** and unguessable; static or reused nonces are no protection.
Key points:
- `connect-src` and `img-src` matter as much as `script-src`: they limit exfiltration by beacon/fetch/pixel.
- Avoid wildcards on shared hosts (`*.cloudfront.net`, `*.amazonaws.com`, `*.googleapis.com`) that serve attacker-controllable content.
- Roll out in **Report-Only** first, with a reporting endpoint, review violations (ignore extension noise), then enforce.
```
Content-Security-Policy-Report-Only: <policy>; report-to csp-endpoint
Reporting-Endpoints: csp-endpoint="https://example.com/csp-reports"
```
- Next.js: generate the nonce in middleware, pass it via a request header, and read it in the root layout for `<Script nonce>`; dynamic rendering is required for per-request nonces (verify current Next.js docs). Static pages can use hash-based CSP instead.
- Document every `unsafe-*` exception with a reason and owner.

## 3. Trusted Types
```
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types default dompurify
```
Forces dangerous sinks (`innerHTML`, `script.src`, `eval`) to accept only policy-produced values. Roll out in Report-Only; third-party code that violates it will surface. Browser support varies; treat as defense in depth.

## 4. Other headers/settings relevant to third-party risk
- `Permissions-Policy`: disable unneeded features (`camera=(), microphone=(), geolocation=(), payment=(self)`), and delegate narrowly to iframes via `allow`.
- `Referrer-Policy: strict-origin-when-cross-origin` (or stricter) to limit URL leakage to vendors.
- Cookies: `HttpOnly; Secure; SameSite=Lax|Strict` for session cookies so injected scripts cannot read them.
- `Cross-Origin-Resource-Policy` / COOP / COEP as appropriate for isolation goals.

## 5. Script inventory and change detection (PCI DSS v4 context)
PCI DSS v4.0 requirements 6.4.3 (authorize, justify, and maintain an inventory of scripts on payment pages, with integrity assurance) and 11.6.1 (detect unauthorized changes to payment page scripts and headers) apply to merchants handling card data in the browser. Verify the current requirement wording with your assessor or the PCI SSC documents. Practical implementation:
- Maintain a table: script URL, purpose, owner, justification, integrity method, review date.
- Use CSP + SRI + periodic hash comparison of fetched scripts, or a commercial page-protection tool.
- Prefer PSP-hosted fields/iframes so card data never touches your page DOM.
- Keep third-party scripts off the payment page unless essential.

## 6. Process controls
- Add a CI check that fails on new external `<script src>` hosts not in an allowlist file.
- Dependency review for any "add this snippet" request: owner, purpose, data sent, privacy review, removal date.
- Quarterly review: remove unused scripts, rotate access, re-verify vendor contracts and domains still resolve to the vendor.
