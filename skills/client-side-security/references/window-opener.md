# window.opener and Reverse Tabnabbing

## Mechanism
A page opened via `window.open()` or a link with `target="_blank"` can, in some contexts, access `window.opener` and call `opener.location = 'https://phish.example'`, silently redirecting the original tab to a lookalike login page. The reverse also holds: a page that opens untrusted windows retains a handle (`const w = window.open(...)`) that can leak or be used for messaging.

Modern browsers (Chrome 88+, Firefox 79+, Safari 12.1+) treat `target="_blank"` as implicit `noopener`, so plain links are Low severity today. Still relevant: older embedded WebViews, `window.open` with named targets, programmatic opens, OAuth/payment popups that *need* the opener, and cross-origin same-site pivots.

## What to grep for
- `target="_blank"` / `target='_blank'` / `target: '_blank'` without `rel="noopener"` (ideally `noopener noreferrer`)
- `window.open(` calls with user-influenced URLs, or without `'noopener'` in the features string
- `window.opener` reads or writes anywhere (`opener.postMessage`, `opener.location`)
- Rendering of user-supplied links (markdown, comments, CMS content) without rewriting `rel`
- Popups used for OAuth: confirm `postMessage` origin checks (see postmessage.md) and that the popup is closed after use
- Missing `Cross-Origin-Opener-Policy` header on sensitive apps

## Judging exploitability
Needs: a link or `window.open` to an attacker-controlled or attacker-influenced URL, a browser/WebView where implicit noopener does not apply (or a `window.open` without the opener severed), and a victim who may not notice the original tab changed. Rate Low for static links to trusted domains; Medium for user-generated links on authenticated apps.

## Vulnerable vs fixed
```html
<!-- Vulnerable (older browsers/WebViews) -->
<a href="https://third-party.example" target="_blank">Docs</a>

<!-- Fixed -->
<a href="https://third-party.example" target="_blank" rel="noopener noreferrer">Docs</a>
```
```js
// Vulnerable
window.open(userUrl);

// Fixed: sever the opener and validate the URL scheme
const u = new URL(userUrl, location.href);
if (!['https:', 'http:'].includes(u.protocol)) throw new Error('bad scheme');
window.open(u.href, '_blank', 'noopener,noreferrer');
```
- React/Next.js: ESLint rule `react/jsx-no-target-blank`; Next `<Link>` to external sites needs `rel` set manually for older targets.
- Rewrite user-generated links server- or sanitizer-side (DOMPurify hook adding `rel="noopener noreferrer"` to every `<a target>`).
- Set `Cross-Origin-Opener-Policy: same-origin` for sensitive apps; use `same-origin-allow-popups` if your own OAuth popup flow must keep references. Test login flows after enabling.
- Block `javascript:` and `data:` schemes in any user-supplied `href`.

## False positives
`rel` set via a shared Link component the scanner cannot see; check the component definition before reporting.

## Regression test idea
Lint rule in CI (`react/jsx-no-target-blank`) plus a unit test for the link-sanitizer asserting every output `<a target="_blank">` includes `noopener`.
