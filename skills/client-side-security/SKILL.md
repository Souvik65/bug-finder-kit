---
name: client-side-security
description: Audit and harden front-end code against browser-side attack classes that go beyond XSS - DOM clobbering, prototype pollution, postMessage abuse, window.opener / reverse tabnabbing, clickjacking and UI redressing, and iframe sandboxing mistakes. Use whenever the user asks to review, audit, or secure JavaScript/TypeScript/React/Next.js/Vue/HTML code, mentions postMessage, window.open, target=_blank, iframes, embedding, CSP frame-ancestors, X-Frame-Options, Object.assign / deep merge / lodash merge, "__proto__", id/name attribute collisions, or sanitizer config, or is preparing a pre-launch security check of a web app, widget, or browser extension page. Trigger even if the user only says "is my frontend secure", "review my embed/iframe", or "security check my Next.js app". Complements an XSS detector; this skill covers what XSS tooling misses. Defensive use only - finds and fixes weaknesses in code the user owns or is authorized to test.
---

# Client-Side Security

Review front-end code for six attack classes that XSS scanners usually miss. The goal is to find real, reachable weaknesses, explain the exploit path in one or two sentences, and give a concrete fix. This skill is defensive: it helps the user secure code they own or are authorized to assess. Do not produce weaponized exploit pages; minimal proof-of-concept snippets that demonstrate the flaw to the code owner are fine.

## Why these classes get missed

XSS tooling looks for "untrusted data reaches an HTML/JS sink". These classes are different: the attacker abuses browser *semantics* (named element access, object prototypes, cross-window messaging, framing, window references) and often needs no injected script at all. Findings are about **missing checks and missing headers**, not tainted strings, so they need a different review lens.

## Workflow

1. **Scope.** Identify the stack (plain HTML, React/Next.js, Vue, extension, embeddable widget) and entry points: pages, `<iframe>` usage, `window.open`, `message` listeners, merge/clone utilities, HTML sanitization, response headers (middleware, `next.config.js`, nginx, Vercel config).
2. **Run the scanner** for a fast first pass (heuristic, expect false positives):
   `python scripts/scan.py <path-to-project> [--json]`
   It flags candidate lines per class. Treat hits as leads, not findings.
3. **Triage each lead** by reading the surrounding code and the matching reference file. Decide: exploitable, conditionally exploitable, or safe. Confirm reachability (who controls the input, who can embed or message the page).
4. **Check headers/config** that cannot be seen in component code (see "Config checks" below).
5. **Report** using the template at the bottom. Lead with the highest-impact items. Skip classes with no findings but say they were checked.
6. **Offer fixes as diffs**, framework-appropriate. Iterate if the user wants deeper coverage of one class.

## The six classes (read the reference when a lead appears)

| Class | One-line risk | Reference |
|---|---|---|
| DOM clobbering | Attacker-controlled `id`/`name` attributes shadow globals or `document.*` properties, hijacking config or script URLs | `references/dom-clobbering.md` |
| Prototype pollution | Writes to `__proto__`/`constructor.prototype` via merge/parse/set poison every object, enabling gadget chains | `references/prototype-pollution.md` |
| postMessage abuse | `message` handlers that skip origin checks, or send to `"*"`, leak data or accept forged commands | `references/postmessage.md` |
| window.opener / tabnabbing | Opened pages can navigate the opener; popups/OAuth flows leak references | `references/window-opener.md` |
| Clickjacking | Page can be framed and the user tricked into clicking hidden UI | `references/clickjacking.md` |
| Iframe sandboxing | Embedded third-party or user content runs with too many privileges | `references/iframe-sandboxing.md` |

Load only the reference files relevant to the leads found. Each contains: what to grep for, how to judge exploitability, vulnerable vs fixed code, and false-positive notes.

## Severity guidance

- **High**: exploitable by an unauthenticated attacker with realistic victim interaction and sensitive impact (account action, token/data exfiltration, auth bypass). Examples: `message` handler that executes commands without origin check; missing framing protection on a page with one-click state-changing actions; pollution reachable from URL/JSON input with a known gadget.
- **Medium**: requires a precondition (attacker can inject limited HTML, or a gadget must exist) or impact is limited.
- **Low / hardening**: defense-in-depth gaps (missing `rel="noopener"` on modern browsers, no `Object.create(null)` for dictionaries, overly broad but unexploited `sandbox`).

State the precondition explicitly. A finding without a stated attacker capability is not a finding.

## Config checks (do these even when code looks clean)

- **Framing**: response header `Content-Security-Policy: frame-ancestors 'none'` (or an explicit allowlist) on all authenticated/sensitive routes. `X-Frame-Options: DENY|SAMEORIGIN` as legacy fallback. JavaScript frame-busting alone is not a defense.
- **Opener isolation**: `Cross-Origin-Opener-Policy: same-origin` for sensitive apps (breaks some popup/OAuth flows; call that out and suggest `same-origin-allow-popups` where needed).
- **CSP baseline**: `object-src 'none'`, `base-uri 'none'` or `'self'` (limits base-tag and clobbering-assisted URL hijacks), no `unsafe-inline` where avoidable.
- **Cookies**: `SameSite=Lax|Strict` reduces the impact of framed and cross-site interactions.
- **Embedded third parties**: every `<iframe>` should have `sandbox`, `referrerpolicy`, and a minimal `allow` list.

Where headers are set depends on the stack. Examples:

```js
// next.config.js
module.exports = {
  async headers() {
    return [{
      source: '/:path*',
      headers: [
        { key: 'Content-Security-Policy', value: "frame-ancestors 'none'; object-src 'none'; base-uri 'self'" },
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
      ],
    }];
  },
};
```

```json
// vercel.json
{ "headers": [{ "source": "/(.*)", "headers": [
  { "key": "Content-Security-Policy", "value": "frame-ancestors 'none'" },
  { "key": "X-Frame-Options", "value": "DENY" }
]}]}
```

If the product is *meant* to be embedded (widget, payment form), use an explicit `frame-ancestors https://partner.example` allowlist, never `*`.

## Quick triage heuristics

- A `message` listener whose body never mentions `event.origin` (or `event.source`) is a lead until proven otherwise.
- Any `merge`, `extend`, `assign`, `set(path, value)`, query-string or JSON-path parser handling untrusted keys is a pollution lead. Check the library version against known advisories (`npm audit`, lodash < 4.17.21 for `merge`/`set`/`defaultsDeep`).
- Code that reads `window.someName`, `document.someName`, or `if (!window.config)` fallbacks, **and** the app renders user HTML (even sanitized) is a clobbering lead. Sanitizers often allow `id` and `name`.
- `target="_blank"` without `rel` is low on modern browsers (implicit noopener) but still matters for older WebViews and for `window.open` return-value handling.
- `sandbox="allow-scripts allow-same-origin"` on same-origin content defeats the sandbox entirely; on cross-origin content it is acceptable but should be justified.

## Report template

```
# Client-Side Security Review: <project>

Scope: <files/routes reviewed>, stack: <stack>
Classes checked: DOM clobbering, prototype pollution, postMessage, opener, clickjacking, iframe sandbox

## Findings
### [High|Medium|Low] <title>  (<class>)
- Location: path:line
- Attacker capability required: <what the attacker controls / how victim is lured>
- Impact: <one or two sentences>
- Evidence: <short code excerpt>
- Fix: <diff or exact change>

## Config gaps
<headers missing, where to add them>

## Checked, no issues
<classes/areas with nothing found>
```

Keep the report tight. Prefer fewer, well-evidenced findings over a long list of scanner noise. If something could not be verified (headers set at a CDN not visible in the repo), say so rather than guessing.

## Writing safe regression tests

When fixing, offer a small test so the fix stays fixed: a unit test feeding `{"__proto__":{"polluted":true}}` to the merge path and asserting `({}).polluted === undefined`; a test dispatching a `MessageEvent` with a foreign origin and asserting the handler ignores it; a header assertion in an integration test for `frame-ancestors`. See each reference file for class-specific test ideas.
