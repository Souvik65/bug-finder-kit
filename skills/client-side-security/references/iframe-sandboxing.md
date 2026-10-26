# Iframe Sandboxing and Embedding Third-Party Content

## Mechanism
`<iframe sandbox>` applies a deny-by-default policy: no scripts, no forms, no popups, no top navigation, and a unique opaque origin. Each token (`allow-scripts`, `allow-same-origin`, `allow-forms`, `allow-popups`, `allow-top-navigation`, ...) removes a restriction. Mistakes turn the sandbox into decoration.

## High-risk configurations
- `allow-scripts` **+** `allow-same-origin` on content served from the **same origin** as the parent: the framed page can remove its own `sandbox` attribute via `parent.document` or access parent storage/cookies. Sandbox is effectively off.
- `srcdoc` / `blob:` / `data:` URLs with `allow-same-origin`: inherits the creator's origin.
- `allow-top-navigation` (or `-by-user-activation` where unneeded): framed content can redirect the whole tab (phishing).
- `allow-popups` without `allow-popups-to-escape-sandbox` is safer; with escape the popup is unsandboxed, so only allow it for trusted content.
- `allow-modals`, `allow-forms`, `allow-downloads` granted by default "just in case".
- No `sandbox` at all on user-generated or third-party content (ads, widgets, previews, markdown HTML, email bodies).
- Overbroad `allow` (Permissions Policy) such as camera, microphone, geolocation, `payment`, `clipboard-write`, plus missing `referrerpolicy`.
- Parent receives `message` events from the iframe without origin checks (see postmessage.md).
- Untrusted HTML rendered in a same-origin iframe via `srcdoc` to "isolate" it, which provides almost no isolation.

## What to grep for
`<iframe`, `createElement('iframe')`, `iframe.src =`, `srcdoc`, `sandbox=`, `allow=`, `allowfullscreen`, `credentialless`, React components wrapping iframes (YouTube, Maps, Stripe, Calendly, Typeform, Notion, CodeSandbox embeds), `dangerouslySetInnerHTML` containing iframe markup.

## Judging exploitability
Classify the framed content: (a) first-party trusted, (b) third-party trusted vendor, (c) user-generated/untrusted. Strictness scales up for (c). For (a)/(b), the risk is mainly supply-chain: a compromised vendor script gets whatever you grant.

## Recommended baselines
```html
<!-- Untrusted/user content: maximum isolation, ideally from a separate sandbox origin -->
<iframe src="https://usercontent.example-sandbox.net/preview/123"
        sandbox="allow-scripts"
        referrerpolicy="no-referrer"
        loading="lazy"
        allow=""></iframe>

<!-- Third-party widget that needs scripts + its own storage (cross-origin only) -->
<iframe src="https://widget.vendor.com/embed"
        sandbox="allow-scripts allow-same-origin allow-forms"
        referrerpolicy="strict-origin"
        allow="clipboard-write"></iframe>
```
Principles:
- Start from `sandbox=""` and add only the tokens needed; document why each exists.
- Never combine `allow-scripts` and `allow-same-origin` for content on your own origin. Host untrusted content on a **separate registrable domain** (not just a subdomain) so cookies and storage cannot be shared.
- Add `referrerpolicy` and a minimal `allow` list (Permissions Policy). Deny everything by default.
- Pair with parent CSP `frame-src` allowlist so only expected origins can be embedded at all: `frame-src https://www.youtube-nocookie.com https://widget.vendor.com`.
- Consider `credentialless` iframes and COEP/COOP where cross-origin isolation is required.
- Prefer sanitizing untrusted HTML (DOMPurify) **and** sandboxing; neither alone is enough for rich user content.
- Use privacy-enhanced embed hosts (`youtube-nocookie.com`) where possible.
- Validate and allowlist iframe `src` when users can supply embed URLs (scheme `https:`, host allowlist); never allow `javascript:` or `data:`.

## False positives
Well-known vendor embeds (YouTube, Stripe Elements) usually require specific tokens; confirm against vendor docs before recommending removal.

## Regression test idea
Unit test the embed-URL validator with `javascript:`, `data:`, lookalike hosts (`youtube.com.evil.net`); lint/grep CI check that rejects `sandbox` values containing both `allow-scripts` and `allow-same-origin` for first-party URLs.
