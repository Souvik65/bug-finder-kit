---
name: third-party-script-audit
description: Audit the risk that third-party JavaScript (analytics, ads, marketing pixels, chat widgets, A/B testing, session replay, CDN-hosted libraries) and tag managers (Google Tag Manager, Segment, Tealium, Adobe Launch) add to a website, including Shadow DOM and web component isolation limits. Use whenever the user asks to review or harden script tags, GTM/GA/Meta Pixel/Hotjar/Intercom/Clarity integrations, CSP script-src/connect-src, Subresource Integrity (SRI), tag manager permissions, tracker privacy leakage, magecart-style skimming exposure on checkout/login pages, attachShadow/custom elements security, PCI DSS 6.4.3/11.6.1 script inventory, or "what third-party scripts does my site load" and "is it safe to add this script". Complements client-side-security (DOM clobbering, postMessage, clickjacking); this skill covers supply-chain and vendor-script risk. Defensive use only.
---

# Third-Party Script Audit

Any `<script src>` you do not control runs with the full privileges of your page: it can read the DOM, keystrokes, cookies not marked HttpOnly, `localStorage`, and make network requests as your origin. A tag manager multiplies this, because whoever can publish a container can ship code to production without a deploy. This skill inventories that exposure, ranks it, and produces concrete mitigations.

The goal is a **prioritized inventory and fix list**, not a lecture. Most sites cannot remove all third parties; the useful output is "which ones, on which pages, with what blast radius, and what controls reduce it".

## Workflow

1. **Inventory (static).** Run `python scripts/audit_scripts.py <project-path>` (add `--json` for machine output, `--md` for a report skeleton). It finds script tags, dynamic loaders, known vendor snippets, tag manager containers, missing SRI, inline-script patterns, `document.write`, `attachShadow` usage, and CSP/header evidence. Treat output as leads.
2. **Inventory (runtime) if the site is live and user-owned.** Suggest the user capture it themselves, since you cannot browse their staging: DevTools Network tab filtered by third-party, `performance.getEntriesByType('resource')` grouped by hostname, Chrome "Issues"/CSP report-only logs, or a CSP `report-uri`/`report-to` collection in Report-Only mode for 1-2 weeks. Tag managers load further scripts dynamically, so static grep under-counts. Say so in the report.
3. **Classify each script** with the rubric below (where it loads, what it can see, who can change it).
4. **Check the controls**: CSP, SRI, consent gating, tag manager governance, page-level isolation of sensitive flows (see `references/`).
5. **Report** with the template at the bottom. Lead with sensitive pages (login, checkout, account, admin, health/finance forms).
6. **Offer fix diffs**: CSP header, SRI attributes, script removal on sensitive routes, Partytown/worker offload, sandboxed iframe wrappers, consent-gated loader.

## Risk rubric

Score each script on four axes, then give an overall High / Medium / Low.

| Axis | Questions |
|---|---|
| **Placement** | Which routes load it? Sensitive pages (auth, payment, PII forms) multiply risk. A pixel on a marketing page is not the same as on `/checkout`. |
| **Capability** | Can it read form fields or keystrokes (session replay, heatmaps, chat, A/B tools)? Can it inject DOM or load more scripts (tag managers, ad tech)? Can it modify requests (consent managers, personalization)? |
| **Control** | Self-hosted and pinned with SRI, or vendor-hosted mutable URL (`.../latest.js`, `gtm.js?id=`)? Does the vendor load sub-dependencies you cannot see? |
| **Data** | What leaves the site: URLs with tokens or IDs in query strings, emails/IDs, form contents, referrers, cookies? Which jurisdictions and consent rules apply (GDPR/ePrivacy, India DPDP, CCPA)? |

Rules of thumb:
- Mutable vendor URL **plus** sensitive page **plus** DOM-read capability = High.
- Tag manager container on sensitive pages without publish governance = High, regardless of which tags are currently in it.
- Session replay / heatmap without field masking on forms = High (privacy and credential exposure).
- Analytics with a pinned, first-party-proxied script and a tight `connect-src` = Low.
- Anything unmaintained, with an expired domain, or loaded from a URL shortener / personal GitHub Pages / unpinned CDN path = High (hijack risk).

## What to check, by theme (load the reference when a lead appears)

| Theme | Reference |
|---|---|
| Analytics, ads, marketing pixels, session replay, chat, A/B, CDN libraries; what each can see; masking and consent | `references/analytics-marketing-scripts.md` |
| Tag manager abuse: container takeover, custom HTML tags, data layer injection, publish governance, server-side GTM | `references/tag-manager-abuse.md` |
| Shadow DOM and web components: what isolation is and is not, `open` vs `closed`, widget embedding | `references/shadow-dom.md` |
| Controls: CSP design, SRI, Report-Only rollout, Trusted Types, header placement, PCI-style script inventory | `references/controls-csp-sri.md` |

## Quick triage heuristics

- `<script src="https://...">` with no `integrity` + `crossorigin` is expected for vendor-mutable URLs (SRI would break on update). The fix there is isolation and governance, not SRI. SRI **is** appropriate for pinned library versions on CDNs (`jquery@3.7.1`, `cdnjs` paths with a version).
- `googletagmanager.com/gtm.js` anywhere = treat the whole container as arbitrary code execution for whoever has publish rights. Check who they are.
- Inline snippets that build `createElement('script')` loaders (GA, Meta Pixel, Hotjar, Clarity style) are dynamic loaders: CSP needs a nonce or hash for the inline part, plus host allowlisting for the loaded part. `unsafe-inline` defeats the purpose.
- Wildcards in CSP (`*.googleapis.com`, `https:`, `*.cloudfront.net`) often allow attacker-controlled content on the same host (JSONP endpoints, user-uploaded buckets, Angular libs). Prefer nonce + `strict-dynamic` and narrow `connect-src`.
- `document.write`, `eval`, `new Function`, and `innerHTML` assigned from vendor callbacks are red flags in either your code or the vendor's.
- Shadow DOM is **encapsulation, not a security boundary**: scripts in the page can still reach into `open` roots, and `closed` is trivially bypassed by anything that runs before the component. Do not recommend it as isolation for untrusted code. Use cross-origin iframes (sandboxed) for that.
- Cookies: tag-managed scripts can read non-HttpOnly cookies. Session cookies must be `HttpOnly; Secure; SameSite`.

## Safe recommendations ladder (cheapest first)

1. Remove scripts that nobody owns or uses (stale pixels, old A/B tools). Most audits find 20-40%.
2. Remove third parties from sensitive routes (route-level script loading; Next.js `<Script>` only in layouts for marketing pages).
3. Self-host or proxy pinned copies where licensing allows; add SRI to pinned CDN libs.
4. Add CSP in Report-Only, then enforce: nonce + `strict-dynamic`, `object-src 'none'`, `base-uri 'none'`, narrow `connect-src`, `frame-ancestors`.
5. Lock down the tag manager: least-privilege roles, 2-step approval, block custom HTML/JS tags on sensitive pages, alerting on publish.
6. Isolate high-risk vendors: sandboxed cross-origin iframe, or offload to a worker (Partytown) with explicit forwarded APIs; payment fields in vendor-hosted iframes.
7. Consent-gate everything non-essential; mask form fields and block selectors in replay tools.
8. Ongoing: script inventory with owner and justification, monthly diff alerts, vendor security review.

## Report template

```
# Third-Party Script Audit: <project>

Scope: <routes, repo paths>; method: static scan + <runtime capture yes/no>
Note: tag-manager-loaded scripts are only visible at runtime.

## Inventory
| Script / host | Purpose | Loaded on | Mutable URL | SRI | Can read forms/DOM | Owner |
|---|---|---|---|---|---|---|

## Findings
### [High|Medium|Low] <title>
- Where: path:line or route
- Risk: <what an attacker or a vendor compromise could do, one or two sentences>
- Evidence: <snippet>
- Fix: <diff / config>

## Controls status
CSP: <enforced|report-only|absent>   SRI: <coverage>   Tag manager governance: <summary>   Consent gating: <yes/no/unknown>

## Removed/Reduced recommendations
<scripts to delete or move off sensitive routes>

## Unknowns to verify at runtime
<list>
```

Keep it short. Do not invent vendor incidents or CVEs; if citing a specific past incident or vendor behavior, say it should be verified against current vendor docs or advisories, since vendors change behavior frequently.
