# Analytics, Marketing, and Vendor Script Risk

## Why they matter
These scripts run first-party with full DOM access. Risks come from (1) vendor compromise or domain takeover, (2) over-collection of data (privacy/regulatory), (3) capability creep via auto-updating mutable URLs, (4) the script loading *more* scripts you never reviewed, (5) performance and availability coupling.

## Categories and what each can typically do
Capabilities below describe how these product classes generally work; verify specifics in the vendor's current docs.

| Category | Examples (non-exhaustive) | Typical access | Main concerns |
|---|---|---|---|
| Pageview analytics | GA4, Plausible, Matomo, PostHog | URL, referrer, events, cookies/IDs | Tokens in URLs, user IDs sent as dimensions, consent |
| Ad/marketing pixels | Meta Pixel, TikTok, LinkedIn Insight, Google Ads | URL, events, hashed identifiers, DOM reads for "automatic events" | Auto-capture of form/button metadata, cross-site tracking, PII leakage in query strings |
| Session replay / heatmaps | Hotjar, Microsoft Clarity, FullStory, LogRocket | Serialises DOM, inputs, mouse/keys | Password/payment/PII capture unless masked; replay stored by vendor |
| Chat / support widgets | Intercom, Drift, Crisp, Zendesk | Injects UI, reads page context and often identity | XSS-like exposure through widget content, identity verification misuse |
| A/B testing & personalization | Optimizely, VWO, Google Optimize successors | Rewrites DOM, often synchronous and blocking | Arbitrary DOM modification by marketing users, flicker snippets that `eval` |
| Consent managers | OneTrust, Cookiebot, Usercentrics | Controls other scripts | Single point of control; compromise disables gating |
| Ad tech / affiliate | Many | Loads chains of third-party iframes/scripts | Malvertising, redirect abuse, unknown sub-vendors |
| CDN libraries | jQuery, Bootstrap, fonts, polyfill-style services | Executes as your code | Mutable paths, hijacked/sold domains |

Historical lesson (verify before citing): CDN/polyfill-service domain ownership changes and tag-manager-delivered skimmers have caused real incidents on checkout pages. Treat "who controls this hostname tomorrow" as part of the risk.

## What to look for in code
- Script tags and loaders: `<script src=`, `createElement('script')`, `import('https://...')`, `next/script` with `src`, `@next/third-parties`, `react-gtm-module`, `react-ga4`, `analytics.js`, `gtag(`, `fbq(`, `hj(`, `clarity(`, `Intercom(`, `Sentry`/RUM SDKs
- Mutable versions: `latest`, no version in path, `gtm.js?id=`, `/v1/` floating tags
- Missing `integrity`/`crossorigin` on pinned libs
- Same snippet loaded on every route via root layout (`_app`, `_document`, `layout.tsx`, `index.html`)
- PII in events: `email`, `phone`, `userId`, `name` passed to `gtag/fbq/identify/set_user`
- Sensitive data in URLs (reset tokens, order IDs, search queries) that analytics will capture as page URL/referrer
- Replay configuration: masking options absent; `data-*` mask attributes missing on sensitive inputs
- `window.dataLayer.push` with user-supplied values (see tag-manager-abuse.md)

## Mitigations
- **Route scoping**: load marketing/replay/chat tools only on non-sensitive routes. Block on `/login`, `/checkout`, `/account`, `/admin`, `/reset-password`.
- **Masking**: configure replay tools with default-mask-all inputs and explicit allow lists; add vendor mask attributes to payment/PII fields; disable keystroke capture on auth forms.
- **Consent gating**: do not load non-essential scripts until consent; implement a loader that injects scripts after consent and tears down on withdrawal.
- **PII hygiene**: scrub query strings before pageview (`history.replaceState` or analytics-side URL rules); use opaque IDs; hash only where the vendor requires it and document it.
- **Pin and verify**: pinned versions + SRI for CDN libs; self-host critical ones.
- **CSP `connect-src`/`img-src`/`frame-src`** limited to the exact vendor endpoints so exfiltration to other hosts is blocked (pixel beacons often use `img-src`).
- **Server-side options**: server-side tagging or first-party proxies reduce browser exposure but add backend responsibility; validate the data you forward.
- **Isolation**: heavy vendors in a worker (Partytown) or an iframe with a narrow postMessage API; payment inputs only in PSP-hosted iframes.
- **Vendor hygiene**: owner per script, review date, DPA/security questionnaire for those touching sensitive pages; remove on contract end.

## Fix example: Next.js, load marketing script only on non-sensitive routes
```tsx
// app/(marketing)/layout.tsx  (not the root layout)
import Script from 'next/script';
export default function MarketingLayout({ children }: { children: React.ReactNode }) {
  return (<>
    {children}
    <Script src="https://vendor.example/pixel.js" strategy="afterInteractive" nonce={/* from headers */ undefined} />
  </>);
}
```
Keep `(app)` / `(auth)` / `(checkout)` route groups free of third-party tags.

## Consent-gated loader sketch
```js
function loadAfterConsent(src, { integrity } = {}) {
  if (!window.__consent?.analytics) return;               // set by your CMP
  const s = document.createElement('script');
  s.src = src; s.async = true;
  if (integrity) { s.integrity = integrity; s.crossOrigin = 'anonymous'; }
  document.head.appendChild(s);
}
```

## False positives / judgment calls
- Self-hosted analytics (Plausible/Matomo/PostHog self-hosted) reduce third-party exposure but still run in-page.
- SRI on mutable vendor URLs breaks updates: don't recommend it there.
- First-party subdomain proxies may be "first party" in name only; check who operates them.
