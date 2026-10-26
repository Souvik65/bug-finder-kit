# Clickjacking (UI Redressing)

## Mechanism
An attacker page frames the target site in a transparent or disguised `<iframe>` and lures the victim into clicking what looks like harmless UI, actually triggering a sensitive action in the framed app (delete account, approve OAuth grant, transfer funds, change settings). Variants: drag-and-drop content theft, cursorjacking, and likejacking. Success requires the victim to be logged in (cookies sent with the framed request) and the target action to need only clicks/keystrokes (no re-auth, no unguessable input).

## Defenses (server-side headers are authoritative)
- `Content-Security-Policy: frame-ancestors 'none'` (or `'self'`, or explicit allowlist)
- `X-Frame-Options: DENY` or `SAMEORIGIN` as legacy fallback (`ALLOW-FROM` is obsolete, do not use)
- `SameSite=Lax|Strict` on session cookies: cross-site framed requests then send no session cookie (Lax still allows top-level navigations; Strict is stronger)
- Re-authentication / confirmation step (password, passkey, typed confirmation) for destructive or high-value actions
- JS frame-busting (`if (top !== self) top.location = self.location`) is bypassable (sandbox attribute, `onbeforeunload` tricks, double framing) and is **not** an acceptable sole defense. A CSS "hide until verified" snippet is a reasonable complement:
```html
<style id="antiClickjack">body { display: none !important; }</style>
<script>
  if (self === top) document.getElementById('antiClickjack').remove();
  else top.location = self.location;
</script>
```

## What to check
- Response headers on **all** HTML routes, especially authenticated ones, OAuth consent screens, payment/checkout, settings, admin panels. Check `next.config.js`, `middleware.ts`, `vercel.json`, nginx/Apache/Cloudflare rules, hosting platform defaults.
- Whether the header is applied to error pages, redirects, and static HTML (often missed).
- Conflicting headers: CSP `frame-ancestors` takes precedence over `X-Frame-Options` where supported; make them consistent.
- Intentional embeds: should use explicit origin allowlist, not `*`; consider a separate route/subdomain for embeddable views so the main app can stay `DENY`.
- One-click sensitive actions with no confirmation.
- `<meta http-equiv="X-Frame-Options">` / `<meta http-equiv="Content-Security-Policy" content="frame-ancestors ...">`: **ignored by browsers** for these directives; report as missing.

## Judging exploitability
High when: sensitive state-changing action + reachable by click only + cookies sent in cross-site frame + no framing protection. Medium when only low-impact actions are reachable or cookies are SameSite=Lax/Strict in practice. Informational for fully public static pages with no actions.

## Verify
```bash
curl -sI https://example.com/settings | grep -i -E 'x-frame-options|content-security-policy'
```
Test from a local HTML file containing `<iframe src="https://your-site/...">`; the frame should refuse to load. Only test against sites you own or are authorized to assess.

## Fix examples
```js
// Next.js middleware.ts
import { NextResponse } from 'next/server';
export function middleware() {
  const res = NextResponse.next();
  res.headers.set('Content-Security-Policy', "frame-ancestors 'none'");
  res.headers.set('X-Frame-Options', 'DENY');
  return res;
}
```
```nginx
add_header Content-Security-Policy "frame-ancestors 'none'" always;
add_header X-Frame-Options "DENY" always;
```

## Regression test idea
Integration test requesting key routes (including 404 and redirect targets) and asserting both headers are present with the expected values.
