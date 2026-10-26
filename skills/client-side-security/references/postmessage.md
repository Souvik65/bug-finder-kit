# postMessage Abuse

## Mechanism
`window.postMessage` is cross-origin by design, so every `message` listener is a public input surface and every `postMessage(data, "*")` can leak data to whoever controls the receiving window.

Failure modes:
1. **Missing/weak origin validation** on the receiver: any page that can obtain a reference (framing, `window.open`, or being opened) can send commands or data.
2. **Weak checks**: `origin.includes('example.com')`, `endsWith('example.com')` (matches `evilexample.com`), `startsWith('https://example.com')` (matches `https://example.com.evil.net`), regex without anchors, trusting `event.source` only, checking `location` rather than `event.origin`.
3. **Wildcard target origin** when sending sensitive data (`targetWindow.postMessage(token, '*')`).
4. **Dangerous sinks** fed by message data: `innerHTML`, `eval`, `location = data.url`, `window.open(data.url)`, `fetch(data.url)`, merge into state (prototype pollution), `localStorage.setItem` for auth state.
5. **Missing schema validation**: trusting `data.type`/`data.action` shapes.
6. **Origin `"null"`** accepted (sandboxed iframes and `file:`/`data:` pages send `null`).

## What to grep for
- `addEventListener('message'`, `onmessage`, `window.onmessage`, `useEffect` registering message listeners, `$(window).on('message'`
- Inside handlers: absence of `event.origin` / `e.origin` / `evt.origin`
- `postMessage(` with `'*'` second arg, or missing second arg in legacy wrappers
- `event.data` flowing to sinks listed above
- OAuth/payment/SSO popups and embedded widgets (high-value targets), `MessageChannel` ports passed without checking origin first

## Judging exploitability
Ask: what can the handler *do* with a forged message (change state, navigate, read/return secrets, run code), and can an attacker page reach the window (is the page frameable, or does it `window.open` attacker-influenced URLs, or does an attacker-controlled page open it)? Sending with `'*'` is high when the payload includes tokens, PII, or auth codes and the receiving window could be navigated or replaced.

## Vulnerable vs fixed
```js
// Vulnerable
window.addEventListener('message', (e) => {
  if (e.data.type === 'setTheme') document.body.innerHTML = e.data.html;
});

// Fixed
const ALLOWED = new Set(['https://app.example.com', 'https://widget.example.com']);
window.addEventListener('message', (e) => {
  if (!ALLOWED.has(e.origin)) return;                 // exact match on a set
  if (e.source !== expectedWindow) return;            // optional: bind to a known window
  const msg = schema.safeParse(e.data);               // validate shape
  if (!msg.success) return;
  if (msg.data.type === 'setTheme') applyTheme(msg.data.theme); // data, never HTML
});

// Sending
frame.contentWindow.postMessage(payload, 'https://widget.example.com'); // never '*' for sensitive data
```
Additional guidance:
- Compare `e.origin` by exact string equality or parsed `new URL(e.origin).origin` against an allowlist; never substring or regex without anchors.
- Reject `e.origin === 'null'` unless an explicitly sandboxed integration requires it, and then rely on `e.source` + a handshake secret.
- Use `MessageChannel` after an origin-verified handshake for ongoing communication.
- Treat message data as untrusted input everywhere downstream.
- Remove listeners on unmount (React `useEffect` cleanup) to avoid duplicate and stale handlers.

## False positives
Handlers that only log, or listeners in extension content scripts responding to the same extension via `runtime.onMessage` (a different API). Same-origin-only apps with no iframes/popups have a smaller surface, but still validate origin.

## Regression test idea
Dispatch `new MessageEvent('message', { data: {...}, origin: 'https://evil.example' })` and assert no state change; repeat with `https://app.example.com.evil.net` and `null`.
