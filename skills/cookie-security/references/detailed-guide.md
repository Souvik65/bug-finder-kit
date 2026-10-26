# Cookie Security & Hardening — Technical Reference

## 1. RFC 6265bis Cookie Prefix Enforcement Algorithm

Modern user agents enforce strict validation rules when a cookie name starts with `__Host-` or `__Secure-`.
If any rule is violated, the browser discards the `Set-Cookie` header completely.

### The `__Host-` Cookie Validation Rules:
1. **Secure Origin:** The cookie must be set from a URI with the `https://` scheme.
2. **Secure Flag:** The header must contain the `Secure` attribute.
3. **Host-Only Scoping:** The header **must not** contain a `Domain` attribute. Any cookie with `__Host-` and `Domain=...` is rejected.
4. **Root Path:** The header **must** contain `Path=/`. Any other path is rejected.

### The `__Secure-` Cookie Validation Rules:
1. **Secure Origin:** The cookie must be set from a URI with the `https://` scheme.
2. **Secure Flag:** The header must contain the `Secure` attribute.
3. (Allows `Domain` and custom `Path` attributes).

---

## 2. Browser Cookie Jar Limits & Eviction Dynamics

Browsers maintain per-domain and global storage limits to prevent resource exhaustion:

| Browser Engine | Max Cookies per Domain | Max Size per Cookie | Max Cookies Total | Eviction Policy |
|---|---|---|---|---|
| **Chromium** (Chrome, Edge, Brave) | 180 | 4096 bytes | ~1000 | LRU (Least Recently Used) |
| **Gecko** (Firefox) | 150 | 4096 bytes | ~3000 | LRU |
| **WebKit** (Safari) | 200 | 4096 bytes | ~500 | FIFO / LRU |

### Denial of Service / Eviction Attacks
If an attacker can write cookies to a domain (via an XSS flaw, open redirect, or subdomain control),
they can execute a loop injecting 200 dummy cookies. The browser will automatically evict the
legitimate `session_id` cookie, causing an instant denial of service for the authenticated session.

---

## 3. Subdomain Cookie Tossing Deep-Dive

### Attack Setup
- Primary Application: `https://banking.example.com`
- User Content / Blog: `https://blogs.example.com`
- Attacker controls content on `blogs.example.com`

```
  Attacker on blogs.example.com
            │
            ▼ Sets cookie for parent domain
  Set-Cookie: session=ATTACKER_SESSION; Domain=example.com; Path=/
            │
            ▼ Victim visits banking.example.com
  Browser sends both cookies in non-deterministic order:
  Cookie: session=ATTACKER_SESSION; session=VICTIM_REAL_SESSION
            │
            ▼ Backend server parses headers
  Server reads first matching 'session' key:
  req.cookies.session -> ATTACKER_SESSION (Account Hijack / Login CSRF!)
```

### Why `__Host-` Defeats Cookie Tossing
Because `blogs.example.com` cannot set a cookie named `__Host-session` that affects `banking.example.com`.
The browser enforces that `__Host-` cookies can **only** be written by the exact origin (`banking.example.com`)
and never shared or shadowed across sibling subdomains or parent domains.

---

## 4. CHIPS (Cookies Having Independent Partitioned State)

As browsers phase out unpartitioned third-party cookies, legitimate cross-site embeds (e.g. chat widgets,
payment forms, embedded calendars) must use Partitioned cookies:

```http
Set-Cookie: chat_session=xyz987; Secure; SameSite=None; Partitioned; Path=/
```

### How Partitioning Works
A partitioned cookie has a **two-key storage model**:
- **Top-level site:** `https://parent-site.com`
- **Cookie partition key:** `https://chat-widget.com`

If the user visits another site (`https://another-site.com`), the chat widget running there
cannot see the cookie set under `https://parent-site.com`. This maintains functionality while
eliminating cross-site tracking.

---

## 5. Session Expiration vs Cookie Expiration

Always maintain two distinct expiration mechanisms:

1. **Client-Side Cookie Expiry:** Managed via `Max-Age` (in seconds) or `Expires`.
2. **Server-Side Session Expiry:** Managed in Redis, PostgreSQL, or backend session store.

> [!IMPORTANT]
> Never trust the client to expire its own session! If an attacker clones a cookie with a 10-year
> client `Max-Age`, the backend session store must reject the session if the server-side idle timeout
> or absolute timeout has lapsed.

```javascript
// Secure backend session validation pattern:
function isSessionValid(sessionRecord) {
  const now = Date.now();
  const IDLE_TIMEOUT_MS = 30 * 60 * 1000;       // 30 minutes
  const ABSOLUTE_TIMEOUT_MS = 12 * 60 * 60 * 1000; // 12 hours

  if (now - sessionRecord.lastActiveAt > IDLE_TIMEOUT_MS) {
    return false; // Invalidate due to inactivity
  }
  if (now - sessionRecord.createdAt > ABSOLUTE_TIMEOUT_MS) {
    return false; // Force re-authentication
  }
  return true;
}
```
