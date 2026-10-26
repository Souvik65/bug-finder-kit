# cookie-security

> Deep-dive HTTP cookie security audit and session token hardening skill for the
> **bug-finder-kit**. Provides end-to-end evaluation of cookie attributes, scoping,
> browser prefixes, session lifecycle security, and cross-subdomain attack vectors.

---

## What This Skill Covers

| Attack Vector / Control | Audit Focus |
|---|---|
| **Core Directives** | Missing `HttpOnly` (XSS theft), missing `Secure` (MITM sniffing) |
| **SameSite Matrix** | `Strict` vs `Lax` vs `None`, CSRF risk on state-changing GETs |
| **Domain Scope Sprawl** | Explicit `Domain=` attribute leaking cookies to all subdomains |
| **Cookie Prefixes** | Modern RFC 6265bis `__Host-` and `__Secure-` browser hardening |
| **Session Fixation** | Reusing unauthenticated session IDs across login boundaries |
| **Cookie Tossing** | Rogue or compromised subdomains overwriting parent domain cookies |
| **Cookie Jar Overflow** | DoS eviction attacks via cookie flooding |
| **Supercookies & Privacy** | Public Suffix List boundaries, partitioned cookies (`CHIPS`) |
| **Framework Presets** | Production-ready configs for Express, Django, Spring Boot, PHP, Go |

---

## Scope Boundary

| Skill | What It Covers |
|---|---|
| `auth-security` | Broad authentication logic, password policies, MFA, JWT lifecycle |
| `cors-deep-dive` | Cross-Origin Resource Sharing headers, origin reflection, preflight bypass |
| **`cookie-security`** | Exhaustive audit of all cookie attributes, scoping, prefixes (`__Host-`), cookie tossing, session fixation, and cookie jar limits |

---

## Trigger Phrases

Activate this skill by asking:
- `"cookie security"`, `"cookie audit"`
- `"SameSite review"`, `"HttpOnly Secure flags check"`
- `"cookie prefixes"`, `"__Host- cookie audit"`
- `"cookie tossing vulnerability"`, `"session fixation check"`
- `"cookie domain scope"`, `"cookie jar overflow"`
- `"cookie hardening"`

---

## Directory Structure

```
skills/cookie-security/
├── SKILL.md              — Core audit guide (Phases 1–11, attack classes, code examples)
├── README.md             — Overview, scope boundary, and triggers
└── references/
    └── detailed-guide.md — Technical reference on RFC 6265bis prefix rules, browser storage limits,
                            CHIPS/Partitioned cookies, and advanced attack scenarios
```
