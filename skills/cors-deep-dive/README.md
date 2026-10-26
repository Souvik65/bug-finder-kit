# cors-deep-dive

> Deep-dive CORS misconfiguration detection, exploitation, and remediation skill for
> the **bug-finder-kit**. Goes far beyond basic header review to identify origin
> reflection, null origin exploitation, credential leakage, preflight bypass,
> validation logic flaws (prefix/suffix/regex), and postMessage origin abuse.

---

## What This Skill Covers

| Attack Class | Detection Focus |
|---|---|
| **Origin Reflection** | Server blindly echoes any `Origin:` header back as `ACAO:` |
| **Wildcard + Credentials** | Invalid `* + ACAC: true` combination or behavioural equivalents |
| **Prefix / Suffix Bypass** | `trusted.com.evil.com` and `attackertrusted.com` passing string checks |
| **Regex Without Anchors** | `/trusted\.com/` matching `attacker-trusted.com.evil.com` |
| **Null Origin** | Sandboxed iframe or `file://` origin exploitation |
| **HTTP Scheme Downgrade** | `http://trusted.com` accepted on HTTPS APIs |
| **Preflight Bypass** | Simple request types (form POST) skipping OPTIONS enforcement |
| **Cached Preflight Abuse** | Long `Access-Control-Max-Age` bypassing policy updates |
| **Subdomain Sprawl** | Wildcard subdomain allowlist + XSS on any subdomain |
| **postMessage Validation** | Missing or weak `event.origin` checks on message handlers |
| **Vary: Origin Missing** | CDN/proxy cache poisoning from absent Vary header |
| **CORS-as-CSRF vector** | Reading CSRF tokens cross-origin to forge protected requests |

---

## Scope Boundary

| Skill | What It Covers |
|---|---|
| `api-security-review` | CORS in the context of broader API security (shallow coverage) |
| **`cors-deep-dive`** | CORS attack classes, server logic flaws, exploitation PoC, framework remediations |

---

## Trigger Phrases

Activate this skill by asking:
- `"CORS audit"`, `"CORS misconfiguration"`
- `"Access-Control-Allow-Origin review"`, `"wildcard CORS"`
- `"null origin CORS"`, `"CORS credentials leak"`
- `"preflight bypass"`, `"origin reflection"`
- `"postMessage origin"`, `"CORS-based CSRF"`

---

## Directory Structure

```
skills/cors-deep-dive/
├── SKILL.md              — Core audit guide (Phases 1–10, all attack classes)
├── README.md             — Overview, scope boundary, and triggers
└── references/
    └── detailed-guide.md — Browser enforcement model, SameSite interaction,
                            framework configs (Express/Django/Spring), and automated scanners
```

---

## Author & Version
`bug-finder-kit` — v1.0.0 — 2026-10-22
