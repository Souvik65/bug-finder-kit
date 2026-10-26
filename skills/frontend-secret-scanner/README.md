# frontend-secret-scanner

> Frontend-specific secret and sensitive data exposure detection skill for the
> **bug-finder-kit**. Audits the browser-deliverable attack surface: JavaScript
> bundles, source map files, build artifacts, client-side environment variables,
> SSR hydration payloads, and browser storage APIs.

---

## Scope Boundary

| Skill | Focus |
|---|---|
| `secrets-scanner` | Backend source code, server config files, repository history |
| **`frontend-secret-scanner`** | Browser-delivered JS bundles, source maps, env var prefixes, localStorage, HTML pages |

---

## What This Skill Covers

| Exposure Vector | Detection Targets |
|---|---|
| **JS Bundles** | Hardcoded API keys, tokens, passwords; internal endpoint URLs; private keys |
| **Source Maps** | `*.js.map` files exposing complete original source code and server-side logic |
| **Env Variable Prefixes** | Secrets assigned to `REACT_APP_`, `NEXT_PUBLIC_`, `VITE_`, `VUE_APP_` prefixes |
| **SSR Hydration Payloads** | `window.__NEXT_DATA__`, `__INITIAL_STATE__` over-sharing server-fetched credentials |
| **localStorage / sessionStorage** | Auth tokens, JWTs, API keys stored in XSS-readable browser storage |
| **HTML Pages** | Secrets in `<meta>` tags, inline `<script>` blocks, HTML comments |
| **Build Artifacts** | `.env` files deployed as static assets; compiled config files with embedded secrets |

---

## Trigger Phrases

Activate this skill by asking:
- `"frontend secret"`, `"scan JS bundle for API keys"`
- `"source map leak"`, `"exposed source map"`
- `"REACT_APP_ secret"`, `"NEXT_PUBLIC_ API key"`, `"VITE_ token"`
- `"localStorage token storage"`, `"client-side credential"`
- `"env variables in client bundle"`, `"__NEXT_DATA__ secret"`

---

## Quick-Reference: What MUST Stay Server-Side

```
❌ NEVER in REACT_APP_ / NEXT_PUBLIC_ / VITE_ prefixes:
   - Stripe secret key (sk_live_...)
   - Database connection strings
   - Server-to-server API keys (OpenAI, Twilio, SendGrid)
   - JWT signing secrets / private keys
   - OAuth client secrets
   - AWS secret access keys
   - Internal microservice credentials

✅ Safe for public prefixes:
   - Stripe publishable key (pk_live_...)
   - Public Google Analytics ID
   - Public feature flag values
   - CDN base URL
```

---

## Directory Structure

```
skills/frontend-secret-scanner/
├── SKILL.md              — Core audit guide (Phases 1–7, all exposure vectors)
├── README.md             — Scope boundary, coverage, and triggers
└── references/
    └── detailed-guide.md — Extended regex patterns (20+ services), CI/CD pipeline scan,
                            secure architecture patterns, localStorage vs cookie comparison
```

---

## Author & Version
`bug-finder-kit` — v1.0.0 — 2026-10-22
