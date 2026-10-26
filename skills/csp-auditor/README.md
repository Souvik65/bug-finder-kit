# csp-auditor

> Content Security Policy (CSP) analysis, bypass detection, and hardening skill for
> the **bug-finder-kit**. Evaluates CSP header completeness and strength, detects
> bypass vectors (JSONP, open redirectors, Angular CDN, subdomain wildcards), guides
> nonce-based and hash-based policy migration, and validates Trusted Types adoption for
> DOM XSS prevention.

---

## What This Skill Covers

| Audit Area | Detection & Guidance |
|---|---|
| **Directive Completeness** | Missing `object-src`, `base-uri`, `form-action`, `frame-ancestors`, `worker-src` |
| **Dangerous Source Expressions** | `'unsafe-inline'`, `'unsafe-eval'`, `*`, `https:`, `data:`, `blob:` in `script-src` |
| **Allowlist Bypass Vectors** | JSONP endpoints, open redirectors, Angular CDN bypass, user-uploadable CDN paths on allowlisted domains |
| **Subdomain Wildcard Risks** | `*.trusted.com` allowing attacker-controlled subdomains |
| **Nonce-Based CSP** | Per-request CSPRNG nonce generation, nonce reuse detection, `'strict-dynamic'` propagation |
| **Hash-Based CSP** | SHA-256 hash generation for static inline scripts |
| **Trusted Types (DOM XSS)** | `require-trusted-types-for 'script'`, policy implementation, DOMPurify integration |
| **Reporting & Monitoring** | `report-to` / `report-uri` endpoint configuration, Report-Only staging workflow |

---

## Trigger Phrases

Activate this skill by asking:
- `"audit CSP"`, `"review Content Security Policy"`
- `"check CSP bypass"`, `"unsafe-inline CSP"`
- `"nonce-based CSP"`, `"Trusted Types"`
- `"CSP report-uri"`, `"strengthen CSP headers"`
- `"JSONP CSP bypass"`, `"script-src policy"`

---

## Complementary Skills

| Skill | Relationship |
|---|---|
| `xss-detector` | Finds XSS sinks; CSP-auditor evaluates the policy layer protecting those sinks |
| `web-security` | General web security framework; CSP is the browser enforcement mechanism |

---

## Directory Structure

```
skills/csp-auditor/
├── SKILL.md              — Core audit guide (Phases 1–9, directives, bypasses, nonce, Trusted Types, reporting)
├── README.md             — Overview, coverage, and triggers
└── references/
    └── detailed-guide.md — Directive inheritance, CSP Evaluator API, bypass CDN list, framework nonce templates
```

---

## Author & Version
`bug-finder-kit` — v1.0.0 — 2026-10-22
