# error-handling-audit

> Error handling, logging security, and exception flow review skill for the **bug-finder-kit**.
> Audits codebases for stack trace leaks, database schema disclosure, sensitive data
> logging (PII, credentials, bearer tokens), swallowed exceptions causing fail-open
> authorization bypasses, and CRLF log injection.

---

## What This Skill Covers

| Audit Area | Vulnerability Scenarios | Key Remediation |
|---|---|---|
| **Information Disclosure** | Stack traces in HTTP responses, framework debug pages (Django/Spring/Laravel), database schema leaks | Disable debug flags in production; return opaque correlation IDs (RFC 7807) |
| **Log Hygiene** | Plaintext credentials, tokens, session cookies, and PII written to logs/APM | Automated logging redaction filters (Pino/Structlog); mask sensitive fields |
| **Log Injection** | CRLF injection forging audit logs or spoofing admin logins | Enforce structured JSON logging; escape newline characters in input values |
| **Fail-Open Logic** | Swallowed errors in authentication/authorization checks defaulting to `true` | Enforce fail-closed defaults; explicit denial on exception |
| **Transaction Integrity** | Catch blocks failing to invoke `rollback()`, leaving partial commits | Enforce `tx.rollback()` inside error handling paths |
| **Availability (DoS)** | Unhandled promise rejections or panics crashing process instances | Global exception middleware; process-level unhandled rejection handlers |

---

## Trigger Phrases

Activate this skill by asking:
- `"error handling audit"`, `"check for stack trace leaks"`
- `"logging security"`, `"sensitive data in logs"`
- `"log injection"`, `"swallowed exception"`
- `"fail-open vulnerability"`, `"exception handling review"`
- `"log sanitization"`, `"unhandled rejection DoS"`

---

## Directory Structure

```
skills/error-handling-audit/
├── SKILL.md              — Core audit guide (Phases 1–6, information disclosure, log hygiene, fail-open)
├── README.md             — Overview, audit areas, and trigger keywords
└── references/
    └── detailed-guide.md — RFC 7807 problem details, language exception templates, and redaction filters
```

---

## Author & Version
`bug-finder-kit` — v1.0.0 — 2026-10-21
