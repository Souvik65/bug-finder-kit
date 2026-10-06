---
name: web-security
description: Defensive web application security review plus methodology support for AUTHORIZED penetration tests. Use whenever the user asks to review code, an endpoint, or a config for security problems; asks about SQL injection, command injection, XSS, CSRF, broken authentication, session handling, path traversal, access control or insecure server configuration; asks how to fix or prevent a web vulnerability; wants a pentest plan, scope checklist, test checklist or findings report; or mentions OWASP, hardening, DVWA, Burp Suite, ZAP, or "is this secure". Use it even if the user never says the word "security" but is clearly asking whether web code is safe.
---

# Web Security

Two jobs: (1) find and fix vulnerabilities in web code and configuration, and (2) help security professionals run **authorized** assessments with a clear method and good reports.

## Operating rules

1. **Authorization first.** Before helping plan or run any active test against a live system, confirm the user owns it or has written permission, and what is in scope. If they cannot confirm, stay with code review, local lab targets (DVWA, OWASP Juice Shop, their own dev environment), and general guidance.
2. **Prove, don't exploit.** Validate a finding with the smallest harmless evidence (an error difference, a reflected marker string, a response showing another user's record id). Do not provide web shells, persistence, privilege-escalation chains, data-dumping workflows, or phishing/social-engineering kits. Do not help test against systems the user doesn't control.
3. **Fix every finding.** Each issue ends with a concrete remediation, ideally with a before/after code snippet in the user's language.
4. **Say what you verified.** Separate confirmed findings from suspicions. Scanner output and version banners are leads, not proof.

## Pick the mode

| User wants | Do this |
|---|---|
| Review code / a PR / a config | **Code review mode**: read the code, map untrusted input to dangerous sinks, report findings in the format below |
| Plan or run an authorized test | **Authorized testing mode**: confirm scope, then follow `references/authorized-testing.md` |
| "How do I fix / prevent X" | **Fix mode**: go straight to the matching reference's Fixes section |
| Write up results | **Reporting mode**: `references/reporting.md` |

## Core method (applies to all modes)

Work through **recon → scanning → validation → fix**, against three targets:

- **Web server**: the OS and services hosting the app (patching, exposed services, error messages, default accounts)
- **Web application**: the code (injection, authentication and sessions, access control, file handling)
- **Web user**: attacks that run in or abuse the browser (XSS, CSRF); user awareness issues are reported but not "exploited"

For each target, ask: what can an attacker control, where does it go, and what stops it?

## Code review shortcut: source → sink

1. List untrusted inputs: query/body/header/cookie values, uploaded file names and contents, data from other users, third-party API responses.
2. Trace each to a dangerous sink: SQL/NoSQL query, shell or process call, file path, HTML/JS output, redirect URL, deserializer, template.
3. Check what sits between them: parameterization, allowlist validation, output encoding, authorization check.
4. Flag any path where input reaches a sink with none of those controls.

## Where to go next

| Topic | Read |
|---|---|
| Scope, phases, tools, safe validation, lab setup | `references/authorized-testing.md` |
| SQL, OS command, LDAP, XPath injection | `references/injection.md` |
| Login, passwords, sessions, cookies | `references/auth-session.md` |
| Missing authorization, IDOR, path traversal, uploads | `references/access-control-paths.md` |
| XSS, CSRF, user-targeted attacks | `references/xss-csrf.md` |
| Server hardening, error handling, scanner triage, modern extras | `references/server-config.md` |
| Finding format, severity, report structure | `references/reporting.md` |

Read only the files relevant to the request.

## Finding format

```
### [Severity] Title
- Location: file:line or URL + parameter
- What: one sentence describing the flaw
- Why it matters: attacker capability and impact
- Evidence: harmless proof or the exact code path
- Fix: concrete change, with before/after code
- Confidence: Confirmed | Likely | Needs verification
```

## Severity guide

- **Critical**: unauthenticated remote code execution, full database read/write, authentication bypass on admin functions
- **High**: injection or access-control flaws exposing other users' data, stored XSS on authenticated pages, session takeover
- **Medium**: reflected XSS, CSRF on sensitive actions, weak lockout or session timeout, missing hardening that enables other attacks
- **Low / Info**: verbose errors, missing headers, version disclosure

## Provenance

Method and structure are distilled and rewritten from Josh Pauli, *The Basics of Web Hacking* (Syngress, 2013), and updated with current practice (OWASP guidance, modern cookie and CSP controls). Where the book's advice is dated, the references say so.
