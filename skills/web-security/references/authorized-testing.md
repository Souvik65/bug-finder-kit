# Authorized Testing Workflow

## Contents
1. Before anything: scope and authorization
2. Test environment
3. Phase 1: Recon
4. Phase 2: Scanning
5. Phase 3: Validation
6. Phase 4: Fix and retest
7. Stop conditions

## 1. Scope and authorization

Do not proceed to active testing until these are written down:

- Who authorized the test, and that they have authority over the systems
- Exact targets: domains, IPs, environments (prefer staging over production)
- Allowed and forbidden techniques (for example: no denial of service, no social engineering, no testing of third-party services)
- Time window and a contact to call if something breaks
- Data handling: what happens to any sensitive data seen during testing
- Test accounts provided (at least two per role to check access control)

If the user cannot supply this, offer code review, a local lab, or a draft scope document instead.

## 2. Test environment

Practice and tool-learning belong in an isolated lab, not on real systems.

- Use virtual machines so the environment is isolated and can be reset to a clean snapshot after you break something.
- Keep the vulnerable target unreachable from outside your machine, and keep attack tools from reaching networks you don't own.
- Intentionally vulnerable practice apps: DVWA, OWASP Juice Shop, WebGoat. The source book used DVWA on a BackTrack VM; today Kali Linux or a container setup is the usual choice.

## 3. Phase 1: Recon (learn the target)

Goal: understand what exists before touching it.

- **Web server**: hostnames, IP ranges, technology stack, server and framework versions, exposed admin interfaces. Use public sources (DNS records, certificate transparency, search engines) first.
- **Web application**: map pages, forms, parameters, API endpoints, and authentication flows. An intercepting proxy (Burp Suite, OWASP ZAP) records every request while you browse; its spider/crawler fills in the rest. Look for content not linked from the UI (old files, backup files, admin paths, robots.txt entries).
- **Web user**: what do users see and trust (login pages, emails, third-party scripts)? What cookies and tokens does the app set?

Output of this phase: a sitemap, a list of inputs (every parameter and header the app reads), and technology notes.

## 4. Phase 2: Scanning (find leads)

- **Server level**: port and service scan (Nmap) to see what is listening; a vulnerability scanner (Nessus, OpenVAS, Nikto for web servers) to flag outdated or misconfigured services.
- **Application level**: an automated web scanner (ZAP, Burp Scanner) for common issues. Scanners are good at reflected injection and missing headers, and **poor at** access-control, business-logic, and multi-step flaws, so those need manual testing with two accounts.
- Throttle scans and agree on timing; scanners can trigger alerts, lock accounts, or load fragile systems.

Treat every scanner finding as a lead. Verify before reporting (see `server-config.md` for triage).

## 5. Phase 3: Validation (prove it, minimally)

Confirm each lead with the least invasive evidence:

| Class | Harmless validation |
|---|---|
| SQL/command injection | A single metacharacter causing an error or behavior change; a true/false condition pair giving different responses. Stop at "input controls the query." |
| XSS | A unique inert marker string shows up unencoded in a script/HTML context. A non-executing proof is usually enough. |
| CSRF | A state-changing request succeeds without any anti-forgery token or SameSite protection |
| Access control / IDOR | Account A requests Account B's object id and gets it |
| Path traversal | A request returns a harmless known file within agreed scope, or a canonicalization error proves the path is unchecked |
| Auth/session | Missing lockout shown with a handful of attempts on a test account; cookie flags and timeout inspected |

Rules for validation:
- Use test accounts and test data. Never use real users' credentials or sessions.
- Do not extract more data than needed to prove impact; redact anything sensitive in notes.
- Do not install persistence, create backdoor accounts, pivot to other systems, or run password-cracking against real user data. If your scope explicitly includes deeper post-exploitation, that is a separate, contractually defined activity beyond this skill.
- Automated exploitation tools (for example sqlmap) should only run with explicit permission, against the agreed scope, at a low rate, and with data-extraction options limited.

## 6. Phase 4: Fix and retest

Clients ask "how do we fix it?" as soon as you report. Attach remediation to every finding (use the topic references), then retest after fixes and record the result.

## 7. Stop conditions

Stop and contact the client contact if you: find real user data exposed, find evidence of a prior compromise, cause instability, or discover the target is out of scope.
