---
name: code-review-security
description: Structured, security-focused code review workflow - maps trust boundaries, traces untrusted input to dangerous sinks, then applies a checklist covering input validation, authn/authz, error handling, logging hygiene, secrets, and secure defaults, and delivers severity-ranked findings with concrete fixes. Use whenever the user asks for a security review, secure code review, "is this safe", PR/diff security check, hardening, pre-deploy or pre-launch audit, or pastes code (API routes, auth flows, DB queries, file uploads, Supabase policies, Django views, Next.js handlers) and wants vulnerabilities, risks, or best-practice gaps found. Use it even if the user only says "review this" for code that touches auth, user input, databases, files, payments, or secrets. Complements generic bug-finding - this skill hunts adversarial misuse, not just correctness bugs.
---

# Security Code Review

Bug-finding asks "does this break under normal use?" Security review asks "what can an attacker make this do?" Different question, different method. Work through the phases below in order; don't jump to the checklist, because most real vulnerabilities live in the *path* between an entry point and a sink, not in a single line.

## Phase 0 - Scope and depth

Pick a depth from what the user gave you. Say which one you chose in one line.

| Mode | When | Output |
|---|---|---|
| **Quick** | Diff, single file, or "sanity check this" | Top findings only, inline |
| **Standard** | A feature, module, or API surface | Full report (template below) |
| **Deep** | "Audit", pre-launch, or auth/payments code | Standard + threat model + missing-control analysis |

If the stack or deployment context is unknown and it changes the verdict (public internet vs internal, browser vs server, multi-tenant vs single), state your assumption and proceed. Ask only if a wrong assumption would flip severity.

## Phase 1 - Map trust boundaries

Before reading logic, list:
1. **Entry points** - HTTP routes, server actions, webhooks, queue consumers, CLI args, file uploads, env/config, third-party callbacks.
2. **Untrusted data** - anything from request body/query/headers/cookies, uploaded files, DB rows written by users, third-party API responses, LLM output.
3. **Sensitive assets** - credentials, tokens, PII, payment data, admin functions, other tenants' data.
4. **Sinks** - DB queries, shell/exec, file paths, HTML rendering, redirects, deserialization, outbound HTTP (SSRF), eval/templates, logs.

For repos, run the triage script to get a head start (it finds candidates, it does not give verdicts):

```bash
python scripts/scan_signals.py <path> [--format md|json]
```

Treat every hit as a lead to verify by reading the code, not as a finding.

## Phase 2 - Trace source to sink

For each entry point, follow untrusted data to every sink it reaches. At each hop ask: is it validated, encoded/parameterized for *this* sink, and authorized for *this* user? Validation at the edge does not excuse a missing control at the sink.

## Phase 3 - Apply the checklist

Read `references/checklist.md` and apply the sections relevant to the code. The four pillars the user cares most about:

- **Input validation** - allowlists over denylists; validate type, length, range, format server-side; canonicalize before checking; never trust client-side checks.
- **Error handling** - fail closed; no stack traces, SQL, or paths to clients; no empty `catch` that swallows auth failures; consistent error shape so responses don't leak whether a user exists.
- **Logging hygiene** - no secrets, tokens, passwords, full PII, or raw request bodies in logs; neutralize newlines in logged user input; log security events (auth failures, permission denials) with enough context to investigate.
- **Secure defaults** - deny by default, least privilege, safe cookie flags, strict CORS, short token lifetimes, TLS-only, debug off, new endpoints authenticated unless explicitly public.

Then read `references/stack-notes.md` for the stack in front of you (Next.js/React, Node/Express, Django/Python, Supabase/Postgres RLS, MongoDB/MySQL, n8n/webhooks, LLM-integrated code). Framework-specific footguns matter more than generic advice.

## Phase 4 - Look for what's missing

The most dangerous bugs are absent code. Explicitly check for missing: authentication on a route, object-level authorization (can user A fetch user B's record by changing an ID?), rate limiting on login/reset/OTP, CSRF protection on cookie-authed mutations, RLS policies on tables exposed to clients, ownership checks on file downloads, webhook signature verification, and server-side enforcement of anything the UI merely hides.

## Phase 5 - Rate and report

Rate each finding by **exploitability x impact**, not by how scary the bug class sounds.

- **Critical** - remotely exploitable without auth, or full data/account takeover (SQLi, auth bypass, RCE, exposed secrets in use).
- **High** - exploitable by any authenticated user to reach other users' data or privileged actions (IDOR, missing authz, stored XSS).
- **Medium** - needs unusual conditions or chaining (weak validation, verbose errors, missing rate limits, CSRF on low-impact actions).
- **Low / Hardening** - defense in depth (headers, log hygiene, dependency pinning).

Only report what you can point to in the code. If you suspect something but can't confirm from what you can see (e.g., middleware elsewhere may cover it), label it **Needs verification** and say exactly what to check. Don't pad with generic advice; a short list of real issues beats a long list of maybes.

### Report template (Standard / Deep)

```markdown
# Security Review: <scope>
**Mode:** <quick|standard|deep> | **Assumptions:** <1-2 lines>

## Summary
<2-3 sentences: overall posture, count by severity, the one thing to fix first>

## Findings
### [SEV] <short title> - `path/file.ext:line`
**Issue:** what is wrong and the attacker's path in one or two sentences.
**Impact:** what they gain.
**Fix:**
```<lang>
<minimal corrected code>
```
**Verify:** how to confirm the fix (test, request, or query).

## Needs verification
- <suspicion> - check <where>

## What's done well
- <controls that are correct; keeps the report credible and tells the author what to keep>
```

For Quick mode, use only the Findings entries, ordered by severity.

## Principles

- **Fixes, not just flags.** Every finding gets a minimal, copy-pasteable fix in the user's own stack and style.
- **Explain the attack in one sentence.** Developers fix what they understand; "possible injection" gets ignored, "`id` is concatenated into the query, so `1 OR 1=1` returns every row" gets fixed.
- **Don't write exploits.** Describe the attack path and give a harmless illustrative input where needed; do not build weaponized payloads or working attack tooling.
- **Respect the framework.** Many frameworks already protect by default (Django ORM, React text interpolation); flag where code *opts out* (`raw()`, `dangerouslySetInnerHTML`, `mark_safe`, service-role keys in the browser).
- **Secrets found in code are compromised.** Recommend rotation, not just removal from the file or git history.
