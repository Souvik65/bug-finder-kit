# PR security checklist

Design principle: the checklist must be short enough to be read. Use a **three-question core** for everyone and conditional sections that appear only when relevant. Checklists that exceed ~10 visible items are ticked without reading.

## Core (every PR, T0 and up)
```
- [ ] Does this change touch authN/authZ, secrets, crypto, user input, or data storage? (If yes, fill the sections below.)
- [ ] Any new dependency, external call, or permission? (If yes, fill "Supply chain/Integrations".)
- [ ] Could this log, expose, or persist sensitive data in a new place?
```

## Conditional sections (author ticks; reviewer verifies)

**AuthN / AuthZ**
- [ ] Every new endpoint/handler enforces authentication and object-level authorization server-side
- [ ] Negative test exists (wrong user/tenant/role denied)
- [ ] No trust in client-supplied role, tenant, or user ID

**Input / output**
- [ ] Inputs validated by allow-list (type, length, format); queries parameterized
- [ ] Output encoded for context; no raw HTML/JS from user data
- [ ] File/URL handling guards against path traversal and SSRF

**Data & secrets**
- [ ] No secrets, tokens, or PII in code, logs, errors, URLs, or test fixtures
- [ ] Sensitive data encrypted and classified; retention considered

**Supply chain / integrations**
- [ ] New dependency reviewed (maintainer, license, vuln status), pinned
- [ ] Outbound calls have timeouts; credentials scoped to least privilege
- [ ] Webhook/inbound events verified (signature, replay window)

**Observability**
- [ ] Security-relevant events logged with actor/target; no sensitive payloads

**Tier extras (T2/T3)**
- [ ] Threat model / security stories linked: <link>
- [ ] Security champion/AppSec reviewer assigned and approved
- [ ] Pre-release verification complete (T3): <link to test/pen-test result>

## Reviewer guidance (put in the PR template footer)
1. Read the diff *adversarially*: for each new input, ask "what if this is hostile?"; for each new output, "who else could see this?"
2. Look at what is **missing** (no auth check, no test, no log) as much as what is present.
3. Block on: missing authZ, secrets in code, unparameterized queries, disabled security controls, unreviewed new trust boundary.
4. Comment prefixes: `blocker:`, `fix:`, `nit:`, `question:`.
5. Automated tools (SAST, SCA, secrets) are evidence, not the review; a green scan does not satisfy the checklist.

## Routing with CODEOWNERS
Use ownership rules so risky paths auto-request a security reviewer without relying on author judgment:
```
# .github/CODEOWNERS
/src/auth/**          @org/security-champions
/src/payments/**      @org/security-champions @org/payments
/infra/iam/**         @org/appsec
**/crypto/**          @org/appsec
.github/workflows/**  @org/appsec
```
Pair with branch protection: require code-owner review for these paths.

## PR template (drop-in)
See `assets/pull_request_template.md`.
