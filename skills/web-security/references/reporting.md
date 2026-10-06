# Reporting

## Contents
1. Report structure
2. Writing a finding
3. Evidence handling
4. Prioritizing fixes

## 1. Report structure

1. **Executive summary**: scope, dates, overall risk in plain language, top three issues, what to fix first. One page, no jargon.
2. **Scope and method**: targets, what was and wasn't tested, accounts used, tools, limitations.
3. **Findings**: sorted by severity, each in the finding format from `SKILL.md`.
4. **Positive observations**: controls that worked (useful for the client and for credibility).
5. **Remediation roadmap**: grouped fixes with owners and effort.
6. **Appendix**: raw tool output, request/response samples (redacted), retest results.

## 2. Writing a finding

- Title names the flaw and the place ("SQL injection in /search `term` parameter").
- Describe **what an attacker could do**, not just what is wrong.
- Give reproduction steps that a developer can follow in minutes: request, parameter, expected vs actual behavior.
- Give a specific fix (code or config), then a retest condition ("`term` is passed as a bound parameter; the quote test no longer changes behavior").
- State confidence honestly: Confirmed, Likely, or Needs verification.

## 3. Evidence handling

- Redact passwords, tokens, session IDs, personal data, and cookies in screenshots and logs.
- Keep only the minimum data needed to demonstrate the issue; delete the rest per the engagement's data-handling terms.
- Don't include working attack payloads beyond what is needed to reproduce a harmless proof.

## 4. Prioritizing fixes

Rank by likelihood × impact, then by effort. Typical order: injection and authentication bypass; broken access control; stored XSS and CSRF on sensitive actions; session weaknesses; missing hardening and headers; informational items. Group fixes with a shared root cause (one encoding helper, one authorization middleware) so a single change closes many findings.
