---
name: sast-scanner
description: Static application security testing (SAST) guidance - reasoning about taint analysis and data flow (sources, sinks, sanitizers), choosing and configuring SAST tools (Semgrep, Bandit, ESLint security plugins, CodeQL), writing custom rules/queries, running scans in CI, normalizing SARIF output, and triaging findings into true vs false positives. Use this skill whenever the user mentions SAST, static analysis for security, taint tracking, Semgrep rules, Bandit, eslint-plugin-security, CodeQL queries, SARIF, "scan my code for vulnerabilities", security linting, or wants to review code for injection, XSS, SSRF, path traversal, deserialization, hardcoded secrets or insecure crypto - even if they never say "SAST".
---

# SAST Scanner

Help the user find security vulnerabilities in source code by combining (a) sound reasoning about how untrusted data flows through a program and (b) the right static analysis tooling. A SAST tool is only as good as the rule, the configuration, and the triage that follows, so this skill covers all three.

## Core mental model: taint analysis

Almost every injection-class vulnerability is the same shape: **untrusted data (source) reaches a dangerous operation (sink) without passing through a neutralizing step (sanitizer)**.

| Term | Meaning | Examples |
|---|---|---|
| Source | Where attacker-controlled data enters | HTTP params/headers/body, cookies, CLI args, env vars, file/DB contents, message queues |
| Sink | Operation that is dangerous with tainted input | SQL execution, shell exec, `eval`, template render, file open, HTTP client, deserializer, redirect |
| Sanitizer / validator | Step that makes the data safe *for that specific sink* | Parameterized queries, `shlex.quote`, allow-list check, `path.resolve` + prefix check, HTML encoding |
| Propagator | Operation that carries taint along | assignment, concatenation, f-strings, `.format`, container insert/read, function args/returns |

Key reasoning rules (apply these when reading code *and* when judging tool output):

1. **Sanitizers are sink-specific.** HTML-escaping does not stop SQL injection; `int()` stops most injection but not logic flaws. Always ask "safe for which sink?"
2. **Taint is transitive.** Follow it through helpers, class fields, and return values. Intra-procedural tools miss flows that cross function boundaries; inter-procedural tools (CodeQL, Semgrep Pro/taint mode) catch more.
3. **Second-order flows exist.** Data written to a DB/file in one request and used unsafely in another is invisible to most tools. Flag stored-data sinks manually.
4. **Framework magic hides sources and sinks.** Decorators, DI, ORM raw-query escape hatches, and template `|safe` filters are where tools most often go blind. Model them explicitly in custom rules.
5. **Absence of findings is not evidence of safety.** Report what was scanned, with which rules, and the known blind spots.

For the detailed catalogue of sources/sinks/sanitizers by language and vulnerability class, read `references/taint-analysis.md`.

## Workflow

Follow these steps in order. Skip a step only if the user's request clearly doesn't need it.

1. **Scope** - Identify languages, frameworks, repo layout, and the threat model (public web app? internal CLI? library?). A CLI run by its own user has very different sources than an internet-facing API. Ask one short question only if this is genuinely unclear.
2. **Pick tools** - Use the selection table below. Prefer running 2 complementary tools over 1 noisy one.
3. **Run** - Use the tool recipes in the reference files. Always emit **SARIF** (or JSON) so results can be merged and triaged programmatically.
4. **Normalize** - Run `scripts/sarif_summary.py` on the outputs to dedupe, rank, and group findings.
5. **Triage** - For each high/medium finding, trace source -> sink by hand using the checklist in `references/triage.md`. Classify as True Positive, False Positive, or Needs Context, with a one-line reason.
6. **Fix or suppress** - Propose the smallest fix that neutralizes the *sink* (not just the symptom). Suppress false positives with a scoped, justified inline comment, never a blanket disable.
7. **Prevent regression** - Offer a CI step and, for recurring bug patterns, a custom rule (see `references/custom-rules.md`).

## Tool selection

| Situation | Reach for | Why |
|---|---|---|
| Fast feedback in PRs, any language, custom team patterns | **Semgrep** | Pattern-based, readable rules, has taint mode, seconds to run |
| Python codebase, quick baseline | **Bandit** | Python-specific AST checks, zero setup, good for CI gates |
| JS/TS codebase, editor/lint integration | **ESLint + eslint-plugin-security / eslint-plugin-no-unsanitized** | Runs where devs already lint; cheap |
| Deep inter-procedural data flow, variant analysis, high-assurance | **CodeQL** | Real dataflow/taint library, queries as code, best for finding "all variants of this bug" |
| Secrets / dependency CVEs | Out of scope for SAST proper - recommend gitleaks/trufflehog and SCA tools | Different technique |

Per-tool details: `references/semgrep.md`, `references/bandit.md`, `references/eslint-security.md`, `references/codeql.md`.

## Output format

When reporting results, use this structure so the user can act immediately:

```
## Scan summary
Scope: <paths, languages>   Tools: <tool + version + ruleset>
Findings: <N total> -> <TP count> true positive, <FP count> false positive, <NC count> needs context

## Confirmed issues (highest severity first)
### <ID> <Title> - <CWE-ID> - <severity>
Location: path/file.py:LINE
Flow: <source> (file:line) -> <propagation> -> <sink> (file:line)
Why it's exploitable: <1-2 sentences>
Fix: <minimal code change>

## Dismissed (false positives)
<ID> - <reason in one line>

## Coverage gaps
<what these tools cannot see here: second-order flows, generated code, unscanned dirs, auth logic>
```

Always include the **Coverage gaps** section - it keeps the user from over-trusting a clean scan.

## Guardrails

- This skill is for **defensive** review of code the user owns or is authorized to assess. Write detection rules and fixes, not working exploits. Proof-of-concept payloads should be minimal, inert, and only included when needed to demonstrate a finding to the code owner.
- Never claim a codebase is "secure" from a scan. Say what was and wasn't checked.
- Don't paste secrets found during a scan into the report; show the file, line, and a redacted prefix.
- Pin tool versions in CI snippets; rule sets change behavior between releases.
