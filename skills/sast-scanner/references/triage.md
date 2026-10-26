# Triage & CI integration

## Triage checklist (per finding)
1. **Reproduce the flow by reading code.** Open the sink line, walk backward to the source. Note file:line for each hop.
2. **Reachability**: is the function reachable from an entry point (route, handler, CLI, job)? Dead code and test-only paths are lower priority.
3. **Control**: can an attacker control the value, and how much of it (whole string, a fragment, just a number)?
4. **Mitigations upstream/downstream**: validation in middleware/schema, WAF (never count on this alone), type coercion, DB permissions.
5. **Impact**: what happens on success - data read, write, RCE, SSRF into cloud metadata? Rate with CVSS-like reasoning.
6. **Verdict**: TP / FP / Needs Context, plus one-line reason.

## Common false-positive patterns
- String building from constants or enums only
- Value validated by a framework schema (pydantic, zod, JSON Schema) before reaching the sink
- Test fixtures, scripts, and migrations not deployed
- Hash functions used for cache keys or ETags, not secrets
- Findings in vendored/third-party code (fix by upgrading the dependency instead)

## Common false negatives (tell the user)
- Second-order/stored flows; flows through message queues, caches, or DB round-trips
- Authorization and business-logic flaws (IDOR, missing auth checks) - SAST rarely finds these
- Runtime config, infra-as-code misconfigurations (use dedicated IaC scanners)
- Dynamic code generation, reflection, and unusual framework conventions

## Severity rubric (quick)
- Critical: unauthenticated RCE, SQLi on internet-facing path, auth bypass
- High: authenticated RCE/SQLi, SSRF to internal network, stored XSS on privileged views
- Medium: reflected XSS, path traversal limited to a directory, weak crypto on sensitive data
- Low: info leak of non-sensitive data, missing hardening flags

## CI integration (GitHub Actions example)
```yaml
name: sast
on: [pull_request]
permissions: { contents: read, security-events: write }
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<commit-sha>
        with: { fetch-depth: 0 }
      - run: pip install semgrep==<pinned>
      - run: semgrep scan --config p/default --sarif --output semgrep.sarif --error --severity ERROR
      - uses: github/codeql-action/upload-sarif@<commit-sha>
        if: always()
        with: { sarif_file: semgrep.sarif }
```
Principles: block on new HIGH+ findings only; keep a baseline file for legacy debt; run full scans nightly; make suppressions require a reason; track FP rate per rule and retire rules that stay noisy.

## Merging results
`python scripts/sarif_summary.py *.sarif --min-level warning --format markdown` dedupes across tools, groups by CWE/rule, and ranks by severity so triage starts with the highest-value items.
