# Semgrep

Best for: multi-language scanning, fast PR checks, and encoding team-specific patterns as readable YAML.

## Run

```bash
pip install semgrep==<pinned>            # or: docker run semgrep/semgrep
semgrep scan --config p/default --config p/owasp-top-ten \
  --sarif --output semgrep.sarif .
# language packs: p/python p/javascript p/typescript p/java p/golang p/security-audit
# only fail CI on new findings in a PR:
semgrep ci --baseline-commit "$(git merge-base origin/main HEAD)"
```

Useful flags: `--severity ERROR`, `--exclude tests/ --exclude node_modules`, `--metrics off` (air-gapped / privacy), `--dataflow-traces` (show source->sink in output), `--max-target-bytes` for huge files.

## Taint mode rule (the unique value over plain patterns)

```yaml
rules:
  - id: flask-request-to-sql
    mode: taint
    languages: [python]
    severity: ERROR
    message: User input reaches a raw SQL query. Use bound parameters.
    metadata:
      cwe: ["CWE-89: SQL Injection"]
      owasp: ["A03:2021 - Injection"]
      confidence: HIGH
    pattern-sources:
      - pattern: flask.request.$ANY.get(...)
      - pattern: flask.request.$ANY[...]
    pattern-sanitizers:
      - pattern: int(...)
      - pattern: sqlalchemy.text(...).bindparams(...)
    pattern-propagators:            # optional: teach custom carriers
      - pattern: $LIST.append($X)
        from: $X
        to: $LIST
    pattern-sinks:
      - patterns:
          - pattern: $CUR.execute($Q, ...)
          - focus-metavariable: $Q
```

Notes:
- Use `focus-metavariable` on the sink so only the dangerous argument counts, not bound parameters.
- Put wrappers in `pattern-sanitizers` only after confirming they truly neutralize that sink.
- `metadata.cwe` / `confidence` populate SARIF and make triage and dashboards easier.

## Non-taint pattern examples

```yaml
  - id: yaml-unsafe-load
    languages: [python]
    severity: WARNING
    message: yaml.load without SafeLoader allows arbitrary object construction.
    patterns:
      - pattern: yaml.load(...)
      - pattern-not: yaml.load(..., Loader=yaml.SafeLoader)
      - pattern-not: yaml.load(..., Loader=yaml.CSafeLoader)
```

## Test rules before trusting them

Co-locate a test file; annotate expected hits:

```python
# ruleid: flask-request-to-sql
cur.execute("SELECT * FROM t WHERE id=" + request.args["id"])
# ok: flask-request-to-sql
cur.execute("SELECT * FROM t WHERE id=%s", (request.args["id"],))
```
Run `semgrep --test rules/`. Always include at least one `ok:` case per sanitizer.

## Suppress

`# nosemgrep: rule-id  -- reason, ticket` on the line. Never bare `# nosemgrep`.

## Known limits
Taint is strongest within a file/function in the OSS engine; cross-file inter-procedural flow generally needs Semgrep's paid engine. When flows cross modules, either supplement with CodeQL or add propagators/sources at the module boundary.
