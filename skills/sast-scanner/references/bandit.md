# Bandit (Python)

Best for: a fast, zero-config baseline on Python code and an easy CI gate. It is AST-pattern based with limited data-flow, so treat it as a smell detector and confirm by tracing.

## Run

```bash
pip install bandit[sarif]==<pinned> bandit[toml]
bandit -r src/ -f sarif -o bandit.sarif
bandit -r src/ -ll -ii            # only MEDIUM+ severity AND MEDIUM+ confidence
bandit -r src/ -c pyproject.toml  # config-driven
```

`pyproject.toml`:
```toml
[tool.bandit]
exclude_dirs = ["tests", ".venv"]
skips = []            # prefer per-line suppression over global skips
```

## High-value test IDs

| ID | Finds | Notes |
|---|---|---|
| B102/B307 | `exec` / `eval` | Check whether argument is attacker-influenced |
| B301/B302 | `pickle`/`marshal` loads | Untrusted data => RCE |
| B506 | `yaml.load` unsafe | Use `yaml.safe_load` |
| B602/B605 | `subprocess` shell=True / `os.system` | Look for tainted string building |
| B608 | SQL string building | Frequent FP on constant strings; verify no user data |
| B324 | weak hash (md5/sha1) | FP if used for non-security checksums |
| B105/B106/B107 | hardcoded password strings | FP on placeholders; FN on non-obvious names |
| B113 | requests without timeout | Reliability/DoS, low severity |
| B501 | TLS verify disabled | Almost always a true positive in prod code |
| B701 | Jinja2 autoescape off | XSS enabler |

## Triage tips
- Severity x Confidence matrix: start with HIGH/HIGH, then HIGH severity with MEDIUM confidence.
- B608 and B105 produce the most false positives; require a manual flow check.
- Bandit does not follow values across functions. A clean run does not mean tainted data never reaches `execute`.

## Suppress
`# nosec B608 - parameters are constants, see ticket` on the specific line. Always name the test ID.

## Pair with
Semgrep taint rules for flows Bandit cannot see (request -> execute across helper functions).
