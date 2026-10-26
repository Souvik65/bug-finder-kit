# Writing custom SAST rules

Write a custom rule when: the codebase has an internal wrapper (`run_cmd`, `db.raw`), a framework the stock rules don't model, or a bug class has recurred.

## Process
1. **Anchor on a real bug.** Copy the vulnerable snippet and the fixed snippet from the repo.
2. **Name the triple**: source, sink, sanitizer(s) - for your wrapper, not the stdlib.
3. **Pick the engine**: single-file pattern or one-function flow -> Semgrep; multi-file flow or library-heavy modeling -> CodeQL; simple syntax ban -> ESLint `no-restricted-syntax`.
4. **Write tests first**: at least 1 vulnerable, 1 sanitized, 1 look-alike safe case. Run the rule on the whole repo and read 20 hits.
5. **Measure noise**: if >30% of hits are false positives, tighten sources or add sanitizers before rolling out. Noisy rules train developers to ignore the tool.
6. **Ship with metadata**: CWE, severity, confidence, a message that says *how to fix*, and a link to the secure internal helper.
7. **Roll out gradually**: warn -> block on new code only (baseline) -> block everywhere.

## Good rule messages
Bad: "Possible injection."
Good: "`run_cmd` receives request data. Pass an argument list to `run_cmd_args()` instead, or validate against `ALLOWED_COMMANDS`."

## ESLint syntax ban example
```js
"no-restricted-syntax": ["error", {
  selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
  message: "Use <SafeHtml> (sanitizes with DOMPurify) instead."
}]
```
