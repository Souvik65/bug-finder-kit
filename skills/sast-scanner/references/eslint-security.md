# ESLint security plugins (JavaScript / TypeScript)

Best for: catching risky constructs while developers type, at near-zero cost. These are lint rules, mostly syntactic, so expect false positives and weak data-flow.

## Setup

```bash
npm i -D eslint eslint-plugin-security eslint-plugin-no-unsanitized @microsoft/eslint-formatter-sarif
```

`eslint.config.js` (flat config):
```js
import security from "eslint-plugin-security";
import noUnsanitized from "eslint-plugin-no-unsanitized";

export default [
  security.configs.recommended,
  {
    plugins: { "no-unsanitized": noUnsanitized },
    rules: {
      "no-unsanitized/method": "error",
      "no-unsanitized/property": "error",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
    },
  },
];
```

Run for SARIF:
```bash
npx eslint . -f @microsoft/eslint-formatter-sarif -o eslint.sarif
```

## Rules worth knowing

| Rule | Detects | Reliability |
|---|---|---|
| security/detect-eval-with-expression | `eval(variable)` | High |
| security/detect-child-process | `child_process` use | Medium - verify args are tainted |
| security/detect-non-literal-fs-filename | dynamic path to `fs` | Noisy; confirm user control |
| security/detect-non-literal-regexp | ReDoS risk | Noisy |
| security/detect-object-injection | `obj[var]` | Very noisy; consider disabling, rely on prototype-pollution checks |
| security/detect-unsafe-regex | catastrophic backtracking | Medium |
| security/detect-possible-timing-attacks | `==` on secrets | Medium |
| no-unsanitized/property, /method | `innerHTML`, `insertAdjacentHTML`, `document.write` with unsanitized value | High for DOM XSS |

For React/Vue also grep for `dangerouslySetInnerHTML` and `v-html` (add `no-restricted-syntax` selectors) since the above plugins do not cover framework-specific sinks.

## Triage tips
- `detect-object-injection` is the largest FP source; downgrade or turn off, then cover prototype pollution with a Semgrep/CodeQL rule.
- ESLint cannot see across files. Use it as the first, cheapest layer.
- For TypeScript, use `@typescript-eslint/parser` so rules run on `.ts/.tsx`.

## Suppress
`// eslint-disable-next-line security/detect-child-process -- args are literals` with a reason.
