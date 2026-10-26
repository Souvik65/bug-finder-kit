# Shadow DOM and Web Component Risks

## What Shadow DOM is (and is not)
Shadow DOM encapsulates **styles and DOM structure** for components. It is **not** a security boundary against JavaScript running in the same document. Any script on the page shares the same JS realm and origin as the component.

## Key facts
- `attachShadow({ mode: 'open' })`: `element.shadowRoot` is accessible to any page script. Reading, modifying, and event-listening inside are all possible.
- `mode: 'closed'`: `element.shadowRoot` returns `null`, but this is **obfuscation, not protection**. A script that runs before the component (or patches `Element.prototype.attachShadow`) can capture the root; browser extensions and devtools also have access. Do not rely on it to hide secrets or to stop a hostile script.
- Events: `composed: true` events cross the shadow boundary and are **retargeted**, so listeners outside see the host element, but `event.composedPath()` can reveal internals for open roots.
- CSS isolation can hide content from your page's CSS-based checks and some scanners, and can hinder naive sanitizers and security tooling that do not traverse shadow roots.
- Form-associated custom elements, slots, and `<slot>` projection can move untrusted light-DOM content into trusted component layouts.

## Where the real risks are
1. **False sense of isolation for third-party widgets.** Embedding a vendor widget as a web component that attaches to your DOM gives it your origin's full privileges. For untrusted code use a **cross-origin sandboxed iframe**.
2. **Security tooling blind spots.** DOM scanners, DLP, sanitizers, XSS filters, accessibility/security extensions, and CSP-adjacent checks may not pierce shadow roots. Content inside can escape review. Example: a sanitizer run on `container.innerHTML` will not see inside open shadow roots of existing elements, and code that clones nodes may not clone shadow content as expected.
3. **Hidden form fields and clickjacking aids.** Third-party components can render invisible or overlaid inputs/buttons inside shadow trees that page-level audits do not enumerate. Replay and heatmap tools may or may not capture shadow content, leading to unexpected over- or under-collection.
4. **Skimmer concealment.** A malicious script can attach UI or listeners inside a shadow root to avoid page-level DOM inspection (`querySelectorAll` does not pierce roots). Detection tooling must traverse shadow roots.
5. **XSS via `innerHTML` inside components.** Components that assign `innerHTML`/`insertAdjacentHTML` from attributes, properties, or slots introduce standard injection issues inside the shadow tree; encapsulation does not neutralize them.
6. **Attribute/property to HTML sinks.** `attributeChangedCallback` pipelines that write into templates are common sinks.
7. **Declarative Shadow DOM** (`<template shadowrootmode="open">`) parsed from HTML: sanitizers must handle it; some older sanitizer versions or configs strip or mishandle it. Verify your sanitizer's current behavior and keep it updated.
8. **Autofill and password manager interactions** with fields inside shadow roots vary; do not assume protection.
9. **Trusted Types and CSP** still apply inside shadow roots (same document); they are your actual controls.

## What to look for in code
- `attachShadow(`, `shadowRoot`, `customElements.define`, `<template shadowrootmode`, `ShadowRoot`, `composedPath`, `composed: true`
- `this.shadowRoot.innerHTML =`, `insertAdjacentHTML`, `outerHTML` writes inside components
- Vendor SDKs that inject a custom element at runtime (chat, consent banners, payment helpers)
- Security checks written with `document.querySelector` that assume they see all inputs/links/scripts (consent enforcement, PII masking, link rewriting for `rel=noopener`)

## Mitigations
- Use **cross-origin iframes with `sandbox`** for untrusted widgets (see client-side-security `iframe-sandboxing`); communicate through a validated `postMessage` API.
- Enforce **Trusted Types** (`require-trusted-types-for 'script'`) so component `innerHTML` writes must pass through a policy.
- Make scanners and masking tools shadow-aware. Example traversal:
```js
function* deepQueryAll(root, selector) {
  yield* root.querySelectorAll(selector);
  for (const el of root.querySelectorAll('*')) {
    if (el.shadowRoot) yield* deepQueryAll(el.shadowRoot, selector);
  }
}
for (const input of deepQueryAll(document, 'input, textarea')) { /* audit or mask */ }
```
(This sees open roots only; closed roots need cooperation from the component author.)
- Configure replay/masking vendors for shadow DOM per their docs; test that password and payment fields inside components are actually masked.
- For your own components: avoid HTML-string sinks, use `textContent`/DOM APIs, validate attributes, and prefer `open` mode (security should not depend on closed).
- Keep sanitizer libraries current and test them with declarative shadow DOM payloads.
- Do not store secrets in component properties assuming `closed` hides them.

## Judgment calls
- Using Shadow DOM for style isolation of your own UI is fine; flag only when someone treats it as a defense.
- For third-party widgets already built as web components, the control is governance + CSP + least-data, or moving them into an iframe if the vendor supports it.
