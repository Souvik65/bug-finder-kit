# Prototype Pollution (client side)

## Mechanism
Assigning to `obj.__proto__.x`, `obj.constructor.prototype.x`, or merging attacker-controlled keys into objects adds properties to `Object.prototype`, which every plain object then inherits. Exploitation needs a **source** (attacker-controlled key path) and a **gadget** (code that later reads an unset property and uses it in a dangerous sink, such as `innerHTML`, script `src`, `fetch` options, template or sanitizer config).

Typical sources: deep merge/clone/extend helpers, `set(obj, path, value)`, URL/query parsers that support `a[b][c]=1` or `a.b.c=1`, `JSON.parse` output fed to a merge, hash-fragment config (`#__proto__[x]=y`), `postMessage` payloads merged into state.

## What to grep for
- `merge(`, `mergeWith(`, `defaultsDeep(`, `extend(true`, `$.extend(true`, `Object.assign` in loops over nested data, custom `deepMerge`/`deepClone`/`recursiveAssign`
- `_.set(`, `lodash.set`, `dot-prop`, `setValue`, `objectPath.set`, `qs.parse`, `query-string`, `deparam`, `node-querystring` with nesting enabled
- Manual loops: `for (k in src) target[k] = ...` without key filtering
- Keys from untrusted input used as property names: `obj[userKey][userKey2] = v`
- Dependency versions: run `npm audit`; known risky: lodash < 4.17.21 (`merge`, `mergeWith`, `defaultsDeep`, `set`, `zipObjectDeep`), jQuery < 3.4.0 `extend(true)`, old `minimist`, `hoek`, `qs` < 6.x settings
- Gadget candidates (for severity): code reading `options.something`, `config.html`, `props.dangerouslySetInnerHTML`, `transport_url`, `src`, `srcdoc`, `onload`-like defaults, sanitizer `ALLOWED_*` defaults

## Judging exploitability
1. Can an attacker choose a *key path* (not just values)? URL, JSON body echoed to client, postMessage, localStorage restored from shared state.
2. Does a merge/set/parse sink accept `__proto__` or `constructor.prototype`?
3. Is there any gadget? If none is known, rate Medium/Low but still fix: gadgets appear through dependency updates.

## Vulnerable vs fixed
```js
// Vulnerable
function merge(t, s) {
  for (const k in s) {
    if (typeof s[k] === 'object' && s[k] !== null) { t[k] = t[k] || {}; merge(t[k], s[k]); }
    else t[k] = s[k];
  }
  return t;
}
merge({}, JSON.parse('{"__proto__":{"polluted":true}}')); // ({}).polluted === true

// Fixed
const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);
function merge(t, s) {
  for (const k of Object.keys(s)) {
    if (BLOCKED.has(k)) continue;
    const v = s[k];
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      if (!Object.hasOwn(t, k) || typeof t[k] !== 'object') t[k] = {};
      merge(t[k], v);
    } else t[k] = v;
  }
  return t;
}
```
Defense in depth:
- Use `Object.create(null)` or `Map` for dictionaries keyed by user input.
- `Object.freeze(Object.prototype)` early in app startup (test for breakage from libraries that extend prototypes).
- Validate input with a schema (zod/ajv with `additionalProperties: false`) before merging.
- Read options with `Object.hasOwn(opts, 'x')` rather than `opts.x` in security-relevant code.
- Upgrade patched libraries; prefer `structuredClone` for cloning.
- Node-side flag: `node --disable-proto=delete` (server code, mention if relevant).

## False positives
Merging only developer-controlled constants is safe. `Object.assign({}, a, b)` is shallow and does not recurse into `__proto__` as a setter on the target in the dangerous way, but spreading attacker-controlled objects into config is still a logic risk.

## Regression test idea
```js
test('merge ignores __proto__', () => {
  merge({}, JSON.parse('{"__proto__":{"polluted":1}}'));
  expect(({}).polluted).toBeUndefined();
});
```
