# XSS, CSRF, and Web-User Attacks

## Contents
1. Concepts
2. Code review red flags
3. Safe testing
4. XSS fixes
5. CSRF fixes
6. User-targeted social engineering
7. Dated advice in the source material

## 1. Concepts

**Cross-site scripting (XSS)**: the app puts untrusted input into a page without proper output encoding, so the victim's browser runs attacker-supplied script because it trusts the site. Types:
- *Reflected*: input in the request is echoed in that response; a victim must be lured to a crafted link (roughly one victim per link).
- *Stored*: input is saved (comments, profiles, forum posts) and served to every visitor; far more damaging because it persists and spreads.
- *DOM-based*: client-side script writes untrusted data into the page itself.
Impact: session theft, acting as the user, keylogging, redirects, content tampering.

**Cross-site request forgery (CSRF)**: a victim who is logged in is lured into sending a valid state-changing request (change email or password, create a user, post content) that the app accepts because the browser attaches the user's session automatically. Rule of thumb: XSS abuses the user's trust in the site; CSRF abuses the site's trust in the user's browser. They combine: stored XSS can perform CSRF-style actions that spread (the 2005 MySpace "Samy" worm).

## 2. Code review red flags

- Template output marked "safe"/unescaped (`|safe`, `{!! !!}`, `<%- %>`, `Html.Raw`)
- `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `dangerouslySetInnerHTML`, `v-html`, jQuery `.html()` with request- or user-derived data
- Untrusted data placed inside `<script>` blocks, event-handler attributes, inline styles, or `href`/`src` values (check `javascript:` URLs)
- User-supplied HTML accepted without an allowlist sanitizer
- State-changing endpoints using GET, or POST endpoints with no anti-forgery token and cookies lacking `SameSite`
- Session cookies without `HttpOnly`
- No Content-Security-Policy

## 3. Safe testing (authorized)

- Submit a unique, inert marker string and find where it lands in the response. Check the output context (HTML body, attribute, script, URL) and whether special characters are encoded there.
- If special characters are returned unencoded in a context where they matter, that is sufficient to report. Do not publish or leave live script payloads on shared stored-input pages; use a test account and remove test data afterward.
- For CSRF: take a state-changing request and check for an anti-forgery token, its validation, `SameSite` cookie attributes, and whether the action works from a different origin in a controlled test.

## 4. XSS fixes

Treat an HTML page as a template with a few safe "slots" for untrusted data, like a parameterized query.

1. Never place untrusted data outside allowed slots (not inside script blocks, comments, or tag names).
2. **Context-aware output encoding**: HTML-escape for element content, attribute-escape for attributes, JavaScript-escape for JS data values, URL-encode for URL parameters, and strictly validate for CSS values.
3. Use the framework's auto-escaping templating and avoid its raw/unsafe escape hatches.
4. Where users may submit HTML, sanitize with a maintained allowlist sanitizer (for example DOMPurify) on the server or at render time.
5. Avoid dangerous DOM sinks; use `textContent` rather than `innerHTML`.
6. Set `HttpOnly` on session cookies so script can't read them.
7. Add a **Content-Security-Policy** that restricts script sources as defense in depth.
8. Validate input with allowlists (and canonicalize first); this helps but does not replace output encoding.

## 5. CSRF fixes

1. **Anti-CSRF tokens** (synchronizer token pattern): a random, session-bound value included in every state-changing request and verified on the server.
2. **`SameSite` cookies** (Lax or Strict) as a baseline browser-side defense.
3. Use POST/PUT/DELETE for state changes, never GET; for APIs, require a custom header or token that a cross-site form can't set, and verify `Origin`/`Referer`.
4. Require re-authentication or confirmation for sensitive actions.
5. Reasonable session timeouts shrink the window.
6. Remember: an XSS bug defeats CSRF tokens, so fix XSS too.

## 6. User-targeted social engineering

Attacks that rely on tricking a user (clicking a link, opening a file, approving a prompt) need no application flaw, and servers, firewalls, and WAFs cannot stop them. For this skill:
- Report the exposure and recommend defenses: user awareness training, MFA that resists phishing, email filtering, least-privilege accounts, endpoint protection, and timely patching.
- Do **not** build phishing pages, malicious documents, or use social-engineering toolkits against real people. If an authorized awareness exercise is in scope, it must be explicitly contracted and coordinated by the client's security team; help with planning, metrics, and training content instead.

## 7. Dated advice in the source material

The 2013 book lists browser add-ons and filters (NoScript, Internet Explorer's XSS filter, early `X-Content-Security-Policy` headers, Chrome's XSS auditor). Browser XSS filters have been removed from modern browsers and must not be relied on. Use output encoding, framework protections, `Content-Security-Policy`, and cookie flags instead.
