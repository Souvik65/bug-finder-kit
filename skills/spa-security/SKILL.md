---
name: spa-security
description: >
  Comprehensive Single Page Application (SPA) and modern frontend framework security
  audit skill. Audits React, Vue, Angular, Next.js, Nuxt, and Svelte applications
  for framework-specific vulnerabilities: Server-Side Rendering (SSR) state injection,
  client-side hydration mismatch attacks, raw HTML rendering sinks (dangerouslySetInnerHTML,
  v-html, [innerHTML]), insecure dynamic component imports, client-side route guard
  bypass without server enforcement, Angular template injection and sanitizer bypasses,
  Vue runtime compiler risks, React Server Components (RSC) boundary leakage, and
  unauthenticated Server Action execution. Activate when the user asks to "audit SPA security",
  "React security review", "Vue security audit", "Angular security check", "Next.js SSR security",
  "hydration mismatch vulnerability", "client-side route guard bypass", or "dangerouslySetInnerHTML audit".
triggers:
  - "SPA security"
  - "React security"
  - "Vue security"
  - "Angular security"
  - "Next.js security"
  - "hydration attack"
  - "dangerouslySetInnerHTML"
  - "v-html"
  - "route guard bypass"
  - "SSR injection"
  - "Server Components security"
  - "Server Actions security"
  - "SPA audit"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
tags: "[spa-security, react-security, vue-security, angular-security, nextjs, hydration, ssr-injection, route-guards, dangerouslySetInnerHTML, v-html]"
date_added: "2026-10-23"
---

# Single Page Application (SPA) & Frontend Framework Security Audit

> Modern Single Page Applications (SPAs) and hybrid SSR frameworks (React, Next.js, Vue,
> Nuxt, Angular, SvelteKit) shift substantial routing, state management, and rendering
> logic directly into the client browser. This architectural shift introduces specialized
> vulnerability classes that traditional static code analyzers and generic XSS scanners
> miss completely: hydration mismatch exploitation, client-only route guard illusions,
> SSR initial state script breakouts, unauthenticated React Server Actions, and dynamic
> component path injection.

---

## SPA & Modern Frontend Attack Surface Taxonomy

```
SPA Security Attack Surface
  ├── 1. Server-Side Rendering (SSR) & State Serialization
  │     ├── window.__INITIAL_STATE__ script-tag breakout via unescaped JSON
  │     ├── __NEXT_DATA__ / __NUXT__ payload injection
  │     └── Server-Side Request Forgery (SSRF) during SSR pre-fetching
  ├── 2. Hydration Mismatch & DOM Desync Attacks
  │     ├── Server/client markup divergence altering execution contexts
  │     ├── Attribute pollution through suppressed hydration warnings
  │     └── Injected DOM attributes hijacking React synthetic events
  ├── 3. Raw HTML & Unsafe Framework Sinks
  │     ├── React: dangerouslySetInnerHTML={{ __html: untrusted }}
  │     ├── Vue: v-html with unsanitized user content
  │     ├── Angular: DomSanitizer.bypassSecurityTrust* overuse
  │     └── Svelte: {@html untrusted} raw rendering
  ├── 4. Insecure Dynamic Component Loading
  │     ├── User-controlled dynamic imports: import(`./components/${userInput}`)
  │     ├── Dynamic Vue component tags: <component :is="userInput" />
  │     └── Prototype pollution triggering unauthorized component rendering
  ├── 5. Client-Side Route Guard & Navigation Illusions
  │     ├── Private views protected ONLY in react-router/vue-router/Angular CanActivate
  │     ├── Unprotected backend REST/GraphQL endpoints serving sensitive data
  │     └── Secret data embedded in client bundles or SSR payloads for hidden routes
  ├── 6. React Server Components (RSC) & Server Actions
  │     ├── "use server" actions callable directly via HTTP without auth checks
  │     ├── Passing sensitive backend objects/tokens across the RSC boundary to Client Components
  │     └── Prototype pollution or parameter tampering in Server Action arguments
  ├── 7. Framework Template Injection & Sandbox Escapes
  │     ├── Vue runtime template compilation (eval-like compilation of user strings)
  │     ├── Angular legacy AngularJS expression sandboxes ($eval breakouts)
  │     └── User input passed into template interpolators
  └── 8. Build Configuration & Development Artifact Leaks
        ├── React/Vue DevTools enabled in production bundles
        ├── Source maps (.map) deployed to production exposing proprietary logic
        └── Environment variables (NEXT_PUBLIC_*, VITE_*) containing secrets
```

---

## Phase 1: SSR State Injection & Initial State Breakout

Hybrid applications serialize server state into the HTML page so the client can "hydrate"
the interactive DOM without refetching data. If state objects contain user-supplied strings
and are serialized with native `JSON.stringify()`, closing HTML tags (like `</script>`) inside
the JSON string will terminate the script tag immediately and execute arbitrary HTML/JavaScript.

### Vulnerable Pattern: Raw `JSON.stringify` into `<script>`

```javascript
// ❌ VULNERABLE: Direct JSON.stringify inside an HTML script tag
// If user.bio contains: "</script><script>alert(document.domain)</script>"
// the browser terminates the JSON script block immediately!
app.get('/profile', async (req, res) => {
  const userData = await getUser(req.query.id);
  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <script>
          window.__PRELOADED_STATE__ = ${JSON.stringify(userData)};
        </script>
      </head>
      <body><div id="root">${renderToString(<App data={userData} />)}</div></body>
    </html>
  `;
  res.send(html);
});
```

### Remediated Pattern: Serialized with `serialize-javascript` or Escaped Unicode

```javascript
// ✅ SAFE: Use serialize-javascript with { isJSON: true } or encode unsafe chars
const serialize = require('serialize-javascript');

app.get('/profile', async (req, res) => {
  const userData = await getUser(req.query.id);
  
  // serialize-javascript automatically escapes '<' to '\\u003C', '/' to '\\u002F'
  const safeJsonState = serialize(userData, { isJSON: true });

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <script>
          window.__PRELOADED_STATE__ = ${safeJsonState};
        </script>
      </head>
      <body><div id="root">${renderToString(<App data={userData} />)}</div></body>
    </html>
  `;
  res.send(html);
});
```

Alternatively, use a `<script type="application/json" id="__STATE__">` tag and parse it via
`JSON.parse(document.getElementById('__STATE__').textContent)` on the client side, which is
immune to script execution breakouts.

---

## Phase 2: Hydration Mismatch & DOM Desync Exploitation

Hydration happens when the client-side framework (React/Vue/Angular) loads in the browser and
attaches event handlers and state to the server-rendered HTML. If the server HTML diverges from
the client render, a hydration mismatch occurs.

### Attack Vector: Hydration Attribute Injection
When developers use `suppressHydrationWarning` (React) or ignore hydration mismatches, malicious
content injected into server HTML can persist or trick the client reconciler into attaching
event handlers to attacker-controlled nodes.

```tsx
// ⚠️ DANGEROUS: Suppressing hydration warnings can mask injection artifacts
<div 
  suppressHydrationWarning={true}
  dangerouslySetInnerHTML={{ __html: serverRenderedMarkup }}
/>
```

### Audit Steps for Hydration Vulnerabilities
1. Search for `suppressHydrationWarning` across React/Next.js codebases. Verify why hydration
   mismatch warnings are suppressed.
2. Check if user-controlled input appears in server-rendered attributes (`href`, `src`, `data-*`).
   If the client renders different defaults, verify if browser-injected extensions or markup
   tampering can survive reconciliation.
3. Check for time-of-day, window-dependent (`typeof window !== 'undefined'`), or cookie-dependent
   rendering differences between server and client that could permit unauthorized view exposure.

---

## Phase 3: Raw HTML Framework Sinks

Every framework provides an escape hatch to inject raw HTML into the DOM. These sinks completely
bypass the framework's built-in XSS contextual encoding engines.

### 1. React: `dangerouslySetInnerHTML`
```tsx
// ❌ VULNERABLE: Direct rendering of untrusted content
function CommentView({ commentText }) {
  return <div dangerouslySetInnerHTML={{ __html: commentText }} />;
}

// ✅ SAFE: Sanitize with DOMPurify before passing to dangerouslySetInnerHTML
import DOMPurify from 'dompurify';

function CommentView({ commentText }) {
  const cleanHtml = DOMPurify.sanitize(commentText, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p'],
    ALLOWED_ATTR: ['href', 'target', 'rel']
  });
  return <div dangerouslySetInnerHTML={{ __html: cleanHtml }} />;
}
```

### 2. Vue: `v-html`
```html
<!-- ❌ VULNERABLE: Direct v-html binding -->
<template>
  <div v-html="userDescription"></div>
</template>

<!-- ✅ SAFE: Computed sanitized property -->
<script setup>
import DOMPurify from 'dompurify';
import { computed } from 'vue';

const props = defineProps(['userDescription']);
const sanitizedDescription = computed(() => DOMPurify.sanitize(props.userDescription));
</script>

<template>
  <div v-html="sanitizedDescription"></div>
</template>
```

### 3. Angular: `DomSanitizer.bypassSecurityTrust*`
Angular sanitizes values bound to `[innerHTML]` by default. However, developers often bypass
this using `DomSanitizer`:

```typescript
// ❌ VULNERABLE: Bypassing Angular's built-in sanitizer on untrusted input
import { Component, Input } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
  selector: 'user-bio',
  template: `<div [innerHTML]="trustedBio"></div>`
})
export class UserBioComponent {
  trustedBio: SafeHtml;

  constructor(private sanitizer: DomSanitizer) {}

  @Input() set bio(value: string) {
    // Calling bypassSecurityTrustHtml completely disables Angular XSS protection!
    this.trustedBio = this.sanitizer.bypassSecurityTrustHtml(value);
  }
}

// ✅ SAFE: Sanitize using DOMPurify before bypassing, or rely on Angular defaults
import DOMPurify from 'dompurify';

@Input() set bio(value: string) {
  const clean = DOMPurify.sanitize(value);
  this.trustedBio = this.sanitizer.bypassSecurityTrustHtml(clean);
}
```

---

## Phase 4: Insecure Dynamic Component Loading & Imports

Modern SPAs dynamically import components for route code-splitting or modular widget rendering.
If any part of the component path or component name is derived from user input (query parameters,
route slugs, or database values), attackers can load unintended modules or trigger path traversal.

### Vulnerable Pattern: User Input in Dynamic `import()`

```typescript
// ❌ VULNERABLE: Dynamic import with user-controlled parameter
// URL: /widget?name=../../admin/SecretAdminDashboard
import React, { useState, useEffect } from 'react';

export function WidgetLoader({ widgetName }) {
  const [Component, setComponent] = useState(null);

  useEffect(() => {
    // Dynamic import resolves arbitrary modules or components
    import(`./widgets/${widgetName}`)
      .then(mod => setComponent(() => mod.default))
      .catch(err => console.error("Widget load failed", err));
  }, [widgetName]);

  if (!Component) return <div>Loading...</div>;
  return <Component />;
}
```

### Remediated Pattern: Strict Component Allowlist / Registry Map

```typescript
// ✅ SAFE: Explicit component lookup table
import dynamic from 'next/dynamic';

const WIDGET_REGISTRY = {
  weather: dynamic(() => import('./widgets/WeatherWidget')),
  calendar: dynamic(() => import('./widgets/CalendarWidget')),
  clock: dynamic(() => import('./widgets/ClockWidget'))
} as const;

type WidgetKey = keyof typeof WIDGET_REGISTRY;

export function WidgetLoader({ widgetName }: { widgetName: string }) {
  const SafeComponent = WIDGET_REGISTRY[widgetName as WidgetKey];

  if (!SafeComponent) {
    return <div>Invalid widget selected</div>;
  }

  return <SafeComponent />;
}
```

---

## Phase 5: Client-Side Route Guard Bypass & Illusion

A prevalent architectural flaw in SPAs is relying **solely on client-side route guards** for
authorization.

### The Route Guard Fallacy
In React Router (`<Navigate />`), Vue Router (`beforeEach`), or Angular (`CanActivate`),
a route guard merely determines whether the client browser should display a particular
component tree. **It does not secure data.**

```typescript
// ❌ ARCHITECTURAL FLAW: Client-only route guard
// An attacker can disable React Router in DevTools, set localStorage.role = 'admin',
// or directly inspect network bundles to bypass this guard!
const AdminRoute = ({ children }) => {
  const { user } = useAuth();
  if (!user || user.role !== 'admin') {
    return <Navigate to="/unauthorized" replace />;
  }
  return children;
};
```

### Critical Audit Checkpoints for Route Guards:
1. **API Independence:** Does every backend endpoint (REST/GraphQL/Server Action) independently
   validate the user's session token and permissions on *every single request*?
2. **Bundle Segregation:** Does the frontend JavaScript bundle contain sensitive business logic,
   PII, admin dashboard schemas, or internal API documentation inside code chunks that are
   downloaded even by non-admin visitors?
3. **Lazy-Chunk Protection:** Are code-split chunks for administrative routes hosted on public
   CDNs without authentication? If sensitive logic exists in those chunks, any unauthenticated
   user can download and decompile the chunk.

---

## Phase 6: React Server Components (RSC) & Server Actions

Next.js App Router and modern React introduce Server Actions (`"use server"`) and React Server
Components. These blur the boundary between server and client, opening subtle security risks:

### 1. Unauthenticated Server Actions
Server Actions generate an internal POST HTTP endpoint (e.g. `/_next/action/...`). Anyone can
invoke these HTTP endpoints directly using `curl` or Postman, completely bypassing the client UI!

```typescript
// ❌ VULNERABLE: Server Action missing authorization check
'use server'

import prisma from '@/lib/db';

export async function deleteUserAccount(targetUserId: string) {
  // Vulnerable to IDOR: Anyone can forge an HTTP request to this Server Action
  // and delete any user account!
  await prisma.user.delete({ where: { id: targetUserId } });
}

// ✅ SAFE: Authenticate and authorize inside EVERY Server Action
'use server'

import prisma from '@/lib/db';
import { getSession } from '@/lib/auth';

export async function deleteUserAccount(targetUserId: string) {
  const session = await getSession();
  if (!session || !session.userId) {
    throw new Error('Unauthorized');
  }

  // Enforce access control
  if (session.userId !== targetUserId && session.role !== 'admin') {
    throw new Error('Forbidden: Cannot delete other accounts');
  }

  await prisma.user.delete({ where: { id: targetUserId } });
}
```

### 2. Leaking Server Secrets via RSC Props
Passing backend database models directly to Client Components (`"use client"`) exposes all model
properties in the React Flight / RSC hydration payload streamed over HTTP:

```tsx
// ❌ VULNERABLE: Passing full DB user record (with passwordHash / secrets) to Client Component
// app/users/page.tsx (Server Component)
import { UserCard } from './UserCard'; // 'use client'
import prisma from '@/lib/db';

export default async function Page() {
  const user = await prisma.user.findFirst();
  // user object contains: { id, email, passwordHash, twoFactorSecret, apiKey }
  // Even if UserCard only renders user.email, ALL fields are sent in the network payload!
  return <UserCard user={user} />;
}

// ✅ SAFE: Explicitly project only safe public fields
export default async function Page() {
  const user = await prisma.user.findFirst();
  const safeUser = {
    id: user.id,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl
  };
  return <UserCard user={safeUser} />;
}
```

---

## Phase 7: Framework Template Injection & Sandbox Escapes

### Vue.js Runtime Template Compilation
When Vue is configured with the runtime compiler (`vue.esm-bundler.js`), user input can be compiled
as a template string, enabling arbitrary JavaScript execution:

```javascript
// ❌ VULNERABLE: Compiling user-supplied string as a Vue template
import { compile, h } from 'vue';

app.get('/render', (req, res) => {
  const userTemplate = req.query.template; // e.g. {{ constructor.constructor('alert(1)')() }}
  const renderFn = compile(userTemplate);
  // Executes arbitrary JS in the application context!
});
```
**Remediation:** Always use Vue Single File Components (SFC) compiled ahead-of-time (AOT) with Vite
or webpack. Never use `compile()` or `template: userInput` with untrusted data.

### AngularJS Expression Sandbox Escapes (Legacy)
If auditing an AngularJS (1.x) application:
- Never combine server-side templates (JSP, PHP, Jinja2) with client-side AngularJS bindings.
- Expressions like `{{ constructor.constructor('alert(1)')() }}` escape client sandboxes in
  almost every AngularJS release.

---

## Phase 8: Production Build Configuration & DevTools Exposure

In development mode, React, Vue, and Angular provide verbose warning messages, component
inspectors, and global hooks. In production, these must be disabled.

### React DevTools Global Hook
Attackers can hook into `window.__REACT_DEVTOOLS_GLOBAL_HOOK__` to read component internal state,
inspect Redux stores, or intercept credentials stored in component state.

### Audit Checklist:
1. **Production Mode Check:** Verify `NODE_ENV === 'production'` during the build process.
2. **Source Map Leaks:** Check if `build.sourcemap: true` or `productionBrowserSourceMaps: true`
   is enabled in production configs, deploying `.js.map` files to public servers.
3. **Public Environment Variables:** Scan `.env` files for secrets accidentally prefixed with:
   - `NEXT_PUBLIC_*` (Next.js)
   - `VITE_*` (Vite)
   - `REACT_APP_*` (Create React App)
   - `NUXT_PUBLIC_*` (Nuxt)
   Any variable with these prefixes is bundled directly into the public client JavaScript!

---

## Phase 9: Automated Grep & Detection Script

Execute this detection script to scan frontend repositories for common SPA vulnerabilities:

```powershell
# PowerShell SPA Security Scanner
Write-Host "=== Scanning for Raw HTML Sinks ===" -ForegroundColor Cyan
Get-ChildItem -Recurse -Include *.jsx,*.tsx,*.js,*.ts,*.vue,*.html | Select-String -Pattern "dangerouslySetInnerHTML", "v-html", "\[innerHTML\]", "bypassSecurityTrust" | Select-Object Path, LineNumber, Line

Write-Host "`n=== Scanning for SSR JSON Breakout Sinks ===" -ForegroundColor Cyan
Get-ChildItem -Recurse -Include *.jsx,*.tsx,*.js,*.ts | Select-String -Pattern "window\.__[A-Z0-9_]+__\s*=\s*\$\{JSON\.stringify" | Select-Object Path, LineNumber, Line

Write-Host "`n=== Scanning for Unchecked Server Actions ===" -ForegroundColor Cyan
Get-ChildItem -Recurse -Include *.ts,*.tsx | Select-String -Pattern "'use server'|\"use server\"" | Select-Object Path, LineNumber, Line

Write-Host "`n=== Scanning for Dynamic Imports with Template Strings ===" -ForegroundColor Cyan
Get-ChildItem -Recurse -Include *.jsx,*.tsx,*.js,*.ts,*.vue | Select-String -Pattern "import\s*\(\s*`.*?\$\{.*?\}`\s*\)" | Select-Object Path, LineNumber, Line

Write-Host "`n=== Scanning for Public Env Secret Leaks ===" -ForegroundColor Cyan
Get-ChildItem -Recurse -Include *.env* | Select-String -Pattern "(NEXT_PUBLIC|VITE|REACT_APP)_(KEY|SECRET|TOKEN|PASSWORD|PRIVATE)" | Select-Object Path, LineNumber, Line
```

---

## Phase 10: Finding Template & Remediation Checklist

When reporting SPA security flaws, structure findings using this standard template:

### Finding Template
```markdown
### [VULN-SPA-001] Client-Side Route Guard Lacks Backend Authorization Enforcement

- **Severity:** High
- **Framework:** Next.js / React Router
- **Location:** `src/routes/AdminDashboard.tsx:24` and `src/api/admin/users.ts:12`
- **Flaw Description:** The `/admin` dashboard relies entirely on a client-side `<AdminRoute>`
  guard checking `user.role === 'admin'`. The underlying API endpoint `/api/admin/users` does not
  validate the requesting user's session token or database role before returning the full customer
  database. Any authenticated non-admin user can fetch administrative data directly by calling
  the API via `fetch()` or Postman.
- **Evidence / Code:**
  ```tsx
  // src/routes/AdminDashboard.tsx
  if (currentUser.role !== 'admin') return <Navigate to="/home" />;
  ```
- **Remediation:**
  1. Implement server-side session and role validation on `/api/admin/users`.
  2. Reject unauthorized requests with HTTP `403 Forbidden` at the server gateway.
  3. Ensure client-side guards are strictly UX helpers and never treated as security boundaries.
- **Confidence:** High
```

### Remediation Checklist
- [ ] Replace raw `JSON.stringify()` in SSR templates with `serialize-javascript` or `<script type="application/json">`.
- [ ] Sanitize all inputs to `dangerouslySetInnerHTML`, `v-html`, and `[innerHTML]` using `DOMPurify`.
- [ ] Restrict dynamic `import()` and dynamic `<component :is="...">` calls to strict allowlists.
- [ ] Ensure all backend API endpoints and Server Actions independently authenticate and authorize callers.
- [ ] Strip sensitive properties before passing server-side data models to Client Components across RSC boundaries.
- [ ] Disable source maps and developer tools in production build scripts.
- [ ] Verify that `.env` public prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`) contain only non-sensitive constants.
