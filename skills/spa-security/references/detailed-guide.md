# SPA & Frontend Framework Security — Technical Reference

## 1. Hydration Internals & Threat Mechanics

Client-side hydration is the process where React/Vue/Angular traverses the existing HTML DOM
rendered by the server and attaches event listeners, internal state fibers, and reactive observers.

### Why Hydration Mismatches Create Vulnerabilities
1. **DOM Tree Desynchronization:** If an attacker can inject raw HTML into the server response (e.g. via an SSR injection flaw), the client framework may mismatch the virtual DOM against the real DOM. In some scenarios, event listeners can attach to attacker-injected nodes.
2. **Attribute Injection:** When the server renders attributes based on untrusted data and the client reconciles with suppressed warnings (`suppressHydrationWarning`), the injected malicious attributes (such as `formaction` or malicious event-triggering URIs) remain in the live DOM.

```
Server Response (HTML) ─────────► Browser parses DOM ─────────► Framework Hydrates DOM
      │                                                               │
  Contains user data                                          Attaches event listeners
  without safe encoding                                       to DOM nodes
```

---

## 2. Safe Serialization Patterns for SSR State

Never inject raw JSON objects into executable inline `<script>` tags.

### Vulnerable Approach
```html
<script>
  window.__INITIAL_DATA__ = {"username": "</script><script>alert(1)</script>"};
</script>
```

### Best Practice 1: Application/JSON Script Tags
Embed data in a non-executable MIME type `<script type="application/json">`:

```html
<!-- Server renders: -->
<script type="application/json" id="__APP_DATA__">
  {"username": "Alice", "role": "user"}
</script>

<!-- Client reads safely: -->
<script>
  const rawData = document.getElementById('__APP_DATA__').textContent;
  window.__INITIAL_DATA__ = JSON.parse(rawData);
</script>
```
The browser's HTML parser will not execute any JavaScript inside `type="application/json"` even if `<script>` or other tags are present.

### Best Practice 2: Unicode Escaping with `serialize-javascript`
If inline assignment is required:

```javascript
const serialize = require('serialize-javascript');

const safeHtml = `
  <script>
    window.__INITIAL_DATA__ = ${serialize(data, { isJSON: true })};
  </script>
`;
```
This converts `<` to `\u003C` and `>` to `\u003E`, preventing tag termination.

---

## 3. Next.js Server Actions Security Deep-Dive

Next.js Server Actions (`"use server"`) provide direct RPC-like invocations from client components
to server functions.

### Key Security Realities of Server Actions:
1. **Server Actions are Public Endpoints:** Each Server Action is assigned a cryptographic action ID and exposed as an HTTP POST endpoint. They can be triggered by any HTTP client, not just your frontend UI.
2. **Input is Untrusted:** Any argument passed to a Server Action can be altered or forged.

### Secure Server Action Pattern (Zod + Auth)

```typescript
'use server'

import { z } from 'zod';
import { auth } from '@/lib/auth';
import { db } from '@/lib/db';

const UpdateProfileSchema = z.object({
  bio: z.string().max(500),
  website: z.string().url().optional()
});

export async function updateProfile(formData: unknown) {
  // 1. Authenticate session
  const session = await auth();
  if (!session?.user?.id) {
    return { error: 'Unauthorized', status: 401 };
  }

  // 2. Validate input schema
  const parsed = UpdateProfileSchema.safeParse(formData);
  if (!parsed.success) {
    return { error: 'Invalid input', issues: parsed.error.issues, status: 400 };
  }

  // 3. Mutate strictly for the authenticated user
  const updated = await db.user.update({
    where: { id: session.user.id },
    data: parsed.data
  });

  return { success: true, data: { bio: updated.bio } };
}
```

---

## 4. Client-Side Route Guards vs Backend Authorization

In Single Page Applications, routing guards provide user navigation guidance, **not authorization**.

```
                CLIENT (Browser)                               BACKEND (API)
┌──────────────────────────────────────────────┐    ┌───────────────────────────────────┐
│ User navigates to /admin                     │    │                                   │
│ React Router checks: user.isAdmin === true   │    │                                   │
│ ⚠️ Bypassed by modifying JS state or DevTools│    │                                   │
│                                              │    │                                   │
│ Component makes fetch('/api/admin/metrics')  │───►│ API Gateway / Controller          │
│                                              │    │ Validates session cookie / JWT    │
│                                              │    │ Checks DB role in session         │
│                                              │    │ Returns 403 Forbidden if invalid  │
└──────────────────────────────────────────────┘    └───────────────────────────────────┘
```

Always enforce the principle of **Zero Trust Frontend**: assume the client application is
completely compromised, and enforce role checks on every API route, GraphQL resolver, and
server mutation.

---

## 5. Framework Sanitizer Comparison & Best Practices

| Framework | Built-in Sanitization | Safe Binding | Escape Hatch (Dangerous) | Recommended Add-on |
|---|---|---|---|---|
| **React** | Contextual string encoding | `{content}` | `dangerouslySetInnerHTML` | `DOMPurify` |
| **Vue 3** | Text interpolation encoding | `{{ content }}` | `v-html` | `DOMPurify` |
| **Angular** | Strict contextual sanitization | `{{ content }}` | `DomSanitizer.bypassSecurityTrust*` | Built-in or `DOMPurify` |
| **Svelte** | HTML entity escaping | `{content}` | `{@html content}` | `DOMPurify` |

### Standard DOMPurify Wrapper Utility

```typescript
// src/utils/sanitize.ts
import DOMPurify from 'dompurify';

export function sanitizeHtml(dirty: string): string {
  if (typeof window === 'undefined') {
    // If running in SSR (Node.js), use jsdom with dompurify
    const { JSDOM } = require('jsdom');
    const windowMock = new JSDOM('').window;
    const purify = DOMPurify(windowMock);
    return purify.sanitize(dirty);
  }
  return DOMPurify.sanitize(dirty);
}
```
