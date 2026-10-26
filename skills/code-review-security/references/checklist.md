# Security Review Checklist

Contents: 1 Input validation · 2 AuthN/AuthZ · 3 Error handling · 4 Logging hygiene · 5 Secure defaults · 6 Secrets & crypto · 7 Data access · 8 Files & network · 9 Dependencies

Apply only the sections relevant to the code. Each item is a question; "no" or "can't tell" is a lead.

## 1. Input validation
- Is every external input validated server-side (type, length, range, format) before use?
- Allowlist (known-good) rather than denylist (known-bad)?
- Is data canonicalized (decoded, normalized, trimmed) *before* validation, not after?
- Are IDs, enums, and sort/filter fields restricted to expected values (not passed straight into queries or ORDER BY)?
- Mass assignment: can a client set fields they shouldn't (`role`, `isAdmin`, `userId`, `price`) by adding them to the body?
- Are numeric inputs bounded (negative quantities, overflow, huge page sizes)?
- Are request size, array length, and nesting depth capped?
- Schema validation library used (Zod, Pydantic, DRF serializers, Joi) rather than hand-rolled checks?
- Redirect targets, callback URLs, and file names checked against an allowlist?

## 2. Authentication and authorization
- Is authentication enforced on every non-public route, including API routes, server actions, and webhooks?
- Object-level authorization: does each fetch/update/delete verify the record belongs to the caller (IDOR/BOLA)?
- Function-level authorization: are admin/privileged actions checked on the server, not just hidden in the UI?
- Tenant isolation: every query scoped by tenant/user, including joins, counts, and exports?
- Sessions/JWTs: signature verified, algorithm pinned, expiry set, audience/issuer checked, revocation path exists?
- Login, reset, OTP, and invite flows rate-limited and resistant to enumeration and brute force?
- Password storage uses a slow adaptive hash (argon2, bcrypt, scrypt)? Reset tokens single-use, short-lived, unguessable?
- Cookie-authed state changes protected against CSRF (SameSite, tokens, origin checks)?

## 3. Error handling
- Do errors fail closed (deny on exception), never fall through to "allowed"?
- Are internal details (stack traces, SQL, file paths, library versions) kept out of client responses?
- Are errors for login/reset/lookup uniform so they don't reveal whether an account exists?
- Any empty or overly broad `catch`/`except` that swallows security-relevant failures?
- Are resources (files, connections, locks) released on error paths?
- Are unhandled promise rejections / async errors in handlers caught?
- Is there a global handler that returns a generic message plus a correlation ID?

## 4. Logging hygiene
- Are passwords, tokens, API keys, session IDs, full card/ID numbers, and raw auth headers excluded from logs?
- Is PII minimized or masked (email partially masked, no full request bodies)?
- Is user-controlled text neutralized before logging (newlines/control chars) to prevent log forging?
- Are security events logged: login success/failure, permission denied, privilege changes, token refresh failures, repeated validation rejections?
- Do logs include who/what/when/where (user ID, action, resource, IP, request ID)?
- Are `console.log`/`print` debugging leftovers removed from production paths?
- Are log and error-tracking destinations access-controlled, with retention limits?

## 5. Secure defaults
- Deny by default: new routes/tables/buckets start private?
- Debug mode, verbose errors, and test credentials off in production config?
- CORS: specific origins, not `*` with credentials?
- Cookies: `HttpOnly`, `Secure`, appropriate `SameSite`, scoped path/domain?
- Security headers present (CSP, HSTS, X-Content-Type-Options, frame-ancestors, Referrer-Policy)?
- TLS enforced; no HTTP fallbacks; certificate verification not disabled?
- Least privilege for DB users, API keys, cloud roles, and service accounts?
- Token/session lifetimes short with sensible refresh behavior?
- Feature flags and admin endpoints default to off/closed?

## 6. Secrets and crypto
- No hardcoded keys, passwords, tokens, or connection strings in code, committed config, or client bundles?
- Server-only secrets never exposed through public env prefixes (`NEXT_PUBLIC_`, `VITE_`, etc.), and no Supabase service-role key in the browser?
- Standard, current algorithms (AES-GCM, ChaCha20-Poly1305, SHA-256+, Ed25519); no MD5/SHA1 for security, no ECB, no homemade crypto?
- Randomness for tokens from a CSPRNG (`crypto.randomBytes`, `secrets`), never `Math.random`/`random`?
- Secret comparison is constant-time where relevant (HMAC, tokens)?

## 7. Data access
- Queries parameterized or built through the ORM; no string concatenation/f-strings/template literals into SQL, NoSQL operators, or shell?
- NoSQL: can the client inject operators (`{"$ne": null}`) through JSON bodies?
- Row-level security or equivalent enforced at the data layer, not only in app code?
- Responses return only needed fields (no password hashes, internal flags, other users' data)?
- Pagination and query cost bounded to prevent data scraping and DoS?
- Sensitive fields encrypted at rest or otherwise protected as required?

## 8. Files and network
- Uploads: type and size checked server-side, content sniffed, stored outside web root with generated names, served with safe headers?
- Path handling: user input never joined into file paths without normalization and a base-directory check (path traversal, zip-slip)?
- Outbound requests built from user URLs restricted by allowlist and blocked from internal ranges/metadata endpoints (SSRF)?
- HTML output encoded for its context; any raw-HTML sink sanitized with a vetted library?
- Deserialization uses safe formats (JSON), never pickle/unsafe YAML/native object deserialization on untrusted input?
- Webhooks verify signatures and timestamps (replay protection)?

## 9. Dependencies and supply chain
- Lockfile committed; versions pinned; automated advisory scanning enabled (`npm audit`, `pip-audit`, Dependabot)?
- Any unmaintained, typosquat-looking, or install-script-heavy packages?
- CI/CD secrets scoped and not exposed to untrusted PRs?
- Docker images pinned, non-root user, minimal base?
