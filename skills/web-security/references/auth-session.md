# Authentication and Session Management

## Contents
1. Why this area fails so often
2. Review checklist: authentication
3. Review checklist: sessions
4. Testing (authorized, test accounts only)
5. Fixes and modern practice

## 1. Why it fails

HTTP is stateless, so login and sessions were bolted on. Authentication also reaches far beyond the login form: password change, password reset, account recovery, secret questions, "remember me", and account management all count. A weakness in any one of them undermines the rest, and a compromised admin account is the worst case.

Don't invent your own: use the framework's built-in authentication and session handling. Most mistakes come from skipping it.

## 2. Review checklist: authentication

- Every page, API route, and static resource (scripts, PDFs, images) requires authentication unless intentionally public
- All authentication checks run on the server; client-side checks are cosmetic
- One centralized implementation of authentication logic, not copies per route
- Failures are secure (an error in the auth check denies access)
- Lockout or throttling after repeated failures, long enough to deter brute force (without enabling easy denial of service against a user)
- Password change, reset, and recovery are at least as strong as login itself
- Re-authentication required before sensitive actions (email change, payment details, password change)
- Login responses and reset flows don't reveal whether a username exists
- No default, predictable, or never-expiring initial passwords; predictable usernames noted
- Passwords stored as salted hashes with a unique salt per account, never reversible; credentials for external services kept out of source code in protected storage
- Authentication decisions are logged
- Password fields don't echo input; forms avoid caching secrets
- Third-party auth code and libraries reviewed or from trusted maintained sources

## 3. Review checklist: sessions

- Framework default session management used
- Session ID changed at login and re-authentication, and invalidated at logout
- Idle timeout and an absolute maximum lifetime; working logout available on every authenticated page
- Session ID appears only in a cookie, never in URLs, logs, or error messages; no URL-based session IDs
- Server accepts only IDs it generated; IDs are long and random (use the framework generator)
- Cookies scoped with restrictive domain and path

## 4. Testing

- Check lockout and throttling with a small number of attempts against a test account. Large brute-force runs against real accounts are out of bounds; online guessing is slow and noisy, and weak passwords are the usual reason it works.
- Walk the reset and recovery flows for weak tokens, reusable links, or enumeration.
- Inspect session cookies in a proxy: flags, scope, whether the ID changes on login, whether it is invalidated on logout.
- Attacks on session IDs fall into two kinds: weak generation (rarely a problem with modern frameworks) and mishandling of a good ID (leaking it, not rotating it, not expiring it). Focus on the second kind.

## 5. Fixes and modern practice

- Hash passwords with Argon2id, bcrypt, or scrypt (the 2013 book era also accepted salted hashes broadly; fast hashes such as plain MD5/SHA-1 are not acceptable today).
- Offer or require multi-factor authentication, especially for admin accounts; prefer phishing-resistant options (passkeys/WebAuthn).
- Set cookie flags: `HttpOnly`, `Secure`, and `SameSite` (Lax or Strict).
- Rate-limit login, reset, and verification endpoints per account and per IP.
- Block known-breached and very common passwords; favor length over composition rules.
- Rotate session IDs on privilege change; shorten lifetimes for admin sessions.
- OWASP's Application Security Verification Standard (ASVS) has detailed authentication and session checklists to measure against.
