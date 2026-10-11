---
name: auth-security
description: >
  Authentication and authorization security review skill. Audits login flows,
  session management, JWT/OAuth/OIDC implementations, password policies, RBAC/ABAC
  enforcement, privilege escalation paths, insecure direct object references (IDOR),
  and multi-factor authentication gaps. Activate when the user asks to "audit auth",
  "review authentication", "check authorization", "session security", "JWT security",
  "OAuth review", "check RBAC", or "privilege escalation".
triggers:
  - "audit auth"
  - "review authentication"
  - "check authorization"
  - "session security"
  - "JWT security"
  - "OAuth review"
  - "check RBAC"
  - "privilege escalation"
  - "access control"
  - "IDOR"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
---

# Auth Security — Authentication & Authorization Review

> Comprehensive review of authentication mechanisms, session handling, access
> control enforcement, and identity management. Covers the full identity lifecycle
> from registration to account deletion.

---

## Phase 1 — Password Security

### Hashing Algorithm Audit

```bash
# Find password hashing code
grep -rn "bcrypt\|argon2\|scrypt\|pbkdf2\|hashpw\|hash_password\|make_password\|hashSync" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" --include="*.php" .

# Find DANGEROUS hashing
grep -rn "md5\|sha1\|sha256.*password\|hashlib\.sha\|SHA1.*pass\|MD5.*pass" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" --include="*.php" . -i
```

### Hashing Standards

| Algorithm | Status | Min Cost/Iterations |
|---|---|---|
| **argon2id** | ✅ Recommended | memory=64MB, iterations=3, parallelism=4 |
| **bcrypt** | ✅ Acceptable | cost factor ≥ 12 |
| **scrypt** | ✅ Acceptable | N=32768, r=8, p=1 |
| **PBKDF2-SHA256** | ⚠️ Acceptable if tuned | iterations ≥ 600,000 |
| **SHA-256/SHA-512** (unsalted) | ❌ Dangerous | Never use for passwords |
| **MD5, SHA-1** | ❌ Dangerous | Never use for passwords |
| **plaintext** | ❌ Critical | Immediate critical finding |

**Check bcrypt cost factor:**
```javascript
// JavaScript — flag if cost < 12
bcrypt.hash(password, 10)  // cost=10 — flag as LOW (should be ≥12)
bcrypt.hash(password, 5)   // cost=5 — flag as HIGH
```

```python
# Python — flag if rounds < 12
bcrypt.hashpw(password, bcrypt.gensalt(rounds=10))  # flag — rounds too low
```

### Password Policy
```bash
# Find password validation logic
grep -rn "password.*length\|minlength\|min_length\|\.length.*8\|password.*regex\|password.*pattern" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" --include="*.php" . -i
```

**Minimum requirements:**
- [ ] Minimum length ≥ 12 characters (NIST SP 800-63B recommends 8, but ≥ 12 is better)
- [ ] Maximum length ≥ 64 characters (do not truncate passwords)
- [ ] Allow all printable ASCII including spaces
- [ ] Check against known breached passwords (HaveIBeenPwned API)
- [ ] No complexity requirements that reduce entropy (prefer length)

---

## Phase 2 — Session Management

### Session Token Security

```bash
# Find session configuration
grep -rn "session\s*(\|session\.use\|SessionStore\|session_start\|cookieParser" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" --include="*.php" . | head -20

# Find session secret
grep -rn "session.*secret\|SESSION_SECRET\|secret.*session" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" . -i
```

### Session Checklist

- [ ] **Session ID entropy**: ≥ 128 bits (16 bytes) of cryptographic randomness
- [ ] **Session fixation prevention**: Session ID regenerated after login
- [ ] **Session ID not in URL**: Check for `JSESSIONID`, `PHPSESSID` in query string
- [ ] **Cookie flags**:
  - `HttpOnly` — prevents JavaScript access
  - `Secure` — HTTPS only
  - `SameSite=Strict` or `Lax` — CSRF protection
- [ ] **Idle timeout**: Session expires after inactivity (≤ 30 min for sensitive apps)
- [ ] **Absolute timeout**: Session expires regardless of activity (≤ 8 hours)
- [ ] **Logout**: Session destroyed on server-side, not just client-side cookie deletion

```javascript
// Express-session — check configuration
app.use(session({
    secret: process.env.SESSION_SECRET,  // ✓ from env
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,   // ✓
        secure: true,     // ✓ (must be true in production)
        sameSite: "strict", // ✓
        maxAge: 1800000   // ✓ 30 min
    }
}))

// VULNERABLE configuration — flag these
app.use(session({
    secret: "mysecret",  // ✗ hardcoded secret
    cookie: {
        httpOnly: false, // ✗ JavaScript can read cookie
        secure: false,   // ✗ sent over HTTP
        sameSite: "none" // ✗ no CSRF protection
    }
}))
```

---

## Phase 3 — JWT Security

### JWT Configuration Audit

```bash
# Find JWT signing/verification code
grep -rn "jwt\.sign\|jwt\.verify\|jsonwebtoken\|jose\|PyJWT\|jwtlib\|JwtBuilder\|Jwts\." \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" .
```

### JWT Vulnerabilities

#### Algorithm Confusion (CVE pattern)
```javascript
// VULNERABLE — accepts "none" algorithm
jwt.verify(token, secret, { algorithms: ["HS256", "none"] })  // ✗

// VULNERABLE — doesn't specify allowed algorithms
jwt.verify(token, secret)  // ✗ — some libraries default to allowing all

// SAFE
jwt.verify(token, secret, { algorithms: ["HS256"] })  // ✓ explicit allowlist
```

#### Algorithm Switching (RS256 → HS256 confusion)
```javascript
// If using RS256, ensure the public key is NOT accepted as HS256 secret
// Flag: server uses RS256 but also accepts HS256

// SAFE: explicitly only accept the intended algorithm
jwt.verify(token, publicKey, { algorithms: ["RS256"] })  // ✓
```

#### Weak Secrets
```javascript
// Flag weak JWT secrets
const secret = "secret"         // ✗ guessable
const secret = "password"       // ✗ guessable
const secret = process.env.JWT  // check .env for the actual value

// Safe: 256-bit (32-byte) random secret
const secret = process.env.JWT_SECRET  // ✓ if value is cryptographically random
```

#### Missing Claims Validation
```javascript
// Check for expiry validation
const decoded = jwt.verify(token, secret)
// ✓ jwt.verify() automatically validates exp claim

// Flag: manual decode without verification
const decoded = jwt.decode(token)  // ✗ no signature verification!
Buffer.from(token.split('.')[1], 'base64')  // ✗ manual decode = no verification
```

```python
# PyJWT — check options
# VULNERABLE
decoded = jwt.decode(token, secret, options={"verify_exp": False})  # ✗ skip exp check
decoded = jwt.decode(token, secret, algorithms=["none", "HS256"])    # ✗ allows none

# SAFE
decoded = jwt.decode(token, secret, algorithms=["HS256"])  # ✓
```

#### Token Storage (Client-Side)
```bash
# Find where JWT is stored
grep -rn "localStorage.*token\|sessionStorage.*token\|localStorage.*jwt\|localStorage.*auth" \
    --include="*.js" --include="*.ts" .
```

| Storage | CSRF Risk | XSS Risk | Recommendation |
|---|---|---|---|
| `localStorage` | Low | HIGH | Avoid — XSS-accessible |
| `sessionStorage` | Low | HIGH | Avoid — XSS-accessible |
| `HttpOnly` cookie | SameSite=Strict | None | ✅ Recommended |
| Memory (JS variable) | Low | Low (lost on refresh) | ✅ OK for SPAs |

---

## Phase 4 — OAuth / OIDC Security

### OAuth Implementation Audit

```bash
# Find OAuth-related code
grep -rn "oauth\|authorization_code\|client_secret\|redirect_uri\|state.*oauth\|PKCE\|code_verifier" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" . -i
```

### OAuth Checklist

**State parameter (CSRF prevention):**
```javascript
// VULNERABLE — no state parameter
const authUrl = `https://provider.com/auth?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}`
// ✗ missing state — CSRF attack possible

// SAFE
const state = crypto.randomBytes(32).toString("hex")
req.session.oauthState = state
const authUrl = `...&state=${state}`
// In callback: verify req.session.oauthState === req.query.state
```

**Redirect URI validation:**
```javascript
// VULNERABLE — open redirect in OAuth callback
const redirectUri = req.query.redirect_uri  // ✗ user-controlled
// Must validate against a strict allowlist

// SAFE
const ALLOWED_REDIRECT_URIS = ["https://app.example.com/callback"]
if (!ALLOWED_REDIRECT_URIS.includes(req.query.redirect_uri)) {
    return res.status(400).send("Invalid redirect_uri")
}
```

**PKCE (for public clients):**
```javascript
// Check if PKCE is implemented for mobile/SPA OAuth flows
// Flag: public client (no client_secret) without PKCE
grep -rn "code_verifier\|code_challenge\|code_challenge_method" --include="*.js" --include="*.ts" .
```

---

## Phase 5 — Authorization & Access Control

### IDOR (Insecure Direct Object Reference)

```bash
# Find endpoints with direct ID references
grep -rn "req\.params\.id\|req\.params\.\w\+id\|params\[:id\]\|@PathVariable.*id" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.rb" --include="*.java" .
```

**Check each ID-based endpoint for authorization:**
```javascript
// VULNERABLE — IDOR
app.get("/orders/:id", async (req, res) => {
    const order = await Order.findById(req.params.id)  // ✗ no user check
    res.json(order)
})

// SAFE — verify ownership
app.get("/orders/:id", async (req, res) => {
    const order = await Order.findById(req.params.id)
    if (!order || order.userId !== req.user.id) {  // ✓ ownership check
        return res.status(403).json({ error: "Forbidden" })
    }
    res.json(order)
})
```

### Privilege Escalation Paths

```bash
# Find role assignment code
grep -rn "role\s*=\|\.role\s*=\|setRole\|updateRole\|isAdmin\s*=\|makeAdmin" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" . | grep -v "#\|//"

# Find admin/elevated permission checks
grep -rn "isAdmin\|is_admin\|hasRole\|has_role\|can\s*(\|authorize\s*(" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" .
```

**Mass assignment vulnerability:**
```javascript
// VULNERABLE — user can set their own role
const user = await User.create(req.body)  // ✗ if body contains {role: "admin"}

// SAFE — whitelist allowed fields
const user = await User.create({
    name: req.body.name,       // ✓ only allowed fields
    email: req.body.email
    // role NOT included — defaults to "user"
})
```

### Missing Function-Level Authorization

```bash
# Find admin routes
grep -rn "admin\|\/admin\|isAdmin\|requireAdmin\|@AdminOnly" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" .
```

**Check that every admin endpoint verifies admin role:**
```javascript
// VULNERABLE — only checks authentication, not authorization
app.get("/admin/users", authenticate, async (req, res) => {
    // ✗ authenticate checks login, but any user can reach this
    const users = await User.findAll()
    res.json(users)
})

// SAFE — checks both authentication AND authorization
app.get("/admin/users", authenticate, requireRole("admin"), async (req, res) => {
    const users = await User.findAll()  // ✓
    res.json(users)
})
```

---

## Phase 6 — Password Reset & Account Recovery

```bash
# Find password reset logic
grep -rn "reset.*password\|password.*reset\|forgot.*password\|resetToken\|reset_token" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" .
```

### Password Reset Checklist

- [ ] Reset token: cryptographically random, ≥ 128 bits
- [ ] Reset token: single-use (invalidated after first use)
- [ ] Reset token: short expiry (≤ 1 hour)
- [ ] Reset token: stored as hash, not plaintext
- [ ] Reset link: sent only to verified email address
- [ ] Reset token: invalidated on password change
- [ ] Reset token: invalidated on login
- [ ] No user enumeration: same response for known/unknown email

```javascript
// VULNERABLE password reset patterns
// ✗ Predictable token
const token = user.id + Date.now()

// ✗ Token has no expiration check
await PasswordReset.create({ token, userId })  // no expiry field

// ✗ Non-atomic consumption or missing used check (race condition / token reuse)
const record = await PasswordReset.findOne({ where: { token } }) // missing check for record.used === false
// ... resets password without atomic consumption ...
await PasswordReset.update({ used: true }, { where: { token } }) // non-atomic check-then-set race condition

// SAFE: Atomic one-time consumption with hashed storage
const token = crypto.randomBytes(32).toString("hex")
const expiry = new Date(Date.now() + 3600000)  // 1 hour ✓
await PasswordReset.create({ tokenHash: hash(token), userId, expiresAt: expiry, used: false })

// Atomically consume token — reject if already used, expired, or non-existent
const [affected] = await PasswordReset.update(
  { used: true },
  { where: { tokenHash: hash(token), used: false, expiresAt: { [Op.gt]: new Date() } } }
)
if (!affected) throw new Error("Invalid, expired, or already consumed token")
```

---

## Phase 7 — Multi-Factor Authentication

```bash
# Check if MFA is implemented
grep -rn "totp\|otp\|two.factor\|2fa\|mfa\|authenticator\|speakeasy\|pyotp" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" . -i
```

### MFA Checklist

- [ ] MFA available for all users (not just admins)
- [ ] MFA enforced for admin/privileged accounts
- [ ] TOTP implementation uses RFC 6238 (30-second window, max ±1 window)
- [ ] Backup codes: one-time use, hashed storage, user-downloadable
- [ ] MFA not bypassed via account recovery (email reset should also require MFA consideration)
- [ ] Rate limiting on MFA code attempts (prevent brute force of 6-digit TOTP)

---

## Output Format

````markdown
## [SEVERITY] AUTH-[NNN]: [Vulnerability Title]

**Category:** Password | Session | JWT | OAuth | Authorization | MFA | Account Recovery
**CWE:** CWE-XXX
**OWASP:** A07 / A01 / A04 (identification, access control, insecure design)

### Location
- **File:** `path/to/auth.js:LINE`
- **Route/Function:** `POST /login` / `verifyToken()`

### Finding
[Clear description of what is wrong and why it's a vulnerability]

### Attack Scenario
[How an attacker would exploit this — step by step]

### Remediation
```[lang]
[corrected code]
```

### References
- CWE-XXX: https://cwe.mitre.org/data/definitions/XXX.html
````

---

## Rules of Engagement

1. **Trace complete auth flows** — check registration, login, reset, and logout.
2. **Authorization ≠ authentication** — verify BOTH are checked on every protected resource.
3. **Check every endpoint** — admin endpoints often lack role checks.
4. **IDOR needs ID analysis** — enumerate numeric IDs in routes and verify ownership checks.
5. **JWT claims must be verified** — signature + expiry + audience + issuer.
6. **Secrets must be rotatable** — flag any auth configuration that can't be changed without downtime.
