---
name: api-security-review
description: >
  REST and GraphQL API security review skill. Analyzes API endpoints for broken
  authentication, missing authorization, rate limiting gaps, input validation
  weaknesses, mass assignment, sensitive data exposure, insecure CORS, SSRF,
  and API-specific OWASP Top 10 issues. Activate when the user asks to "review API
  security", "API security audit", "GraphQL security", "REST security", "check API
  vulnerabilities", "API rate limiting", or "CORS review".
triggers:
  - "review API security"
  - "API security audit"
  - "GraphQL security"
  - "REST security"
  - "check API vulnerabilities"
  - "API rate limiting"
  - "CORS review"
  - "API OWASP"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
---

# API Security Review — REST & GraphQL Security Analysis

> Comprehensive security review of API layers following OWASP API Security Top 10.
> Covers authentication, authorization, rate limiting, input validation, CORS,
> data exposure, and API-specific attack vectors.

---

## OWASP API Security Top 10 Coverage

| ID | Category | Check |
|---|---|---|
| API1 | Broken Object Level Authorization | IDOR checks |
| API2 | Broken Authentication | Token/session review |
| API3 | Broken Object Property Level Authorization | Mass assignment, over-fetching |
| API4 | Unrestricted Resource Consumption | Rate limiting, pagination |
| API5 | Broken Function Level Authorization | Admin endpoint access |
| API6 | Unrestricted Access to Sensitive Business Flows | Business logic abuse |
| API7 | Server Side Request Forgery | SSRF via URL params |
| API8 | Security Misconfiguration | CORS, headers, debug |
| API9 | Improper Inventory Management | Shadow/zombie APIs |
| API10 | Unsafe Consumption of APIs | Third-party API trust |

---

## Phase 1 — API Inventory

Map all API endpoints before reviewing security:

```bash
# Express/Node.js — find all routes
grep -rn "app\.\(get\|post\|put\|patch\|delete\|all\)\|router\.\(get\|post\|put\|patch\|delete\)" \
    --include="*.js" --include="*.ts" . | grep -v "node_modules"

# Django — list URLs
grep -rn "path(\|re_path(\|url(" --include="*.py" . | grep -v "node_modules\|#"

# Flask
grep -rn "@app\.route\|@blueprint\.route" --include="*.py" .

# Spring Boot
grep -rn "@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping\|@RequestMapping" \
    --include="*.java" .

# FastAPI
grep -rn "@app\.\(get\|post\|put\|patch\|delete\)\|@router\." --include="*.py" .
```

Build an endpoint inventory:
| Method | Path | Auth Required | Authorization | Rate Limited |
|---|---|---|---|---|

---

## Phase 2 — API1: Broken Object Level Authorization (IDOR)

Every endpoint that returns or modifies a resource by ID must verify ownership.

```bash
# Find ID-based endpoints
grep -rn "/:id\|/{id}\|/\w\+/\w\+Id\|params\[\"id\"\]\|path_variable.*id" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.java" --include="*.rb" --include="*.go" . | grep -v "node_modules"
```

**Pattern to check for each resource endpoint:**

```javascript
// VULNERABLE — API1 IDOR
// GET /api/invoices/:id — no ownership check
app.get("/api/invoices/:id", authenticate, async (req, res) => {
    const invoice = await Invoice.findById(req.params.id)  // ✗ any auth'd user
    res.json(invoice)
})

// SAFE — ownership verified
app.get("/api/invoices/:id", authenticate, async (req, res) => {
    const invoice = await Invoice.findOne({
        _id: req.params.id,
        userId: req.user.id    // ✓ must belong to requesting user
    })
    if (!invoice) return res.status(404).json({ error: "Not found" })
    res.json(invoice)
})
```

---

## Phase 3 — API2: Broken Authentication

```bash
# Find authentication middleware
grep -rn "authenticate\|verifyToken\|passport\.authenticate\|requireAuth\|@login_required\|@authenticate" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.java" --include="*.rb" .

# Find endpoints WITHOUT authentication middleware
grep -rn "app\.get\|app\.post\|app\.put\|app\.delete" \
    --include="*.js" --include="*.ts" . | \
    grep -v "authenticate\|auth\|middleware"
```

### Authentication Checklist

- [ ] All non-public endpoints require authentication
- [ ] Authentication is checked in middleware, not per-route ad-hoc
- [ ] Tokens are validated on every request (signature + expiry + revocation)
- [ ] API keys: sufficient entropy (≥ 256 bits), stored hashed server-side
- [ ] No authentication credentials in URLs (query params, path params)
- [ ] No sensitive tokens in logs

```javascript
// VULNERABLE — credentials in URL
GET /api/data?api_key=sk_live_abc123  // ✗ key in URL, logged by servers/proxies

// SAFE — credentials in Authorization header
GET /api/data
Authorization: Bearer sk_live_abc123   // ✓ not logged by default
```

---

## Phase 4 — API3: Broken Object Property Level Authorization

### Mass Assignment
```bash
# Find where request body is directly used to create/update records
grep -rn "\.create\s*(\s*req\.body\|\.update\s*(\s*req\.body\|\.save\s*(\s*req\.body" \
    --include="*.js" --include="*.ts" --include="*.py" .
grep -rn "Object\.assign.*req\.body\|spread.*req\.body\|{\s*\.\.\.req\.body" \
    --include="*.js" --include="*.ts" .
```

```javascript
// VULNERABLE — mass assignment API3
app.put("/api/users/:id", authenticate, async (req, res) => {
    await User.findByIdAndUpdate(req.params.id, req.body)  // ✗ all fields writable
    // Attacker sends: { "role": "admin", "email": "hacker@evil.com" }
})

// SAFE — explicit allowed fields
const ALLOWED_UPDATE_FIELDS = ["name", "bio", "avatar"]
app.put("/api/users/:id", authenticate, async (req, res) => {
    const updates = {}
    ALLOWED_UPDATE_FIELDS.forEach(field => {
        if (req.body[field] !== undefined) updates[field] = req.body[field]
    })
    await User.findByIdAndUpdate(req.params.id, updates)  // ✓
})
```

### Excessive Data Exposure
```bash
# Find all API responses — check for sensitive field exposure
grep -rn "res\.json\|return.*json()\|serialize\|to_dict\|as_json" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.rb" . | head -30
```

```javascript
// VULNERABLE — exposes all fields including sensitive ones
app.get("/api/users/:id", async (req, res) => {
    const user = await User.findById(req.params.id)
    res.json(user)  // ✗ includes passwordHash, resetToken, role, internal IDs
})

// SAFE — explicit projection
app.get("/api/users/:id", async (req, res) => {
    const user = await User.findById(req.params.id).select("name email avatar createdAt")
    res.json(user)  // ✓ only public fields
})
```

---

## Phase 5 — API4: Unrestricted Resource Consumption

### Rate Limiting Audit

```bash
# Find rate limiting middleware
grep -rn "rateLimit\|rate-limit\|throttle\|RateLimiter\|slowDown\|express-rate-limit" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" .

# Find potentially missing rate limiting on sensitive endpoints
grep -rn "app\.post.*login\|app\.post.*register\|app\.post.*password\|app\.post.*forgot\|app\.post.*reset" \
    --include="*.js" --include="*.ts" .
```

**Rate limiting checklist:**
- [ ] Login endpoint: ≤ 5 attempts per minute per IP
- [ ] Registration endpoint: ≤ 3 per minute per IP
- [ ] Password reset: ≤ 3 per hour per email/IP
- [ ] MFA code entry: ≤ 5 attempts before lockout
- [ ] API global rate limit: appropriate for use case
- [ ] Rate limit headers returned: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`

```javascript
// Express rate limiting setup — check configuration
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 5,                      // ✓ 5 per window
    message: "Too many login attempts, please try again later"
})

// Flag: global rate limit is too high or missing
const apiLimiter = rateLimit({ windowMs: 60000, max: 10000 })  // ✗ too permissive
```

### Pagination Limits

```bash
grep -rn "limit\|pageSize\|page_size\|per_page" \
    --include="*.js" --include="*.ts" --include="*.py" . | \
    grep -v "node_modules\|#" | head -20
```

```javascript
// VULNERABLE — no max limit on pagination
app.get("/api/items", async (req, res) => {
    const limit = req.query.limit || 100
    const items = await Item.find().limit(limit)  // ✗ user can request limit=99999
})

// SAFE — cap the limit
const MAX_LIMIT = 100
const limit = Math.min(parseInt(req.query.limit) || 20, MAX_LIMIT)  // ✓
```

---

## Phase 6 — API5: Broken Function Level Authorization

```bash
# Find admin/elevated operations
grep -rn "admin\|delete.*all\|bulk.*delete\|truncate\|drop.*table\|export.*all\|create.*user\|change.*role" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.java" --include="*.rb" . -i | grep "route\|endpoint\|app\.\|@"
```

```javascript
// VULNERABLE — endpoint only checks auth, not admin role
app.delete("/api/admin/users/:id", authenticate, async (req, res) => {
    await User.findByIdAndDelete(req.params.id)  // ✗ any authenticated user can delete
})

// SAFE
app.delete("/api/admin/users/:id", authenticate, requireRole("admin"), async (req, res) => {
    await User.findByIdAndDelete(req.params.id)  // ✓
})
```

---

## Phase 7 — API7: SSRF via API

```bash
# Find endpoints that accept URLs
grep -rn "req\.body\.url\|req\.query\.url\|params\['url'\]\|request\.url\|webhook.*url\|fetch_url\|proxy" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" . -i
```

```javascript
// VULNERABLE — SSRF
app.post("/api/webhook/test", authenticate, async (req, res) => {
    const { url } = req.body
    const response = await fetch(url)  // ✗ attacker can send: http://169.254.169.254/metadata
    res.json({ status: response.status })
})

// SAFE — validate URL against allowlist
const ALLOWED_DOMAINS = ["api.stripe.com", "hooks.slack.com"]
app.post("/api/webhook/test", authenticate, async (req, res) => {
    const parsedUrl = new URL(req.body.url)
    if (!ALLOWED_DOMAINS.includes(parsedUrl.hostname)) {
        return res.status(400).json({ error: "Domain not allowed" })
    }
    const response = await fetch(req.body.url)  // ✓
    res.json({ status: response.status })
})
```

---

## Phase 8 — API8: Security Misconfiguration

### CORS Audit

```bash
# Find CORS configuration
grep -rn "cors(\|Access-Control-Allow-Origin\|CORS_ORIGIN\|CorsConfiguration" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" .
```

```javascript
// MISCONFIGURATION: Wildcard CORS with credentials
// Note: Standard browsers will disallow reading the response when Access-Control-Allow-Origin: * is paired with credentials: true.
// However, state-changing simple requests (CSRF) or non-browser/proxy setups may still be affected.
app.use(cors({
    origin: "*",          // Misconfiguration: browser blocks credentialed response reading, but indicates flawed CORS posture
    credentials: true
}))

// CRITICAL / HIGH — Dynamically reflecting untrusted Origin with credentials (unrestricted cross-origin data exposure)
app.use((req, res, next) => {
    // ✗ Insecure origin reflection: allows any attacker website to make credentialed requests and read responses!
    res.header("Access-Control-Allow-Origin", req.headers.origin)
    res.header("Access-Control-Allow-Credentials", "true")
    next()
})

// SAFE — Explicit trusted origin allowlist
const ALLOWED_ORIGINS = ["https://app.example.com", "https://admin.example.com"]
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) callback(null, true)
        else callback(new Error("Not allowed by CORS"))
    },
    credentials: true  // ✓ only for explicitly allowlisted origins
}))
```

### Security Headers Audit

```bash
# Check for security headers middleware
grep -rn "helmet\|X-Frame-Options\|X-Content-Type\|Content-Security-Policy\|HSTS" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" .
```

**API Security Headers (Scoped by Response Type & Client Architecture):**

| Header | Recommended Directive | Scope & Applicability |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | **All APIs**: Prevents browsers from MIME-sniffing non-executable content (JSON/text) as scripts. |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | **All HTTPS APIs**: Enforces encrypted transport and protects against TLS downgrade attacks. |
| `Cache-Control` | `no-store, max-age=0` | **Authenticated / Sensitive endpoints**: Prevents proxies, caches, and browsers from persisting sensitive tokens or PII on disk. |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | **Browser-consumed APIs**: Primary defense if an API returns HTML, SVG, or JSON error pages directly rendered by browsers. Less critical for server-to-server APIs. |
| `X-Frame-Options` | `DENY` | **Browser-rendered endpoints**: Defends against framing/clickjacking. Not relevant for pure machine-to-machine JSON APIs. |

---

## Phase 9 — GraphQL-Specific Security

```bash
# Detect GraphQL usage
grep -rn "graphql\|Apollo\|type-graphql\|strawberry\|ariadne\|nexus\|pothos" \
    --include="*.js" --include="*.ts" --include="*.py" . | grep -v "node_modules"
```

### GraphQL Checklist

**Introspection in production:**
```javascript
// VULNERABLE — introspection enabled in production
const server = new ApolloServer({
    schema,
    introspection: true  // ✗ expose full schema to attackers
})

// SAFE — disable in production
const server = new ApolloServer({
    schema,
    introspection: process.env.NODE_ENV !== "production"  // ✓
})
```

**Query depth limiting:**
```javascript
// VULNERABLE — no depth limit (allows nested DoS queries)
// Attacker: { user { friends { friends { friends { friends { ... } } } } } }

// SAFE — use graphql-depth-limit
const server = new ApolloServer({
    validationRules: [depthLimit(5)]  // ✓ max 5 levels deep
})
```

**Query complexity limiting:**
```javascript
// SAFE — limit query cost
import { createComplexityLimitRule } from "graphql-validation-complexity"
const server = new ApolloServer({
    validationRules: [createComplexityLimitRule(1000)]  // ✓
})
```

**Field-level authorization:**
```javascript
// VULNERABLE — resolver doesn't check authorization
const resolvers = {
    User: {
        email: (user) => user.email,  // ✗ accessible to any authenticated user
        role: (user) => user.role,    // ✗ exposes role to everyone
    }
}

// SAFE — field-level auth
const resolvers = {
    User: {
        email: (user, _, { currentUser }) => {
            if (currentUser.id !== user.id && currentUser.role !== "admin") return null
            return user.email  // ✓
        }
    }
}
```

**Batching limits:**
```javascript
// Detect if batching is enabled and unlimited
// Attacker can batch 1000 requests in one HTTP call
// Safe: limit batch size
app.use("/graphql", (req, res, next) => {
    if (Array.isArray(req.body) && req.body.length > 10) {
        return res.status(400).json({ error: "Batch too large" })
    }
    next()
})
```

---

## Output Format

````markdown
## [SEVERITY] API-[NNN]: [Vulnerability Title]

**OWASP API:** API[N] — [Category]
**CWE:** CWE-XXX
**Endpoint:** `METHOD /api/path/:id`
**Authentication Required:** Yes / No
**Authorization Checked:** Yes / No

### Vulnerable Code
```[lang]
[exact vulnerable code]
```

### Attack Scenario
1. Attacker makes: `[HTTP method] /api/path/VICTIM_ID`
2. [What the attacker can achieve]
3. [Data/actions accessible]

### Remediation
```[lang]
[safe code with authorization check]
```

### Additional Controls
- Rate limit this endpoint: [recommendation]
- Response filtering: [fields to exclude]
````

---

## Rules of Engagement

1. **Map all endpoints first** — you cannot secure what you haven't inventoried.
2. **IDOR requires manual trace** — check every ID-based endpoint for ownership verification.
3. **Evaluate CORS risk by verified impact** — dynamic reflection of untrusted origins with credentials enables unauthorized cross-origin data exposure; wildcard origin with credentials triggers browser fetch rejections and represents serious configuration error.
4. **Rate limiting gaps on auth = high** — brute force is always a risk without rate limits.
5. **GraphQL schema exposure** — always check introspection in production.
6. **Mass assignment needs object mapping** — check every `create()` and `update()` call.
