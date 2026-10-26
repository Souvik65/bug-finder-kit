---
name: error-handling-audit
description: >
  Error handling and logging security audit skill. Detects stack trace leaks, verbose
  error responses exposing internal file paths and database schemas, sensitive data
  logging (PII, credentials, bearer tokens), swallowed exceptions causing fail-open
  security bypasses, log injection (CRLF/log forging), and unhandled exceptions leading
  to Denial of Service. Activate when the user asks to "audit error handling", "check for
  stack trace leaks", "review logging security", "log injection", "sensitive data in logs",
  "exception handling review", or "fail-open vulnerability".
triggers:
  - "error handling"
  - "stack trace"
  - "logging security"
  - "sensitive data in logs"
  - "verbose error"
  - "log injection"
  - "swallowed exception"
  - "fail-open"
  - "exception audit"
  - "unhandled rejection"
  - "log sanitization"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
tags: "[error-handling, logging, information-disclosure, log-injection, fail-open, security]"
date_added: "2026-10-21"
---

# Error Handling & Logging Security Audit — Information Disclosure & Log Hygiene

> Error handling and logging mechanisms frequently undermine application security in
> two opposite directions: by revealing too much information to untrusted clients
> (stack trace leaks, verbose database errors), or by recording too much sensitive
> data internally (credentials, session tokens, PII in plaintext logs).

> Additionally, improper exception handling flows—such as swallowing errors in
> authentication checks or failing to roll back transactions—introduce critical
> **fail-open** vulnerabilities.

---

## Error & Logging Attack Surface

```
Application Runtime / Request Pipeline
  ├── Client-Facing Error Responses (Information Disclosure)
  │     ├── Full stack traces in HTTP 500 responses
  │     ├── Database errors exposing schema and SQL queries
  │     ├── Framework debug modes enabled in production (Django, Laravel, Spring)
  │     └── Inconsistent error messages enabling user enumeration
  ├── Logging Practices (Data Exposure & Integrity)
  │     ├── Plaintext passwords, tokens, API keys in logs
  │     ├── PII, payment info (credit cards), and session cookies logged
  │     └── Log Injection (CRLF characters forging audit log entries)
  └── Exception Handling Logic (Application State & Availability)
        ├── Swallowed exceptions leading to fail-open access control
        ├── Incomplete rollback in catch blocks causing state corruption
        └── Unhandled promise rejections / panics causing process crashes (DoS)
```

---

## Phase 1 — Information Disclosure via Error Responses

Attackers treat detailed error messages as reconnaissance goldmines, extracting
internal file paths, operating system details, third-party library versions, and database schemas.

### 1.1 Stack Trace Leaks

Scan codebase and configurations for default or unhandled error pages:

```bash
# Node.js / Express
grep -rn "err\.stack\|stack:" src/
grep -rn "app\.use((err, req, res, next)" src/

# Python / Django & Flask
grep -rn "DEBUG\s*=\s*True" .
grep -rn "app\.run(.*debug=True" .

# Java / Spring Boot
grep -rn "server\.error\.include-stacktrace" src/main/resources/
grep -rn "@ExceptionHandler" src/

# PHP
grep -rn "display_errors\s*=\s*On" .
grep -rn "APP_DEBUG\s*=\s*true" .

# ASP.NET Core
grep -rn "UseDeveloperExceptionPage" .
```

### 1.2 Vulnerable vs. Secure Error Patterns

```javascript
// VULNERABLE (Node.js/Express): Returning full error object with stack trace to client
app.use((err, req, res, next) => {
    res.status(500).json({
        message: err.message,
        stack: err.stack, // LEAKS INTERNAL SOURCE PATHS & DEPENDENCY VERSIONS!
        query: err.sql    // LEAKS DATABASE SCHEMA & QUERY SYNTAX!
    });
});

// SAFE: Log full error internally with correlation ID; return opaque message to client
app.use((err, req, res, next) => {
    const errorId = crypto.randomUUID();
    logger.error({ errorId, err, url: req.originalUrl, method: req.method });

    res.status(500).json({
        type: "https://api.example.com/errors/internal-error",
        title: "Internal Server Error",
        status: 500,
        detail: "An unexpected error occurred. Please contact support.",
        instance: `/errors/${errorId}` // Client quotes errorId for support lookup
    });
});
```

### 1.3 Database Exception Leakage

Check for raw ORM or database error output sent directly to HTTP callers:
- **PostgreSQL / MySQL errors:** `ERROR: relation "users" does not exist at character 15`
- **MongoDB errors:** `CastError: Cast to ObjectId failed for value "admin"`
- **Hibernate / JPA:** `org.hibernate.exception.ConstraintViolationException: could not execute statement`

**Rule:** Database errors must be intercepted at the data-access layer and mapped to
domain-level exceptions before reaching API responses.

---

## Phase 2 — Sensitive Data in Logs (Log Hygiene)

Log files are replicated, ingested by third-party APM services (Datadog, Splunk, Elastic),
and viewed by multiple engineers. Writing secrets to logs constitutes an immediate credential leak.

### 2.1 Common Sensitive Data Sinks in Code

Look for logging of entire request objects, auth headers, or raw query bodies:

```python
# VULNERABLE (Python/FastAPI): Logging entire raw request body or headers
@app.post("/login")
async def login(credentials: LoginRequest):
    logger.info(f"Login attempt: {credentials.dict()}") # LOGS PLAINTEXT PASSWORD!
    # ...
```

```javascript
// VULNERABLE (Node.js): Logging headers with authorization tokens
logger.info("Incoming request", { headers: req.headers }); // LOGS BEARER TOKENS & COOKIES!
```

### 2.2 Sensitive Data Redaction Patterns

Establish automated masking for sensitive keys across all loggers:

```
Blacklisted Keys to Redact:
├── password, pass, pwd, secret
├── token, access_token, refresh_token, bearer
├── authorization, cookie, set-cookie
├── api_key, apikey, private_key
├── credit_card, card_number, cvv, pan
└── ssn, national_id, dob
```

```typescript
// SAFE: Log sanitization middleware / serializer
function sanitizeLogPayload(data: Record<string, any>): Record<string, any> {
    const SENSITIVE_KEYS = /password|secret|token|authorization|cookie|card/i;
    const sanitized = { ...data };

    for (const key of Object.keys(sanitized)) {
        if (SENSITIVE_KEYS.test(key)) {
            sanitized[key] = "[REDACTED]";
        } else if (typeof sanitized[key] === "object" && sanitized[key] !== null) {
            sanitized[key] = sanitizeLogPayload(sanitized[key]);
        }
    }
    return sanitized;
}
```

---

## Phase 3 — Log Injection & Log Forging

If user input is appended directly to log files without sanitization, attackers can inject
newline characters (`\r\n` or `\n`) to fabricate fake log entries, spoof authentication success,
or hide malicious activity.

### 3.1 Exploitation Example (CRLF in Logs)

```python
# VULNERABLE: Appending unescaped input to single-line log
username = request.form['username']
# Attacker enters: "alice\n[2026-10-21 23:59:59] [AUTH] [INFO] User admin successfully logged in from 10.0.0.1"
logger.info(f"Failed login attempt for user: {username}")
```

Log output displays two separate entries:
```
[2026-10-21 23:59:59] [AUTH] [WARN] Failed login attempt for user: alice
[2026-10-21 23:59:59] [AUTH] [INFO] User admin successfully logged in from 10.0.0.1
```

### 3.2 Remediation: Structured JSON Logging

Always use structured JSON logging instead of plain text string concatenation.
In JSON format, newlines within values are automatically escaped as `\n` characters within strings,
preventing log entry fabrication.

```python
# SAFE: Structured logger formats as JSON
logger.info("Login attempt failed", extra={"username": username})
# Emits: {"time": "...", "msg": "Login attempt failed", "username": "alice\n[AUTH]..."}
```

---

## Phase 4 — Exception Flow & "Fail-Open" Vulnerabilities

A security control must **fail closed** (deny access or abort the transaction)
when an exception occurs. Failing open allows attackers to bypass security checks by
intentionally triggering errors.

### 4.1 Swallowed Exception in Authorization Check

```go
// VULNERABLE: Swallowed error defaults to authorized (Fail-Open)
func checkPermission(userId string, resourceId string) bool {
    allowed, err := rbacService.IsAllowed(userId, resourceId)
    if err != nil {
        // ERROR SWALLOWED! Network failure or malformed ID bypasses check!
        log.Println("RBAC service check failed:", err)
        return true // FAIL-OPEN! Should be false!
    }
    return allowed
}

// SAFE: Fail-Closed on error
func checkPermission(userId string, resourceId string) bool {
    allowed, err := rbacService.IsAllowed(userId, resourceId)
    if err != nil {
        log.Println("RBAC service error (denying access):", err)
        return false // FAIL-CLOSED
    }
    return allowed
}
```

### 4.2 Missing Transaction Rollback in Catch Blocks

```java
// VULNERABLE: Catch block logs error but fails to rollback transaction
public void transferMoney(Long fromId, Long toId, BigDecimal amount) {
    EntityTransaction tx = em.getTransaction();
    tx.begin();
    try {
        accountDao.deduct(fromId, amount);
        externalPaymentService.send(toId, amount); // If this throws...
        accountDao.credit(toId, amount);
        tx.commit();
    } catch (Exception e) {
        logger.error("Transfer failed", e);
        // MISSING tx.rollback()! If session flushes, deduction remains committed without credit!
    }
}
```

### 4.3 Unhandled Promise Rejections & Panic DoS

In asynchronous runtimes (Node.js, Go goroutines), an unhandled exception or unhandled promise
rejection can terminate the entire process or crash worker threads.

```javascript
// VULNERABLE (Node.js): Unhandled promise rejection crashes Node process
app.get('/process-data', (req, res) => {
    // If backgroundWorker throws, unhandled rejection triggers process.exit(1)
    backgroundWorker(req.query.id); 
    res.send("Processing started");
});

// SAFE: Attach catch handlers or wrap in async handler middleware
app.get('/process-data', (req, res, next) => {
    backgroundWorker(req.query.id).catch(err => {
        logger.error({ msg: "Background worker failed", err });
    });
    res.send("Processing started");
});
```

---

## Phase 5 — Framework-Specific Hardening Matrix

| Framework | Risk Area | Hardening Directive |
|---|---|---|
| **Express / Node.js** | Stack traces in default error handler | Set `NODE_ENV=production`; define 4-argument custom error middleware |
| **Django (Python)** | Debug page showing settings & passwords | Ensure `DEBUG = False` in production; customize `handler500` |
| **Spring Boot (Java)** | Whitelabel error page & stacktraces | `server.error.include-stacktrace=never`; `server.error.whitelabel.enabled=false` |
| **ASP.NET Core** | Developer exception page | Remove `app.UseDeveloperExceptionPage()` in non-development environments |
| **Laravel (PHP)** | Whoops! error reporting screen | Set `APP_DEBUG=false` in production `.env` |
| **FastAPI (Python)** | Internal validation error details | Implement custom `@app.exception_handler(Exception)` |

---

## Phase 6 — Audit Checklist & Finding Format

### Error & Logging Audit Checklist

```
[ ] Client-Facing Responses:
    - Stack traces disabled across all environments accessible to users
    - Framework debug mode explicitly disabled in production configuration
    - Database error messages intercepted and sanitized
    - Generic, standard error formats used (RFC 7807 Problem Details)
    - Opaque correlation/tracking IDs provided to clients instead of technical errors

[ ] Logging Hygiene:
    - Passwords, bearer tokens, API keys, cookies redacted before logging
    - Credit cards, PII, SSNs masked or omitted
    - Structured JSON logging enforced to eliminate CRLF log injection
    - Log storage permissions restricted to authorized administrators

[ ] Exception Handling & Resilience:
    - Authorization checks fail closed (deny) upon any error/exception
    - Database transactions explicitly rolled back in all catch/except blocks
    - Global unhandled exception handlers configured to prevent process crashes
```

### Finding Template

```
### [Severity] Error Handling Flaw: <Title>
- Location: <file:line> or <Endpoint / Configuration>
- Category: Information Disclosure | Sensitive Data in Logs | Log Injection | Fail-Open
- Description: <How the error response or logging flaw exposes data or allows bypass>
- Evidence / Code:
    ```<language>
    // Show vulnerable error handler, print statement, or catch block
    ```
- Remediation:
    - Disable debug flags in production config
    - Implement logging redaction mask
    - Enforce fail-closed exception logic with explicit rollback
    - Before & After code snippet
- Confidence: Confirmed | Likely | Environment Dependent
```
