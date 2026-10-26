---
name: race-condition-detector
description: >
  Concurrency vulnerabilities and race condition detection skill. Analyzes codebases
  for Time-of-Check to Time-of-Use (TOCTOU) flaws, unsafe shared state, data races,
  double-fetch bugs, database lost updates, distributed locking pitfalls, and
  business logic race conditions (such as double-spending, coupon reuse, and
  concurrent rate-limit bypasses). Activate when the user asks to "check race conditions",
  "find TOCTOU", "audit concurrency", "thread safety review", "data race detection",
  "concurrency bugs", "double spending vulnerability", or "mutex locking review".
triggers:
  - "race condition"
  - "TOCTOU"
  - "concurrency"
  - "thread safety"
  - "data race"
  - "unsafe shared state"
  - "double fetch"
  - "double spending"
  - "concurrency vulnerability"
  - "check locking"
  - "distributed lock"
  - "deadlock"
  - "lost update"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
tags: "[concurrency, race-condition, toctou, thread-safety, locking, double-fetch, distributed-systems]"
date_added: "2026-10-21"
---

# Race Condition Detector — Concurrency & TOCTOU Vulnerability Analysis

> Concurrency flaws occur when system behavior depends on the timing, interleaving,
> or ordering of uncontrollable execution events. Attackers deliberately exploit
> these microsecond timing windows to bypass authentication, duplicate funds,
> elevate privileges, or corrupt shared memory.

> This skill covers static code inspection, dynamic testing strategies, and pattern
> verification across multi-threaded applications, async runtimes, distributed services,
> and transactional databases.

---

## Concurrency Vulnerability Taxonomy

```
Race Condition Attack Surface
├── File System & OS
│   ├── TOCTOU (access() followed by open())
│   ├── Symlink races in temporary directories
│   └── Double-fetch in shared kernel/user memory
├── Application Memory & Runtime
│   ├── Non-atomic read-modify-write on shared variables
│   ├── Interleaving in async/event-loop runtimes (Node.js, asyncio)
│   ├── Unsafe concurrent collection mutation
│   └── Broken double-checked locking
├── Database & Transactions
│   ├── Read-Modify-Write without locking (Lost Updates)
│   ├── Insufficient transaction isolation levels
│   └── Distributed lock anti-patterns (Redis TTL expiry during execution)
└── Business Logic & Financials
    ├── Concurrent withdrawal / Double-spending
    ├── One-time voucher / coupon reuse
    ├── Limit & quota circumvention (rate limiting bypass)
    └── Inventory overselling
```

---

## Phase 1 — Time-of-Check to Time-of-Use (TOCTOU) Analysis

TOCTOU occurs when a program checks a precondition (e.g., file existence, permission,
balance) and then performs an action based on that check, while an external process
alters the state in the intervening window.

### 1.1 File System TOCTOU Patterns

Look for separate system calls between checking file attributes and opening/modifying it:

```c
// VULNERABLE (C / C++): Check then open creates a race window
if (access("/tmp/user_data.txt", W_OK) == 0) {
    // Attacker swaps /tmp/user_data.txt with symlink to /etc/passwd here!
    FILE *f = fopen("/tmp/user_data.txt", "w");
    fputs(user_input, f);
    fclose(f);
}

// SAFE: Open with atomic flags, then operate exclusively on file descriptor
int fd = open("/tmp/user_data.txt", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
if (fd < 0) {
    // Handle error safely
}
FILE *f = fdopen(fd, "w");
```

**Common language anti-patterns:**

| Language | Vulnerable Pattern | Secure Replacement |
|---|---|---|
| **Python** | `if os.path.exists(path): open(path)` | `open(path, 'x')` or handle `FileExistsError` |
| **Node.js** | `fs.access(path, () => fs.writeFile(path))` | `fs.open(path, 'wx', (err, fd) => ...)` |
| **Java** | `if (file.exists()) { file.createNewFile(); }` | `Files.newByteChannel(path, CREATE_NEW, WRITE)` |
| **Go** | `if _, err := os.Stat(p); os.IsNotExist(err) { os.Create(p) }` | `os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)` |

### 1.2 Permission & Authorization TOCTOU

Check for authorization checks evaluated early in a request lifecycle that become invalid
when concurrent requests alter roles, revoke sessions, or change resource ownership:

```
□ Is permission verification decoupled from the final database commit?
□ Can an account revocation be raced by in-flight API requests?
□ Does payment verification happen in an isolated step prior to order placement?
```

---

## Phase 2 — Memory & Application State Concurrency

Races occurring directly within shared application memory in multi-threaded or
asynchronous runtimes.

### 2.1 Non-Atomic Read-Modify-Write (RMW)

Detect state mutations that appear atomic in high-level code but translate to multiple
CPU instructions or async execution steps:

```go
// VULNERABLE (Go): Data race on shared global counter
var requestCount int

func handleRequest() {
    // requestCount++ is READ -> MODIFY -> WRITE, not atomic!
    requestCount++ 
}

// SAFE: Using atomic primitives or sync.Mutex
var requestCount int64

func handleRequest() {
    atomic.AddInt64(&requestCount, 1)
}
```

### 2.2 Async Event-Loop Interleaving (Node.js / Python asyncio)

Even single-threaded runtimes suffer from race conditions when async boundaries
(`await`, promises, callbacks) allow other tasks to execute between check and mutation:

```javascript
// VULNERABLE (Node.js): async check-then-act
async function withdrawBalance(userId, amount) {
    const user = await db.getUser(userId); // State check
    if (user.balance >= amount) {
        // CONCURRENCY WINDOW: Another request can arrive here before deduction!
        await externalPaymentGateway.charge(userId, amount);
        await db.updateBalance(userId, user.balance - amount); // State mutation
    }
}
```

```python
# VULNERABLE (Python asyncio): Shared mutable state across coroutines
class RateLimiter:
    def __init__(self):
        self.hits = {}

    async def is_allowed(self, client_id):
        current = self.hits.get(client_id, 0)
        if current >= 10:
            return False
        # Context switch can yield control during network or file I/O
        await asyncio.sleep(0.01)
        self.hits[client_id] = current + 1
        return True
```

### 2.3 Broken Synchronization & Lazy Initialization

Check for broken synchronization patterns like double-checked locking without memory barriers:

```java
// VULNERABLE (Java): Double-checked locking without volatile keyword
public class Singleton {
    private static Singleton instance; // Missing 'volatile'

    public static Singleton getInstance() {
        if (instance == null) {
            synchronized (Singleton.class) {
                if (instance == null) {
                    instance = new Singleton(); // Reordering can expose half-initialized object
                }
            }
        }
        return instance;
    }
}
```

---

## Phase 3 — Database & Transaction Concurrency

Databases handle concurrency via transactions, but default isolation levels
(often `READ COMMITTED`) do not protect against lost updates or race conditions.

### 3.1 Lost Updates (Read-Modify-Write in SQL)

```sql
-- VULNERABLE: Two concurrent sessions execute:
-- Session A:
SELECT balance FROM accounts WHERE user_id = 42; -- returns 100
-- Session B:
SELECT balance FROM accounts WHERE user_id = 42; -- returns 100
-- Session A:
UPDATE accounts SET balance = 100 - 50 WHERE user_id = 42;
-- Session B:
UPDATE accounts SET balance = 100 - 50 WHERE user_id = 42;
-- Result: User withdrew 100, balance reflects only 50 deducted!
```

### 3.2 Remediation Patterns for Database Concurrency

#### Pattern A: Atomic SQL Updates
```sql
-- SAFE: Atomic decrement with integrity constraint
UPDATE accounts 
SET balance = balance - 50 
WHERE user_id = 42 AND balance >= 50;

-- Inspect rows affected: if 0, insufficient funds or concurrent rejection
```

#### Pattern B: Pessimistic Locking (`FOR UPDATE`)
```sql
BEGIN TRANSACTION;
-- Locks the row until commit/rollback
SELECT balance FROM accounts WHERE user_id = 42 FOR UPDATE;

UPDATE accounts SET balance = balance - 50 WHERE user_id = 42;
COMMIT;
```

#### Pattern C: Optimistic Concurrency Control (OCC)
```sql
-- Include version column
SELECT balance, version FROM accounts WHERE user_id = 42; -- version = 5

UPDATE accounts 
SET balance = 50, version = version + 1 
WHERE user_id = 42 AND version = 5;

-- If rows affected == 0, abort and retry
```

### 3.3 Distributed Lock Pitfalls (Redis Redlock, etc.)

Check distributed locking mechanisms for common failure points:

```
□ Lock TTL too short: Lock expires while business logic is still running, allowing concurrent runner
□ Unsafe unlock: Client releases lock without verifying it still owns the token (unlinking competitor's lock)
□ Non-atomic lock acquisition: SETNX followed by EXPIRE (must use single atomic SET key val NX PX ms)
□ Missing fencing tokens: Downstream storage accepts writes from stale lock holders
```

```lua
-- SAFE: Atomic unlock in Redis using Lua script
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
```

---

## Phase 4 — Business Logic Race Conditions

Business-level race conditions are often the most lucrative for attackers and invisible
to traditional vulnerability scanners.

### 4.1 Financial Operations & Balance Depletion
- Concurrent withdrawal requests sent simultaneously (Double-Spending).
- Transferring money between two user accounts in parallel to inflate balances.
- Converting currencies back and forth across simultaneous requests to exploit rate rounding.

### 4.2 One-Time Vouchers, Coupons & Promo Codes
- Applying the same single-use promo code across 20 simultaneous threads.
- Gift card redemption raced from multiple IPs simultaneously.

### 4.3 Rate Limit & Quota Bypasses
- Sending bursts of 50 concurrent login attempts within the same 5ms window before the rate limiter records the hits.
- Exceeding trial tier storage or compute quotas by triggering parallel creations.

### 4.4 Idempotency Check Review
Verify how backend endpoints handle repeated requests:

```
□ Are critical mutation endpoints protected by unique Idempotency-Key headers?
□ Is the idempotency key checked and reserved atomically (e.g. database unique constraint or atomic Redis SETNX)?
□ If an idempotent request is in-flight, do concurrent duplicate requests wait or safely reject with 409 Conflict?
```

---

## Phase 5 — Double-Fetch & Kernel/Hardware Races

Double-fetch vulnerabilities occur when privileged code (kernel, hypervisor, or driver)
reads a value from shared/user-space memory once for validation, and reads it a second time
for execution, giving an unprivileged thread a window to change it.

```c
// VULNERABLE: Privileged buffer size check followed by allocation
// Thread 1 (Privileged):
size_t len = user_struct->length; // Read 1: Validation
if (len > MAX_ALLOWED) return -EINVAL;

// Attacker Thread 2 modifies user_struct->length right here in shared memory!

void *kbuf = kmalloc(user_struct->length); // Read 2: Execution with poisoned size
copy_from_user(kbuf, user_struct->data, user_struct->length);
```

**Defensive Rule:** Copy untrusted shared data to local stack/private memory *once* before
validating, and use that private copy for all subsequent processing.

---

## Phase 6 — Dynamic Testing & Tooling

### 6.1 Language Built-in Race Detectors

```bash
# Go Data Race Detector
go test -race ./...
go run -race main.go

# C / C++ ThreadSanitizer (TSan)
clang -fsanitize=thread -g -O1 main.c -o main

# Rust TSAN
RUSTFLAGS="-Zsanitizer=thread" cargo test --target x86_64-unknown-linux-gnu

# Python Thread Concurrency Checks (Gil-disabled or multithreading)
pytest -n auto
```

### 6.2 HTTP / API Concurrency Testing

To prove a race condition in web APIs, construct concurrent multi-connection bursts:

```bash
# Testing with Turbo Intruder (Burp Suite Extension)
# Uses HTTP pipelining or HTTP/2 single-packet attack to align arrival within microseconds

# Testing with curl parallel requests
for i in {1..20}; do
  curl -s -X POST https://target.local/api/redeem-coupon \
       -H "Authorization: Bearer $TOKEN" \
       -H "Content-Type: application/json" \
       -d '{"code": "ONE_TIME_USE"}' &
done; wait
```

---

## Phase 7 — Findings & Severity Guide

### Severity Classification

| Severity | Description | Examples |
|---|---|---|
| **Critical** | Direct financial duplication, balance double-spend, authentication bypass, or kernel privilege escalation | Multi-withdrawal race yielding double cash, promo code infinite duplication, kernel TOCTOU RCE |
| **High** | Resource exhaustion, quota bypass, or unauthorized state alteration | Complete rate limit evasion, single-use token multi-consumption, file upload race to execute webshell |
| **Medium** | Unsafe shared memory mutation with inconsistent state or crash potential | Missing mutex on in-memory counters, lost database updates on non-financial counters |
| **Low** | Theoretical timing window with no demonstrable impact or low likelihood | Log interleaving, minor metrics discrepancy |

### Finding Format

```
### [Severity] Concurrency Race Condition: <Title>
- Location: <file:line> or <Endpoint + Method>
- Flaw Type: TOCTOU | Lost Update | Shared State Interleaving | Double-Fetch | Business Logic
- Vulnerable Window: Microsecond window between <Check Operation> and <Action Operation>
- Exploit Scenario: How an attacker orchestrates parallel requests to trigger the state desync
- Evidence / Code Snippet:
    ```<language>
    // Highlight check vs use or non-atomic shared mutation
    ```
- Remediation:
    - Code fix (Atomic primitive, lock, transaction isolation, SELECT FOR UPDATE)
    - Before & After code example
- Confidence: Confirmed | Likely | Requires Stress Testing
```
