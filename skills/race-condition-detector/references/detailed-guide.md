# Race Condition & Concurrency Defense — Technical Reference

## Deep Dive: The Anatomy of a Concurrency Window

A race condition requires three conditions to be met simultaneously:
1. **Concurrency**: Two or more execution flows operate concurrently or interleaved.
2. **Shared State**: The execution flows access a shared resource (memory variable, database record, file system object).
3. **State Mutation**: At least one execution flow modifies the shared resource without atomic synchronization.

---

## 1. Single-Packet Attack (HTTP/2 Concurrency Exploitation)

In traditional HTTP/1.1 testing, network latency jitter often spreads requests across tens of milliseconds, making race condition exploitation difficult across the Internet.

With HTTP/2, request multiplexing enables the **Single-Packet Attack** (popularized by James Kettle / PortSwigger Research):
- Multiple HTTP request frames are placed into a single TCP packet.
- All requests arrive at the server application stack at the exact same millisecond.
- Server worker threads or event loops process them virtually simultaneously, maximizing the race window hit rate to over 90%.

### Turbo Intruder Script Template (Python)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2 # Uses HTTP/2 single-packet attack
                           )

    # 1. Warm up connection
    for i in range(5):
        engine.queue(target.req, gate='race1')

    # 2. Queue simultaneous requests
    for i in range(25):
        engine.queue(target.req, gate='race1')

    # 3. Release all requests simultaneously
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

---

## 2. Database Isolation Levels & Anomaly Matrix

| Isolation Level | Dirty Read | Non-Repeatable Read | Phantom Read | Lost Update |
|---|---|---|---|---|
| **Read Uncommitted** | ❌ Allowed | ❌ Allowed | ❌ Allowed | ❌ Allowed |
| **Read Committed** (Default in Postgres/Oracle) | ✅ Prevented | ❌ Allowed | ❌ Allowed | ❌ Allowed (App-level RMW) |
| **Repeatable Read** (Default in MySQL InnoDB) | ✅ Prevented | ✅ Prevented | ⚠️ Engine dependent | ⚠️ May throw serialization failure |
| **Serializable** | ✅ Prevented | ✅ Prevented | ✅ Prevented | ✅ Prevented |

### Critical Rule for Web Applications
Even in `READ COMMITTED` or `REPEATABLE READ`, if your application reads a value into language memory (`$user->balance`), calculates a new value in PHP/Node/Python, and writes it back via `UPDATE users SET balance = $newBalance`, you **will** suffer lost updates unless using:
- Strict row locking (`SELECT ... FOR UPDATE`)
- Atomic in-database math (`UPDATE users SET balance = balance - 10`)
- Unique constraints with rollback handlers

---

## 3. Distributed Locking Best Practices (Redis & Etcd)

When coordinating concurrency across horizontal microservices:

### The Redlock Pitfall (Martin Kleppmann Critique)
If a process acquires a lock with a 5-second TTL, encounters a long garbage collection (GC) pause or network latency spike lasting 6 seconds, the lock will expire in Redis. A second worker can then acquire the lock. When Worker 1 resumes, both workers execute critical code concurrently.

### The Fencing Token Solution
Every time a distributed lock is granted, emit a monotonically increasing token (e.g., 101, 102, 103).
Downstream storage (PostgreSQL, filesystem, S3) must reject any transaction holding a token lower than the highest token observed so far.

```sql
-- Downstream table schema
ALTER TABLE orders ADD COLUMN last_lock_token BIGINT DEFAULT 0;

-- Storage write check
UPDATE orders 
SET status = 'PROCESSED', last_lock_token = 102 
WHERE id = 42 AND last_lock_token < 102;
```

---

## 4. File System TOCTOU Hardening

When operating on temporary files or privileged file paths:

### Unsafe File Creation
```python
# Flawed check-then-create
if not os.path.exists("/tmp/worker.pid"):
    with open("/tmp/worker.pid", "w") as f:
        f.write(str(os.getpid()))
```

### Hardened File Creation
```python
import os

# Atomically create or fail if file already exists
# Prevents symlink attacks and race overwrite
try:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open("/tmp/worker.pid", flags, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(str(os.getpid()))
except FileExistsError:
    # Safely handle existing file
    pass
```
