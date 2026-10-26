# race-condition-detector

> Concurrency vulnerability and race condition analysis skill for the **bug-finder-kit**.
> Audits codebases for Time-of-Check to Time-of-Use (TOCTOU) flaws, memory data races,
> async event-loop interleaving, database lost updates, distributed locking failures,
> and business-logic concurrency exploits.

---

## What This Skill Covers

| Vulnerability Area | Attack Vectors & Detection Targets |
|---|---|
| **TOCTOU Flaws** | File system check-then-open, permission check-then-commit, symlink swaps |
| **Application State & Memory** | Non-atomic read-modify-write, missing mutexes, async promise interleaving |
| **Database & Transactions** | Lost updates, dirty reads, missing row locks (`SELECT ... FOR UPDATE`), OCC failures |
| **Business Logic Exploits** | Double-spending, coupon/voucher reuse, quota and rate-limit bypasses |
| **Distributed Systems** | Stale Redis locks, lock TTL expiry during work, missing fencing tokens |
| **Kernel / Hardware** | Double-fetch attacks on shared memory buffers |

---

## Trigger Phrases

This skill activates when users ask:
- `"race condition"`, `"find TOCTOU"`
- `"concurrency audit"`, `"thread safety review"`
- `"data race detection"`, `"unsafe shared state"`
- `"double spending vulnerability"`, `"lost update"`
- `"check locking"`, `"distributed lock security"`

---

## Quick Example Findings

### 1. Database Lost Update (Double Withdrawal)
```sql
-- Vulnerable:
SELECT balance FROM accounts WHERE id = 1; -- 100
UPDATE accounts SET balance = 100 - 50 WHERE id = 1;

-- Remediation:
UPDATE accounts SET balance = balance - 50 WHERE id = 1 AND balance >= 50;
```

### 2. File Creation TOCTOU
```c
// Vulnerable:
if (access(filepath, F_OK) != 0) {
    fd = open(filepath, O_CREAT | O_WRONLY);
}

// Remediation:
fd = open(filepath, O_CREAT | O_EXCL | O_WRONLY, 0600);
```

---

## Directory Structure

```
skills/race-condition-detector/
├── SKILL.md              — Main skill file (Taxonomy, Phases 1–7, Remediation)
├── README.md             — Overview and usage guide
└── references/
    └── detailed-guide.md — In-depth guide (Single-packet attack, isolation matrix, fencing tokens)
```

---

## Author & Version
`bug-finder-kit` — v1.0.0 — 2026-10-21
