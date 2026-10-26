# business-logic-audit

> Business logic vulnerability auditing and transaction security skill for the **bug-finder-kit**.
> Identifies flaws in application business rules, state machines, and transactional workflows
> that cannot be discovered by generic signature scanners (OWASP A04: Insecure Design).

---

## What This Skill Covers

| Attack Vector | Audit Focus |
|---|---|
| **Price Tampering** | Client-supplied unit prices, discounts, or subtotals in request payloads |
| **Quantity Abuse** | Negative quantities, zero-item bypasses, and 32-bit integer overflow |
| **Workflow Bypasses** | Skipping checkout steps (e.g. going from cart directly to fulfillment) |
| **Coupon & Incentive Stacking** | Single-use coupon replay, invalid promo stacking, referral loops |
| **Currency & Rounding Flaws** | IEEE 754 floating-point errors, sub-cent rounding arbitrage |
| **Double-Spending Races** | Concurrent balance deductions, TOCTOU vulnerabilities on gift cards |
| **Parameter Tampering** | Hidden field manipulation for plan tiers, roles, or quota elevation |
| **Idempotency Defenses** | Idempotency keys for non-repeatable financial transactions |

---

## Scope Boundary

| Skill | What It Covers |
|---|---|
| `race-condition-detector` | General multi-threading, concurrency locks, file/process race conditions |
| `api-security-review` | Technical API vulnerabilities: authentication, CORS, rate limiting, SQLi |
| **`business-logic-audit`** | Application-specific business rules: pricing integrity, state machines, coupon rules, quantity limits, and transactional invariants |

---

## Trigger Phrases

Activate this skill by asking:
- `"business logic audit"`, `"business logic vulnerabilities"`
- `"price manipulation"`, `"coupon stacking bug"`
- `"workflow bypass audit"`, `"quantity abuse check"`
- `"transaction race condition"`, `"e-commerce security review"`
- `"double spending audit"`, `"cart tampering"`

---

## Directory Structure

```
skills/business-logic-audit/
├── SKILL.md              — Core audit guide (Phases 1–10, logic flaw taxonomy, patterns)
├── README.md             — Overview, scope boundary, and triggers
└── references/
    └── detailed-guide.md — E-commerce state machine design, idempotency key implementation,
                            and financial transaction testing recipes
```
