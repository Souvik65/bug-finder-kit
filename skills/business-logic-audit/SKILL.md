---
name: business-logic-audit
description: >
  Comprehensive business logic vulnerability auditing skill. Identifies flaws in application
  business rules, state machines, and transactional workflows: client price manipulation,
  negative quantity abuse, multi-step workflow bypasses, coupon and promo stacking, currency
  rounding exploitation, transactional double-spending race conditions, and hidden field
  parameter tampering. Activate when the user asks to "audit business logic", "business logic
  vulnerabilities", "price manipulation check", "coupon stacking bug", "workflow bypass audit",
  "negative quantity abuse", "transaction race condition", or "e-commerce security review".
triggers:
  - "business logic audit"
  - "business logic vulnerabilities"
  - "price manipulation"
  - "coupon stacking"
  - "workflow bypass"
  - "quantity abuse"
  - "transaction race condition"
  - "e-commerce security review"
  - "state machine bypass"
  - "double spending"
  - "negative balance exploit"
  - "cart tampering"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
tags: "[business-logic, price-manipulation, workflow-bypass, coupon-stacking, quantity-abuse, race-condition, transaction-security, e-commerce, owasp-a04]"
date_added: "2026-10-23"
---

# Business Logic Vulnerability Audit & Transaction Security

> Business logic vulnerabilities arise when an application's design or implementation allows
> users to manipulate valid application features to achieve unauthorized outcomes (such as
> purchasing items for free, bypassing payment gateways, stacking mutually exclusive discounts,
> or draining balances via race conditions).
>
> Unlike technical injection flaws (SQLi, XSS), business logic flaws cannot be detected by
> generic vulnerability signatures because the input is often syntactically valid. Auditing
> requires analyzing **state machines, invariants, transactional integrity, and trust boundaries**.

---

## Business Logic Attack Taxonomy (OWASP A04: Insecure Design)

```
Business Logic Attack Surface
  ├── 1. Financial & Pricing Tampering
  │     ├── Client-supplied price/discount parameters in POST requests
  │     ├── Negative quantity abuse (buying -5 items to reduce total order value)
  │     ├── Zero-value or fractional-cent rounding exploitation
  │     └── Currency conversion arbitrage (switching currency mid-checkout)
  ├── 2. Workflow & State Machine Bypasses
  │     ├── Skipping mandatory intermediary steps (Cart ➔ Delivery, skipping Payment)
  │     ├── Replaying completed order steps or reusing completed transaction IDs
  │     └── Manipulating state transitions out of sequence (e.g. Canceled ➔ Shipped)
  ├── 3. Discount & Incentive Exploitation
  │     ├── Coupon stacking (combining single-use coupons across multiple tabs)
  │     ├── Infinite referral loops (self-referral account farms)
  │     └── First-time customer promotion re-use via email sub-addressing (+tags)
  ├── 4. Concurrency & Transactional TOCTOU
  │     ├── Double-spending gift cards / wallet balances via concurrent HTTP requests
  │     ├── Inventory overselling through simultaneous cart checkouts
  │     └── Missing database row locks during balance deduction
  └── 5. Parameter Tampering & Limit Violations
        ├── Tier/Subscription manipulation via request payload (setting tier="enterprise")
        ├── Rate limit & quota circumvention through multi-account clustering
        └── Bypassing maximum transaction limits by splitting into micro-transactions
```

---

## Phase 1: Client-Side Trust Assumptions & Price Tampering

A common business logic flaw occurs when the backend trusts prices, discounts, or subtotals
sent directly in client HTTP request bodies.

### Vulnerable Pattern: Client-Supplied Price

```typescript
// ❌ VULNERABLE: Accepting unit price from client request body
// Attacker sends: { "productId": 101, "quantity": 1, "unitPrice": 0.01 }
app.post('/api/checkout', async (req, res) => {
  const { productId, quantity, unitPrice } = req.body;

  // The server calculates total based on client-provided price!
  const totalAmount = quantity * unitPrice;

  const payment = await paymentGateway.charge({
    amount: totalAmount,
    currency: 'USD'
  });

  await db.orders.create({
    data: { productId, quantity, totalAmount, status: 'PAID' }
  });

  res.json({ success: true });
});
```

### Secure Pattern: Server-Side Single Source of Truth

```typescript
// ✅ SAFE: Server queries trusted database for authoritative product pricing
app.post('/api/checkout', requireAuth, async (req, res) => {
  const { productId, quantity } = req.body;

  // 1. Strict quantity validation (prevent negative/zero/excessive values)
  if (!Number.isInteger(quantity) || quantity <= 0 || quantity > 50) {
    return res.status(400).json({ error: 'Invalid quantity' });
  }

  // 2. Fetch authoritative price from DB
  const product = await db.products.findUnique({ where: { id: productId } });
  if (!product || !product.isAvailable) {
    return res.status(404).json({ error: 'Product unavailable' });
  }

  // 3. Server calculates total using trusted price
  const totalAmount = quantity * product.priceInCents;

  const payment = await paymentGateway.charge({
    amount: totalAmount,
    currency: 'USD'
  });

  await db.orders.create({
    data: { productId, quantity, totalAmount, status: 'PAID', userId: req.user.id }
  });

  res.json({ success: true });
});
```

---

## Phase 2: Integer & Quantity Boundary Abuse

### 1. Negative Quantity Exploitation
If an e-commerce platform allows negative quantities, an attacker can add 1 expensive item ($500)
and -4 cheap items (-$400), paying only $100 while receiving the $500 item.

### 2. Zero Quantity Bypass
Adding an item with `quantity: 0` might bypass minimum cart limits while still triggering delivery
or digital key fulfillment routines.

### Audit Rule:
Every numeric input representing quantities, amounts, credits, or percentages must enforce:
- Positive integers only (`quantity > 0` and `Number.isInteger(quantity)`).
- Realistic upper bounds (e.g. `quantity <= 100`).
- Safe arithmetic to prevent 32-bit integer overflow/underflow.

---

## Phase 3: Multi-Step Workflow & State Machine Bypasses

Many critical flows (checkout, registration, identity verification, onboarding) consist of multiple
sequential steps.

### Example: E-Commerce Checkout Flow
```
[ Step 1: View Cart ] ──► [ Step 2: Shipping Info ] ──► [ Step 3: Payment ] ──► [ Step 4: Order Confirmation ]
```

### The State Machine Bypass Attack:
An attacker completes Step 1 and Step 2, then directly sends a `POST /api/order/confirm` request,
**skipping Step 3 (Payment)** entirely. If the backend fails to verify that a successful payment
event was recorded for the order ID, the order is fulfilled for free.

### Secure State Machine Implementation:

```typescript
// ✅ SAFE: Strict state machine transitions
enum OrderStatus {
  CART = 'CART',
  SHIPPING_SET = 'SHIPPING_SET',
  PAYMENT_PENDING = 'PAYMENT_PENDING',
  PAID = 'PAID',
  FULFILLED = 'FULFILLED',
  CANCELLED = 'CANCELLED'
}

async function transitionOrderStatus(orderId: string, fromStatus: OrderStatus, toStatus: OrderStatus) {
  return await db.$transaction(async (tx) => {
    const order = await tx.orders.findUnique({ where: { id: orderId } });
    if (!order || order.status !== fromStatus) {
      throw new Error(`Illegal state transition from ${order?.status} to ${toStatus}`);
    }

    return await tx.orders.update({
      where: { id: orderId },
      data: { status: toStatus }
    });
  });
}
```

---

## Phase 4: Coupon, Discount & Incentive Abuse

### Common Flaws:
1. **Coupon Replay:** Applying the same single-use coupon multiple times by submitting concurrent requests before the database marks it as used.
2. **Discount Stacking:** Combining multiple percentage discounts until the total reaches 0 or negative.
3. **Cart Threshold Stripping:** Adding an item to qualify for free shipping or a $20 discount, then removing the item after the discount is locked in.

### Audit Checklist:
- [ ] Are coupons validated against the cart total **at the exact moment of final payment capture**?
- [ ] Is there an explicit rule defining which discounts can be stacked?
- [ ] Is discount application guarded by an atomic transaction or database row lock?

```python
# ❌ VULNERABLE: Discount applied to cart but never re-validated at final payment
def finalize_order(cart):
    # If user removed qualifying items in a parallel tab,
    # the discount remains attached!
    total = cart.discounted_total
    charge_customer(total)

# ✅ SAFE: Recalculate all discounts from scratch during final charge
def finalize_order(cart):
    cart.recalculate_totals_and_promotions()
    if cart.final_total < 0:
        raise ValueError("Invalid total")
    charge_customer(cart.final_total)
```

---

## Phase 5: Currency Conversion & Float Inaccuracies

JavaScript and Python IEEE 754 floating-point arithmetic introduces rounding inaccuracies:
```javascript
0.1 + 0.2 = 0.30000000000000004
```

In financial applications:
- Always store monetary amounts as **integers representing the smallest currency unit** (e.g. cents, pence, satoshis). Never store `$19.99` as a float `19.99`; store it as `1999`.
- Rounding rules must be consistent (e.g. Banker's Rounding `HALF_EVEN`).
- Currency conversion must lock exchange rates with an expiration timestamp; never allow users to initiate in USD, switch to JPY, and pay the numerical USD value in JPY.

---

## Phase 6: Financial Race Conditions & Double-Spending

When two identical requests arrive simultaneously, non-atomic database read-then-write logic
enables double-spending of gift cards, loyalty points, or account balances.

```
Request 1 (Thread A)                      Request 2 (Thread B)
       │                                         │
Reads balance ($100)                      Reads balance ($100)
Checks: $100 >= $100 (OK)                 Checks: $100 >= $100 (OK)
Deducts $100 ──► Balance: $0             Deducts $100 ──► Balance: $0
Fulfills Order 1                          Fulfills Order 2
       └────────────── TWO ORDERS FULFILLED FOR $100! ──────────────┘
```

### Remediation: Atomic Database Updates & Row Locking

```sql
-- ✅ SAFE: Atomic deduction with conditional check
UPDATE accounts 
SET balance = balance - 100 
WHERE id = 'user_123' AND balance >= 100;
-- If affected rows == 0, transaction is rejected!
```

In ORMs (e.g. Prisma / TypeORM):
```typescript
// ✅ SAFE: Database transaction with pessimistic lock (SELECT ... FOR UPDATE)
await db.$transaction(async (tx) => {
  const [account] = await tx.$queryRaw`
    SELECT * FROM accounts WHERE id = ${userId} FOR UPDATE
  `;

  if (account.balance < purchaseAmount) {
    throw new Error('Insufficient balance');
  }

  await tx.accounts.update({
    where: { id: userId },
    data: { balance: { decrement: purchaseAmount } }
  });
});
```

---

## Phase 7: Parameter Tampering & Role/Tier Elevation

Audit all APIs for parameters that influence permissions, account tiers, or billing cycles:

```json
// ❌ VULNERABLE: Mass assignment allows user to upgrade themselves
POST /api/user/profile
{
  "name": "Attacker",
  "subscriptionTier": "PRO",   <-- Should only be set by payment webhooks!
  "isAdmin": true             <-- Should only be set by root admins!
}
```

**Remediation:** Enforce strict DTOs / Schemas (e.g. Zod `.strict()`) that reject unknown or
privileged attributes on public endpoints.

---

## Phase 8: Idempotency Keys for Financial Endpoints

Network retries or rapid double-clicks can cause duplicate payment captures.

```
Client ────────► POST /api/pay (Idempotency-Key: abc-123) ────────► Backend
                                                                         │
                                                                   Checks Redis:
                                                                   Already processed?
                                                                   YES ➔ Return cached result
                                                                   NO  ➔ Process & cache key
```

All state-changing financial transactions must require an `Idempotency-Key` header with
an atomic lock in Redis/DB to prevent duplicate execution.

---

## Phase 9: Automated Grep & Code Pattern Detection

Execute these commands to identify potential business logic flaws in the codebase:

```powershell
# PowerShell Business Logic Scanner
Write-Host "=== Scanning for Client-Supplied Price/Amount Parameters ===" -ForegroundColor Cyan
Get-ChildItem -Recurse -Include *.ts,*.js,*.py,*.go,*.java | Select-String -Pattern "req\.(body|query)\.(price|amount|unitPrice|discount|total)" | Select-Object Path, LineNumber, Line

Write-Host "`n=== Scanning for Missing Integer/Positive Validation ===" -ForegroundColor Cyan
Get-ChildItem -Recurse -Include *.ts,*.js,*.py | Select-String -Pattern "quantity\s*:" | Select-Object Path, LineNumber, Line

Write-Host "`n=== Scanning for Floating Point Financial Math ===" -ForegroundColor Cyan
Get-ChildItem -Recurse -Include *.ts,*.js | Select-String -Pattern "parseFloat\(.*\)\s*[\*\+\-\/]" | Select-Object Path, LineNumber, Line

Write-Host "`n=== Scanning for Non-Atomic Balance Deductions ===" -ForegroundColor Cyan
Get-ChildItem -Recurse -Include *.ts,*.js,*.py | Select-String -Pattern "balance\s*-\s*amount" | Select-Object Path, LineNumber, Line
```

---

## Phase 10: Finding Template & Remediation Checklist

### Finding Template
```markdown
### [VULN-LOGIC-001] Client-Controlled Unit Price in Checkout Endpoint

- **Severity:** Critical
- **Endpoint:** `POST /api/orders/checkout`
- **Location:** `src/controllers/checkout.ts:38`
- **Flaw Description:** The checkout handler accepts the `unitPrice` field directly from the client's
  JSON request body and uses it to calculate the transaction total charged by Stripe. An attacker
  can tamper with the HTTP request, set `unitPrice: 0.01`, and purchase expensive catalog items
  for pennies.
- **Evidence / Code:**
  ```typescript
  const total = req.body.items.reduce((acc, item) => acc + (item.quantity * item.unitPrice), 0);
  await stripe.charges.create({ amount: total * 100, ... });
  ```
- **Remediation:**
  1. Remove `unitPrice` from the accepted client request schema.
  2. Query authoritative prices from the `products` database table on the server side.
  3. Validate that `quantity` is a positive integer between 1 and 50.
  4. Perform the final payment capture based solely on server-computed prices.
- **Confidence:** High
```

### Remediation Checklist
- [ ] Never trust client-supplied pricing, subtotals, or discount amounts.
- [ ] Validate all quantities as positive integers with realistic minimums and maximums.
- [ ] Enforce strict state machines for multi-step processes; verify payment confirmation before fulfillment.
- [ ] Guard discount redemption with atomic database transactions to prevent coupon replay.
- [ ] Store currency values as integers in the smallest currency unit (e.g. cents) to eliminate floating-point errors.
- [ ] Use atomic database queries (`UPDATE ... WHERE balance >= ...`) or row locks (`FOR UPDATE`) to prevent double-spending.
- [ ] Require idempotency keys for all state-changing financial API requests.
