# Business Logic & Transaction Security — Technical Reference

## 1. Strict Finite State Machine (FSM) Architecture

To prevent workflow bypasses (such as skipping payment or executing state transitions out of order),
implement an explicit Finite State Machine.

### State Transition Matrix for Order Checkout

| Current State | Allowed Next States | Trigger Event | Verification Required |
|---|---|---|---|
| `DRAFT` | `SHIPPING_SELECTED` | User sets shipping address | Address validation |
| `SHIPPING_SELECTED` | `PAYMENT_PENDING` | User selects payment method | Recalculate tax & discounts |
| `PAYMENT_PENDING` | `PAID` | Payment gateway webhook | Webhook signature & amount match |
| `PAYMENT_PENDING` | `FAILED` | Payment declined | Log failure reason |
| `PAID` | `PROCESSING` | Warehouse begins packing | Verify paid amount == total |
| `PROCESSING` | `SHIPPED` | Tracking number assigned | Courier API integration |
| `PAID` | `REFUNDED` | Admin / customer cancel | Reverse payment via gateway |

### Code Implementation Pattern (TypeScript / Prisma)

```typescript
export class OrderStateMachine {
  private static ALLOWED_TRANSITIONS: Record<string, string[]> = {
    DRAFT: ['SHIPPING_SELECTED', 'CANCELLED'],
    SHIPPING_SELECTED: ['PAYMENT_PENDING', 'CANCELLED'],
    PAYMENT_PENDING: ['PAID', 'PAYMENT_FAILED', 'CANCELLED'],
    PAID: ['PROCESSING', 'REFUNDED'],
    PROCESSING: ['SHIPPED', 'REFUNDED'],
    SHIPPED: ['DELIVERED', 'RETURNED'],
  };

  static async transition(orderId: string, targetState: string, tx: any) {
    const order = await tx.order.findUnique({
      where: { id: orderId }
    });

    if (!order) {
      throw new Error(`Order ${orderId} not found`);
    }

    const validNextStates = this.ALLOWED_TRANSITIONS[order.status] || [];
    if (!validNextStates.includes(targetState)) {
      throw new Error(
        `Invalid state transition: Cannot change order from ${order.status} to ${targetState}`
      );
    }

    return await tx.order.update({
      where: { id: orderId },
      data: { status: targetState, updatedAt: new Date() }
    });
  }
}
```

---

## 2. Idempotency Key Implementation (Redis + Node.js)

Prevent double-charging or duplicate order fulfillment from network timeouts and rapid clicks:

```typescript
import { Request, Response, NextFunction } from 'express';
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

export async function idempotencyMiddleware(req: Request, res: Response, next: NextFunction) {
  const idempotencyKey = req.headers['idempotency-key'] as string;
  if (!idempotencyKey) {
    // For non-financial routes, proceed; for payment routes, require it
    return next();
  }

  const cacheKey = `idempotency:${req.user?.id}:${idempotencyKey}`;
  const existingRecord = await redis.get(cacheKey);

  if (existingRecord) {
    const { status, body } = JSON.parse(existingRecord);
    return res.status(status).json(body);
  }

  // Intercept response to store result
  const originalJson = res.json.bind(res);
  res.json = (body: any) => {
    if (res.statusCode >= 200 && res.statusCode < 300) {
      redis.set(cacheKey, JSON.stringify({ status: res.statusCode, body }), 'EX', 86400); // 24 hours
    }
    return originalJson(body);
  };

  next();
}
```

---

## 3. Concurrency Testing Script (Simulating Double-Spending)

Use this Python script during audits to test whether an endpoint is vulnerable to race conditions
when redeeming limited balances, coupons, or gift cards:

```python
# test_race_condition.py
import requests
import concurrent.futures

TARGET_URL = "https://app.example.com/api/giftcard/redeem"
HEADERS = {
    "Authorization": "Bearer TEST_TOKEN",
    "Content-Type": "application/json"
}
PAYLOAD = {
    "code": "GIFT-100-DOLLARS",
    "amount": 100
}

def send_request(request_id):
    try:
        response = requests.post(TARGET_URL, json=PAYLOAD, headers=HEADERS, timeout=10)
        return response.status_code, response.text
    except Exception as e:
        return 0, str(e)

def execute_race_test(threads=15):
    print(f"Launching {threads} concurrent redemption requests...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(send_request, i) for i in range(threads)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    success_count = sum(1 for status, _ in results if status == 200)
    print(f"\nResults: {success_count} succeeded out of {threads} attempts.")
    if success_count > 1:
        print("❌ CRITICAL: Race condition detected! Single-use resource redeemed multiple times!")
    else:
        print("✅ PASS: Resource correctly redeemed only once.")

if __name__ == "__main__":
    execute_race_test()
```

---

## 4. Financial Currency Math Best Practices

```
┌────────────────────────────────────────────────────────┐
│                   Database & Internal API              │
│       Store ALL monetary amounts in integer cents:     │
│       $19.99 ➔ 1999 (USD)                              │
│       ¥2,500 ➔ 2500 (JPY, zero-decimal currency)       │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│                   Display / Formatter Layer            │
│       Convert to decimal ONLY when formatting for UI:  │
│       Intl.NumberFormat('en-US', { style: 'currency' })│
└────────────────────────────────────────────────────────┘
```

1. **Zero-Decimal Currencies:** Handle currencies like JPY, KRW, and CLP that do not use cents.
2. **Rounding Rules:** Specify `BigDecimal.ROUND_HALF_EVEN` (Banker's Rounding) to prevent systematic rounding bias when calculating sales tax.
