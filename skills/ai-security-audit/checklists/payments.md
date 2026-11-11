<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Payment Flow Security

Payment code is where a logic slip turns straight into financial loss. Whether the integration is Razorpay, PayU, a UPI collect flow, or Stripe, the recurring theme is the same: the browser is an attacker-controlled environment, yet apps keep trusting it to report what a thing costs, whether a payment succeeded, or who the paying user is.

This checklist is source-only. You are reading order-creation handlers, webhook endpoints, and verification helpers — you are not transacting against a live gateway. When you cannot see both sides of a flow (for example, the webhook handler is in a separate service not in the repo), record `needs_validation` rather than assuming it is safe. See `rules/evidence-gate.md`.

The flows below use INR and Indian gateways where it reads naturally — a payroll SaaS taking subscription payments, an HR portal charging for a background-verification add-on — and stay neutral where the vulnerability is gateway-independent.

---

## 1. The amount must be decided on the server

The defining payment bug in assistant-generated apps: the price arrives in the request body. If the client names the amount, the client can name `1` paisa — or `0`.

Never build a charge from a client-supplied figure:

```js
// BAD — the browser tells the server what to charge
app.post('/order', async (req, res) => {
  const order = await razorpay.orders.create({
    amount: req.body.amount,        // attacker sets this to 100 (₹1)
    currency: 'INR',
    receipt: req.body.receipt,
  });
  res.json(order);
});
```

Resolve the price from a server-side catalogue keyed only by an identifier:

```js
// GOOD — client sends a plan id; the server owns the price
app.post('/order', async (req, res) => {
  const plan = await db.plans.findUnique({ where: { id: req.body.planId } });
  if (!plan) return res.status(404).json({ error: 'unknown plan' });

  const order = await razorpay.orders.create({
    amount: plan.priceInPaise,     // authoritative, never from the client
    currency: 'INR',
    receipt: `sub_${req.user.id}_${Date.now()}`,
    notes: { userId: req.user.id, planId: plan.id },
  });
  res.json({ orderId: order.id, amount: order.amount });
});
```

Where the gateway supports pre-defined price objects (Stripe Price IDs, Razorpay Plan/Subscription entities), prefer those — the figure then lives in the gateway and never transits the client at all.

Verdict rule: an order/charge whose amount, currency, or line-item price is read from the request body (or any client-controlled field) is a `confirmed` price-tampering finding. If the amount is read from the DB but you cannot see where the DB value came from, `needs_validation`.

---

## 2. Verify payment success on the server — never on the client's word

After checkout, the browser gets a success callback. That callback is not proof. For Razorpay you must recompute the signature over `order_id|payment_id` with your key secret and compare; a mismatch means the result was forged or tampered.

```js
// GOOD — confirm the handshake before granting anything
const crypto = require('crypto');

app.post('/verify', async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

  const expected = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest('hex');

  // timing-safe compare — avoid === on secrets
  const ok =
    expected.length === razorpay_signature.length &&
    crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(razorpay_signature));

  if (!ok) return res.status(400).json({ error: 'signature mismatch' });

  await grantSubscription(req.user.id, razorpay_order_id);
  res.json({ status: 'ok' });
});
```

A flow that unlocks a paid feature based solely on a client-reported "payment successful" — with no server-side signature or webhook confirmation — is `confirmed`.

---

## 3. Webhooks: signature first, over the raw body

Webhooks are the authoritative, out-of-band notification from the gateway. Two things must be true before you act on one.

**(a) The signature must be verified.** Razorpay signs the payload with your webhook secret (`X-Razorpay-Signature`); Stripe uses `Stripe-Signature`; PayU posts a hash you must recompute. An unsigned, or signature-unchecked, webhook endpoint is a public API that anyone can call to mark their order paid.

**(b) It must be computed over the exact raw bytes.** Parsing the body as JSON first re-serialises it and breaks the HMAC. The raw body must reach the verifier untouched.

```js
// Express — raw body ONLY on the webhook route, before any json() middleware
app.post('/razorpay/webhook',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const expected = crypto
      .createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET)
      .update(req.body)                        // Buffer, raw bytes
      .digest('hex');

    const sig = req.headers['x-razorpay-signature'];
    if (expected !== sig) return res.status(400).end();

    const event = JSON.parse(req.body);        // parse only AFTER verifying
    handleEvent(event);
    res.status(200).end();
  });
```

```js
// Next.js App Router — use request.text(), never request.json()
export async function POST(request) {
  const raw = await request.text();            // raw string preserves the bytes
  const sig = request.headers.get('x-razorpay-signature');
  // ...verify HMAC over `raw`, then JSON.parse(raw)
}
```

Verdict rules: a webhook handler with no signature verification is `confirmed`. A handler that calls `req.json()` / `express.json()` before verifying (so the signature can never match the real raw body, or is skipped) is `confirmed`. If `express.json()` is mounted app-wide *before* the webhook route, note that the raw body is already gone — `confirmed`.

---

## 4. Idempotency and replay

Gateways retry webhooks until they get a 2xx. A captured webhook can also be replayed by an attacker who sniffed or guessed it. If your handler grants credit or extends a subscription on *every* delivery, a legitimately-paid ₹499 plan can be redeemed many times, or a single payment event double-credits a wallet.

Defend on two axes:

- **Idempotency key.** Record the gateway's event/payment id and make the grant conditional on first-seen. A unique index turns a replay into a harmless no-op.

```js
async function handleEvent(event) {
  try {
    await db.processedEvents.create({ data: { id: event.id } }); // UNIQUE(id)
  } catch {
    return; // already handled — idempotent, safe to drop
  }
  await applyPaymentEffect(event);
}
```

- **Freshness.** Where the gateway signs a timestamp (Stripe's `t=` in the signature header), reject events older than a small tolerance so a replayed old payload is refused even if its signature is intact.

Also send an idempotency key on *outbound* order creation so a retried create call doesn't open two orders for one checkout.

Verdict rule: a webhook / verification handler that applies a financial effect with no first-seen / idempotency guard is `confirmed` (double-credit / replay). Missing timestamp-freshness check where the gateway provides one is `needs_validation` unless replay is clearly exploitable.

---

## 5. Currency must be pinned server-side

If the currency travels with the amount from the client, an attacker can keep `amount: 499` but switch `currency` from `INR` to a weaker unit — paying a fraction of the real price. The currency belongs with the price in your server catalogue, never in the request.

```js
// BAD
razorpay.orders.create({ amount: plan.price, currency: req.body.currency });
// GOOD
razorpay.orders.create({ amount: plan.priceInPaise, currency: plan.currency }); // both from DB
```

Also confirm the unit is consistent: Razorpay and Stripe both charge in the smallest unit (paise / cents). A handler that passes rupees where paise is expected under-charges by 100×, and one that stores the gateway's paise figure as rupees over-reports. A client-supplied `currency`, or a rupee/paise unit mismatch between order creation and reconciliation, is `confirmed`.

---

## 6. Coupons, discounts, and credits — validate every one on the server

Discount logic is a favourite target because the maths is easy to get wrong:

- **Coupon existence, validity window, and usage cap** must be checked in the handler, not assumed from a client flag. A client that posts `couponApplied: true` or a client-computed `finalAmount` has simply told you the price it wants to pay.
- **Per-user limits** must be enforced against stored redemptions, under a transaction/lock, or the same coupon races through concurrently and blows past its cap.
- **Stacking and floors.** Confirm discounts cannot combine to drive the charge to zero or negative, and that percentage logic can't underflow.
- **Wallet / referral credit** is money — deduct it atomically and re-check the balance server-side at charge time, never trusting a balance the client echoed back.

```js
// GOOD — recompute the payable amount server-side from trusted inputs
const plan   = await db.plans.findUnique({ where: { id: planId } });
const coupon = code ? await db.coupons.findValid(code, req.user.id) : null; // existence+window+cap
const payable = applyDiscount(plan.priceInPaise, coupon);                   // server maths
if (payable < plan.floorPaise) throw new Error('discount below floor');
```

A discount or final amount accepted from the client, or coupon validity / usage-cap enforced only in the browser, is `confirmed`. Missing concurrency control on per-user redemption is `needs_validation` unless a race is demonstrable from the code.

**Forgeable coupon / voucher / referral tokens.** Beyond "is the discount validated server-side", check how the token the user presents is *minted and trusted*. A coupon, gift-card, voucher, or referral token must be validated against authoritative server state — a stored record with a remaining balance, a validity window, and a redemption count — not merely parsed or recomputed from the token itself. These patterns let a user mint their own valid discount:

- **Client-forgeable / self-describing tokens.** The token encodes the discount (`BASE64("PCT:50;EXP:2030")`, a JSON blob, or a value the client can edit) and the server honours what it decodes instead of looking the code up. The user rewrites `50` to `100`.
- **Guessable or sequential codes.** Codes are short, predictable, or allocated in sequence (`SAVE0001`, `SAVE0002`), so an attacker enumerates live, unredeemed vouchers. Sequentiality raises likelihood; the finding is the server accepting a code the attacker never legitimately received.
- **Weak or shared signing secret.** A "signed" voucher uses HMAC/JWT with a hardcoded, committed, default, or trivially short secret, or an unkeyed hash (`md5(code)`), so the attacker recomputes valid signatures at will. Pin down the secret's source and strength, the same way the JWT and webhook sections do.
- **No single-use / no authoritative decrement.** Even a well-formed token must be marked spent atomically. A gift-card balance read from the token (or echoed by the client) rather than decremented in the database lets one voucher pay forever.

Recompute the payable amount only from a coupon record the server fetched by code and found valid; never from fields the token carried. A coupon/voucher/referral/gift-card token that is client-forgeable, guessable, sequentially enumerable, or signed with a weak or known secret — or any discount token accepted without being verified against authoritative server state — is `confirmed`. Where the signing secret's strength or storage cannot be resolved from source, `needs_validation` naming the secret.

---

## 7. Entitlement is the database's job, checked every time

Whether a user is on the Pro plan right now is server state — kept in sync by webhooks — and must be re-read on every protected request. Do not gate access on:

- a plan flag baked into the session at login,
- a client-side boolean,
- a JWT claim minted once and never refreshed.

Subscriptions lapse, get cancelled, downgrade, or fail renewal. The database (updated via verified webhooks) is the single source of truth. A payslip-export feature guarded by a stale login-time flag keeps working for a month after the customer stopped paying — and, worse, the same pattern often *grants* access the moment a client flips a client-side flag.

Verdict rule: paid-feature access decided from a client flag or an un-refreshed token claim, rather than current server/DB state, is `confirmed`.

---

## 8. Order metadata must be set server-side

Metadata attached at order creation — `userId`, `planId`, tenant — is what the webhook later trusts to decide *who* to credit. If any of it originates from the client, an attacker pays for a cheap plan while tagging the order with a premium `planId`, or credits the payment to another account entirely.

Set these from the authenticated session when you create the order (see §1's `notes: { userId: req.user.id, ... }`), and on the webhook side re-resolve the user/plan from your own records rather than from any field the client could have influenced. Metadata used for entitlement that was populated from client input is `confirmed`.

---

## 9. Reviewer quick-reference

| # | Pattern to flag | Verdict |
|---|-----------------|---------|
| 1 | Amount / price / currency / line-item read from request body | `confirmed` |
| 2 | Paid feature unlocked on client-reported success, no server verify | `confirmed` |
| 3 | Webhook with no signature verification | `confirmed` |
| 3 | Body parsed as JSON before HMAC (raw bytes lost / check skipped) | `confirmed` |
| 4 | Financial effect applied with no idempotency / first-seen guard | `confirmed` |
| 4 | No replay-window check where gateway signs a timestamp | `needs_validation` |
| 5 | Currency supplied by client, or paise/rupee unit mismatch | `confirmed` |
| 6 | Discount / final amount accepted from client; coupon validity only client-side | `confirmed` |
| 6 | No concurrency control on per-user coupon redemption | `needs_validation` |
| 6 | Coupon/voucher token forgeable, guessable, sequential, or weakly signed | `confirmed` |
| 7 | Entitlement from client flag or stale token, not current DB state | `confirmed` |
| 8 | Entitlement metadata populated from client input | `confirmed` |
| — | Only one side of the flow visible in the repo | `needs_validation` |

See also: `secrets-and-config.md` (gateway key secret / webhook secret leakage — a leaked key secret lets anyone forge signatures, which collapses §2 and §3), `api-authorization.md` (the authenticated-user binding behind order metadata), `data-isolation-and-lifecycle.md` (crediting the right tenant), and `rules/evidence-gate.md`.
