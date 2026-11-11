<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Rate Limiting & Abuse Prevention

AI coding assistants almost never add throttling on their own. The generated route
handler works for one polite user and falls apart the moment someone scripts it. On an
Indian HR/payroll stack the damage is concrete: OTP floods on login, brute-forced
employee logins, enumerated PAN/UAN lookups, and runaway bills on any metered API.

Source-only reminder: we can confirm from code whether a limiter is wired onto a route;
we cannot confirm the live threshold is correctly tuned. Absent or clearly ineffective
limiting is `confirmed`; "a limiter exists but the window is unclear" is
`needs_validation`.

## 1. Which endpoints must be throttled

Think in terms of **what an attacker gains per request**. Any route where repetition is
valuable needs a limit.

| Endpoint class | HR/payroll example | Abuse without a limit |
|----------------|--------------------|-----------------------|
| Authentication | login, register, forgot-password | Password brute force, account lock-out of others |
| OTP / one-time codes | login OTP, salary-slip download OTP | SMS flooding, OTP guessing, carrier-cost drain |
| Lookup / verification | PAN, UAN, Aadhaar-last-4, bank IFSC check | Enumeration of valid identifiers |
| Payment / payout | salary payout trigger, vendor payment | Duplicate payouts, cost abuse |
| Metered third-party calls | eKYC, SMS, LLM summarisation of reviews | A single user drains the monthly budget |
| Heavy compute | payslip PDF generation, bulk Form-16 export | CPU-exhaustion denial of service |

If a route in these classes has no limiter in the code path, it is a finding.

## 2. Two abuse vectors you must both close

The classic enumeration/brute-force pair needs both distinctions addressed:

- **Brute force** — same target, many guesses (one account, thousands of passwords or
  OTPs). Defeated by a per-identifier attempt cap with back-off and lockout.
- **Enumeration** — many targets, one probe each (is this PAN registered? does this
  email have an account?). Defeated by rate limits **plus** uniform responses — return
  the same message and timing whether or not the identifier exists.

A payroll portal that answers "no employee with this PAN" differently from "wrong
password" leaks who is enrolled. Keep responses indistinguishable.

## 3. Combine per-IP and per-account keys

| Keying strategy | Bypassed by | Verdict if used alone |
|-----------------|-------------|------------------------|
| Per-IP only | Rotating IPs (VPN, botnet, cloud ranges) | Weak |
| Per-account / per-identifier only | Registering new accounts | Weak |
| Both, combined | — | Recommended |

Use the pair: an IP budget stops a single host hammering, and a per-identifier budget
stops a distributed brute force on one employee login.

## 4. Store counters where users can't reset them

A limiter is only as trustworthy as its counter store.

- **Do not** keep counters in a client-reachable table (e.g. a Supabase public table a
  user can `UPDATE` through PostgREST) — they will reset their own limit.
- Prefer a serverless store with limiting primitives (Upstash Redis), a **private**
  schema table not exposed by the API, edge/gateway middleware, or an in-memory store
  for a single instance (Redis once you scale horizontally).

## 5. Spend controls (cost abuse is a security issue)

Rate limits cap request **frequency**; you also need a cap on **money**.

- Hard spending caps on every metered provider (eKYC, SMS gateway, LLM).
- Per-user usage quotas that actually block, not just warn.
- Billing alerts on each cloud account (AWS/GCP/Vercel/…).
- Alerting on anomalies — a spike at 3 a.m., or one tenant suddenly generating ten
  thousand Form-16 PDFs.

## 6. Reference implementation

```ts
// Upstash Redis sliding window, keyed on IP + account for an OTP route
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

const otpLimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, "10 m"), // 5 OTP requests / 10 min
});

export async function POST(req: Request) {
  const ip = req.headers.get("x-forwarded-for") ?? "0.0.0.0";
  const { employeeId } = await req.json();
  const { success } = await otpLimit.limit(`otp:${ip}:${employeeId}`);
  if (!success) {
    return new Response("Too many OTP requests, try again later.", { status: 429 });
  }
  // ... issue OTP
}
```

## Audit checklist

- [ ] Every auth, OTP, lookup, payment, metered-API and heavy-compute route has a
      limiter in its code path.
- [ ] Both per-IP and per-identifier keys are used together.
- [ ] Enumeration-prone endpoints return uniform messages and timing.
- [ ] Counters live in a store users cannot reset.
- [ ] Hard spend caps, blocking quotas, billing alerts and anomaly alerting are set.

Unlimited endpoints are `confirmed` with the file/line of the handler per
[../../rules/evidence-gate.md](../../rules/evidence-gate.md); uncertain thresholds are
`needs_validation`.
