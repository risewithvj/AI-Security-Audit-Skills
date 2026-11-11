<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Secrets & Environment Variables

Secrets leak in three predictable places in AI-generated projects: baked into the
source, inlined into the client bundle, or committed to git. For an Indian HR/payroll
app the leaked key is rarely trivial — it is the eKYC credential, the SMS-gateway
token, the payment secret, or the database string holding every employee's salary and
PAN. This checklist separates what may safely live client-side from what must never.

Source-only reminder: we read the repo and build config. A string that *looks* like a
live key is `confirmed`; a value we cannot classify (custom-named constant, unclear
usage) is `needs_validation`.

## 1. The rule of three

1. **Not in source** — no key, token, password or private certificate hardcoded in a
   `.py`/`.ts`/`.php` file.
2. **Not in the client bundle** — no secret behind a public build prefix.
3. **Not in git history** — never committed, not even "temporarily."

Each section below maps to one of these.

## 2. Hardcoded credentials in source

Search for and flag:

- Strings shaped like keys in code files (`sk_live_…`, provider tokens).
- Connection strings carrying an inline password, e.g.
  `postgresql://payrolladmin:S3cr3t@db.example.in:5432/payroll`.
- Private keys / `.pem` / `.p12` certificates committed to the repo.

```js
// WRONG — SMS-gateway secret hardcoded for employee OTP
const SMS_TOKEN = "a1b2c3d4-live-token";

// RIGHT — supplied by the environment, absent from the repo
const SMS_TOKEN = process.env.SMS_TOKEN;
```

Any such hardcoded secret is `confirmed`.

## 3. Client-exposed env prefixes

These build-time prefixes inline the value straight into shipped client code. Whatever
carries them is public — treat it as printed on the login page.

| Framework | Public prefix | Where it ends up |
|-----------|---------------|------------------|
| Next.js | `NEXT_PUBLIC_` | Written straight into the shipped browser bundle |
| Vite | `VITE_` | Substituted into client JS during the build |
| Create React App | `REACT_APP_` | Folded into the static front-end assets |
| Expo / React Native | `EXPO_PUBLIC_` | Compiled into the distributed mobile binary |

A `NEXT_PUBLIC_KYC_SECRET` or `VITE_DB_URL` is an immediate `confirmed` finding — the
public prefix on a secret-named value is the tell.

**Safe to expose client-side** (designed to be public):

- Payment **publishable** key (`pk_live_*`, `pk_test_*`)
- Supabase **anon** key
- Firebase web config (`apiKey`, `authDomain`, `projectId`)
- Public analytics / product-tour IDs

**Never client-side** (server-only, full authority):

- Supabase `service_role` key — bypasses every Row-Level-Security rule
- Payment **secret** key (`sk_live_*`, `sk_test_*`)
- A database DSN or connection URL with embedded credentials
- The **secret** half of any vendor integration — eKYC, SMS gateway, payout API
- JWT signing secrets
- OAuth client secrets

A payment publishable key on the client is normal; its secret counterpart on the client
means anyone can charge or refund. The distinction is the audit.

## 4. Git hygiene and the "delete doesn't help" trap

- `.env`, `.env.local`, `.env.*.local`, and any credential file must be in `.gitignore`
  **before the first commit**.
- `.env.example` / `.env.sample` must hold placeholders only, never real values.
- A secret that was ever committed is compromised the instant it was pushed. Removing the
  file in a later commit does **not** erase it from history — rotate the key, then purge
  history if required. This matters for DPDP: a leaked DB string exposes personal data and
  is a reportable security lapse, not a tidy-up task.

## 5. Detection recipe for auditors

Run these passes over the repo:

- Tracked env files: `git ls-files | grep -E '\.env'`.
- Full-history secret scan: `gitleaks detect` (history, not just HEAD).
- Key-shaped strings: `sk_live_`, `sk_test_`, `AKIA`, `ghp_`, `glpat-`, `xoxb-`, `Bearer `.
- Public-prefixed secrets: `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_` references
  whose name contains `secret`, `private`, `service`, `token`, or `key`.
- Credentials embedded in URLs: `://user:password@host`.

## Audit checklist

- [ ] No secret hardcoded in source files.
- [ ] No secret behind a public build prefix; publishable/anon keys only client-side.
- [ ] `.env*` and credential files gitignored; examples contain placeholders.
- [ ] `gitleaks detect` run over full history; any hit rotated.
- [ ] Any committed secret rotated and, where needed, scrubbed from history.

Confirmed leaks carry the file/line (or git object) per
[../../rules/evidence-gate.md](../../rules/evidence-gate.md). Unclassifiable constants are
`needs_validation`. Related: client-bundle exposure in [mobile.md](mobile.md) and
environment separation in [deployment.md](deployment.md).
