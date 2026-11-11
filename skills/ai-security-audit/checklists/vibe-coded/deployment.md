<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Deployment Security

AI-generated apps ship fast and ship loud. The default scaffolds that assistants
emit are tuned for a developer laptop, not for a production host serving real
payslips and KYC records. This checklist covers the gap between "it runs on my
machine" and "it is safe to point at the public internet."

Framing note: this skill reads source and configuration only. It never runs the
target app. When a setting cannot be resolved from the repo alone — for example,
whether debug mode is actually off on the live host — the verdict is
`needs_validation`, not a guess.

## 1. The verbosity trap (debug, stack traces, source maps)

The single most common vibe-coded leak is a build that is still in "tell me
everything" mode.

| What to look for | Why it bites | Verdict if found in prod config |
|------------------|--------------|----------------------------------|
| `DEBUG = True` (Django/Flask), `app.debug` on, `NODE_ENV` not `production` | A failed PF-calculation request renders a full stack trace with env vars, SQL and file paths | `confirmed` |
| Source maps emitted for client bundles | Opening DevTools on your HR portal reveals the entire TypeScript source | `confirmed` |
| Verbose/unhandled error responses returning internal messages to the client | An Aadhaar-verification timeout echoes the upstream URL and request body | `confirmed` |

A verbose error page on an Indian HR portal routinely exposes the database host,
the payroll schema, and sometimes a half-logged employee PAN. Keep production
errors generic ("Something went wrong, reference ID 7f3a…") and push the detail
to server-side logs only.

```python
# Flask — read the flag from the environment, default to OFF
import os
app.run(debug=os.environ.get("FLASK_DEBUG") == "1")  # never hardcode True
```

## 2. Repository artefacts served to the world

- **Exposed `.git`.** If `https://portal.example.in/.git/HEAD` returns data, the
  whole history is downloadable — including any salary-key or SMTP password that
  was ever committed and later "removed." Treat this as a full source leak.
- Also check for served `.env`, `.env.local`, `/.svn/`, `composer.lock`,
  backup files (`config.php.bak`, `db.sql`) reachable over HTTP.

These are configuration mistakes, not code bugs — flag them `needs_validation`
when you can only infer the web-root layout from the repo, and `confirmed` when a
rule explicitly maps a public path to a sensitive file.

## 3. Keeping environments apart

A preview URL is usually guessable or shareable, so it must never carry live
secrets. Treat each tier as a separate trust boundary.

| Tier | Data it may touch | Keys it may hold |
|------|-------------------|------------------|
| Production | Real employee records, live KYC | Live payment, live Aadhaar/eKYC API keys |
| Staging / Preview | Synthetic or masked data | Sandbox keys only |
| Local dev | Seed/fixture data | Throwaway local keys |

If a preview deployment of the payroll app is wired to the production database or
the live PAN-verification key, anyone who receives the preview link can pull real
personal data — a DPDP exposure, not merely a bug. Cross-check this against
[secrets-and-env.md](secrets-and-env.md).

## 4. Default and placeholder credentials

AI scaffolds love `admin / admin`, `changeme`, seeded demo users, and an
unguarded `/admin` route.

- Hunt for seeded accounts in migrations/fixtures (an `admin@example.com` with a
  known password).
- Confirm admin/management routes require authentication **and** authorisation,
  not just that the link is hidden from the navbar.
- Default framework dashboards (Adminer, phpMyAdmin, Django admin, Bull board)
  must not be reachable unauthenticated in production.

An open `/admin` on an HR system means an attacker can approve their own
salary-revision or export the full employee master. Flag unauthenticated admin
surfaces as `confirmed`; flag "hidden but technically reachable" as
`needs_validation` pending a check of the route guard.

## 5. Cross-origin policy (CORS)

The failure mode is a wildcard copied from a Stack Overflow answer that then ships.

- `Access-Control-Allow-Origin: *` on any authenticated endpoint lets a malicious
  site read the responses — e.g. a third-party page silently fetching an
  employee's payslip JSON using the victim's session.
- `Access-Control-Allow-Credentials: true` paired with `*` is invalid per spec and,
  where frameworks reflect the Origin, becomes an open door. Credentials must be
  paired with an explicit allow-list.
- Prefer an explicit list of your own origins over reflecting `Origin` back.

```js
// Express — allow-list your own front-ends only
const allowed = ["https://hr.example.in", "https://admin.example.in"];
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowed.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  next();
});
```

## 6. Response security headers

Missing headers rarely cause a breach alone but remove defence-in-depth. Set these
on every response:

```
Content-Security-Policy: default-src 'self'; script-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

Tune the `Content-Security-Policy` to your real dependencies (inline styles, a CDN
for fonts), but begin tight and open only what breaks. `X-Frame-Options: DENY`
stops your consent/approval screens from being clickjacked inside an attacker's
iframe. For an HR portal, `Permissions-Policy` locking camera/mic down also helps
your DPDP story on data minimisation.

## 7. Before you flip the switch — pre-ship pass

Run this sweep against the repo and the intended prod config:

- [ ] Secret scanner (`gitleaks detect`) run over the **full history**, not just
      the working tree.
- [ ] `.env`, `.env.*`, and any credential file present in `.gitignore`.
- [ ] Debug/verbose logging confirmed off for production.
- [ ] Error pages return generic messages, no stack traces.
- [ ] CORS limited to owned origins; no wildcard on authenticated routes.
- [ ] Security headers present on responses.
- [ ] No default/seed credentials; admin routes guarded.
- [ ] Preview/staging uses sandbox keys and masked data only.

Anything you cannot verify from source alone stays `needs_validation`; record the
specific check that a human must run on the live host. For the evidence standard
every confirmed finding must meet, see [../../rules/evidence-gate.md](../../rules/evidence-gate.md).
