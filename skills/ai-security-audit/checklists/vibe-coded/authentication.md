<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Authentication & Authorization

AI coding assistants are fluent at scaffolding login screens and token plumbing, but they lean heavily on the happy path. The result is code that *looks* authenticated while leaving the actual gate open. This checklist walks the auth surface of a vibe-coded app the way an attacker reads it: token trust, where checks really run, and who is allowed to touch which record.

Treat every item here as **source-only**. If you cannot resolve a fact by reading the code (for example, the token verification happens inside an opaque third-party SDK you cannot inspect), mark the finding `needs_validation` rather than guessing. See [`../../rules/evidence-gate.md`](../../rules/evidence-gate.md).

---

## 1. Token trust: what the server will actually believe

A JWT is only as trustworthy as the verification step behind it. The single most common AI-generated mistake is reading a token's claims without ever confirming the signature.

### 1.1 Verify, never merely decode

`decode()` parses the payload and hands it back untouched — no signature math happens. Any attacker can hand-craft a token that says `role: "admin"` and your code will cheerfully believe it.

```javascript
// WRONG — reads claims, trusts them, verifies nothing
const claims = jwt.decode(req.headers.authorization.split(' ')[1]);
if (claims.role === 'hr_admin') { return allPayslips(); }

// RIGHT — signature is checked before any claim is trusted
const claims = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256'],
  issuer: 'payroll.cielhr.in',
  audience: 'ess-portal',
});
```

**Check:** search for `jwt.decode`, `jwtDecode`, `base64` splitting of a token, or `JSON.parse(atob(...))` used for anything other than display. If a decoded claim drives an authorization decision → `confirmed` auth bypass.

### 1.2 Pin the algorithm and reject `none`

Several JWT libraries will honour whatever `alg` the token header asks for. Two attacks follow:

- **`alg: none`** — the token declares it is unsigned, and a permissive library accepts it with an empty signature.
- **Algorithm confusion** — a token signed with the public RSA key but presented as `HS256`, tricking the server into verifying an attacker-controlled HMAC against its own public key.

The defence is to *pin* the accepted algorithm list on the verify call (as above) rather than trusting the header. An empty or wildcard `algorithms` option is the smell.

**Check:** verify calls without an explicit `algorithms` array, or code paths that branch on `header.alg` → `needs_validation` at minimum; `confirmed` if `none` is reachable.

### 1.3 Validate the standard claims, not just the signature

A valid signature proves the token came from your signer. It does **not** prove the token is still valid, meant for this service, or issued by the right party. Enforce:

| Claim | Why it matters | Failure if skipped |
|-------|----------------|--------------------|
| `exp` | Token lifetime | A leaked token works forever |
| `iss` | Who minted it | A token from a sibling service is accepted |
| `aud` | Who it is for | An access token meant for the mobile app unlocks the admin API |
| `nbf` | Not-before | Pre-dated tokens |

In a multi-tenant HR SaaS, skipping `aud` is how a token issued for the employee self-service app ends up authorising calls to the payroll-admin backend. Flag any verify call that omits `exp`/`iss`/`aud` checks.

---

## 2. Where the check runs matters more than whether it exists

AI assistants love to put one auth check in a convenient place and assume it covers everything downstream. It rarely does.

### 2.1 Edge middleware is a convenience, not a wall

Next.js middleware (and similar edge filters) runs before the request reaches your handlers, which makes it a tempting single choke point. It is not reliable as the *only* gate. CVE-2025-29927 showed middleware could be skipped entirely by spoofing the internal `x-middleware-subrequest` header, and framework-level bypasses of this shape recur.

Re-assert identity and permission **inside** every protected unit:

- Route handlers (`app/api/**`)
- Server Actions
- Background jobs and cron handlers
- The data-access layer itself

Think of middleware as a courtesy redirect to `/login`, not as the thing standing between an attacker and an employee's Aadhaar number.

**Check:** if the only auth check for a sensitive route lives in `middleware.ts` and the handler re-reads data with no further check → `confirmed`.

### 2.2 Server Actions are public POST endpoints

A Server Action compiles down to a routable POST endpoint. Anyone with `curl` can invoke it directly, bypassing every button, disabled field, and client-side guard. Generated actions routinely assume "only our form calls this."

```javascript
// WRONG — no identity, no ownership, no input shape
'use server';
export async function approveSalaryRevision(empId, newCtc) {
  await db.compensation.update({ where: { empId }, data: { ctc: newCtc } });
}

// RIGHT — three gates, in order, before any mutation
'use server';
export async function approveSalaryRevision(raw) {
  const input = RevisionSchema.safeParse(raw);        // 1. validate shape
  if (!input.success) return { error: 'Bad request' };

  const session = await auth();                        // 2. authenticate
  if (!session?.user) redirect('/login');

  const actor = await getRole(session.user.id);        // 3. authorize
  if (actor !== 'hr_manager') return { error: 'Forbidden' };

  await db.compensation.update({
    where: { empId: input.data.empId },
    data: { ctc: input.data.newCtc },
  });
}
```

Every Server Action needs, at the top and in this order:

1. **Input validation** — a runtime schema (Zod/Yup/Joi), not a TypeScript type.
2. **Authentication** — a real session, not a header the client sets.
3. **Authorization** — proof this user may act on *this* record (see §4).

### 2.3 API route handlers carry the same burden

Every file under `app/api/**`, every Express route, every Flask view is a public endpoint. "It's only linked from the admin dashboard" is not access control. Authenticate and authorize at the top of each handler, individually. A shared middleware is fine *in addition*, never *instead*.

---

## 3. Sessions, cookies, and credential handling

### 3.1 Store tokens where script cannot reach them

Put session tokens in cookies flagged `HttpOnly`, `Secure`, and `SameSite=Lax` (or `Strict` for pure first-party flows). The moment a token lives in `localStorage`, a single reflected-XSS bug exfiltrates every logged-in employee's session, because any script on the page can read it. `HttpOnly` cookies are invisible to JavaScript and ride along automatically.

```javascript
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  maxAge: 1000 * 60 * 30,   // 30 min for a payroll console
});
```

**Check:** `localStorage.setItem(...token...)`, `sessionStorage` holding JWTs, or cookies set without `httpOnly` → `confirmed` for token theft exposure.

### 3.2 Session lifecycle

- **Rotate on privilege change.** Issue a fresh session identifier at login and after any elevation (e.g. an employee being promoted to approver), to defeat session fixation.
- **Invalidate server-side on logout.** A stateless JWT with no revocation list keeps working until `exp`. For KYC/payroll consoles, back long-lived access with a server-checked session or short-lived tokens plus refresh.
- **Bound the lifetime.** Infinite or multi-day access tokens on a DPDP-regulated system are a finding in themselves.

### 3.3 Password and credential handling

- Hash with a slow, salted algorithm — **bcrypt, scrypt, or Argon2**. Any sighting of MD5, SHA-1, SHA-256, or unsalted hashing for passwords → `confirmed`.
- Never log credentials, OTPs, or raw tokens. Grep logging calls near login, OTP verification, and KYC steps for plaintext secrets.
- Compare secrets and OTPs with a constant-time comparison, not `===`, to avoid timing leaks on short codes.
- Enforce real reset flows: single-use, expiring, unguessable tokens — not the user's email or employee ID as the reset key.

---

## 4. Authorization: the gap AI code forgets

Authentication answers "who are you." Authorization answers "may *you* touch *this*." Vibe-coded apps overwhelmingly stop at the first.

### 4.1 Ownership, not just login

A logged-in user is not automatically entitled to every record the query can reach. Scope every read and write to the caller.

```javascript
// WRONG — any authenticated employee can pull any payslip by guessing the id
app.get('/api/payslip/:id', requireLogin, async (req, res) => {
  res.json(await db.payslip.findUnique({ where: { id: req.params.id } }));
});

// RIGHT — the record must belong to the caller (or caller must be HR)
app.get('/api/payslip/:id', requireLogin, async (req, res) => {
  const slip = await db.payslip.findFirst({
    where: { id: req.params.id, empId: req.user.empId },
  });
  if (!slip) return res.sendStatus(404);   // 404, not 403 — don't confirm existence
  res.json(slip);
});
```

This is an **IDOR** (insecure direct object reference). It is the highest-yield bug class in HR/payroll portals: sequential payslip IDs, UAN-based lookups, or `/employee/1042/documents` where swapping the number returns someone else's PAN and Aadhaar. For the full data-layer treatment see [`data-access.md`](data-access.md).

### 4.2 Enforce roles server-side, every time

Client-side role checks (hiding an "Approve" button for non-managers) are cosmetic. The approval endpoint must independently confirm the role. A disabled button in React is not access control.

### 4.3 Function-level authorization

Admin-only operations — bulk Form-16 export, Aadhaar re-verification, deleting an employee record — must check the role on the server at the point of execution, never infer it from the route name or a hidden form field.

---

## 5. Data-shape leaks at the trust boundary

### 5.1 Don't hand whole records to the client

Returning a full database row to a Client Component or API response leaks whatever columns it carries — password hashes, internal flags, another system's foreign keys, full Aadhaar when only the masked last-4 was needed. Select explicitly.

```javascript
// WRONG — ships the entire row, including bank account and PAN, to the browser
const emp = await db.employee.findUnique({ where: { id } });
return <Profile employee={emp} />;

// RIGHT — project only what the view needs
const emp = await db.employee.findUnique({
  where: { id },
  select: { name: true, designation: true, photoUrl: true },
});
return <Profile employee={emp} />;
```

Under DPDP's data-minimisation expectations, over-returning personal data is both a security and a compliance problem.

### 5.2 Keep server-only code server-only

Add `import 'server-only'` to modules that read secrets or personal data, so an accidental import into a Client Component fails the build instead of shipping credentials to the browser.

---

## Verdict rules for this checklist

| Observation | Verdict |
|-------------|---------|
| Decoded (unverified) claim drives an auth/role decision | `confirmed` |
| `alg: none` or unpinned algorithm reachable on a verify path | `confirmed` if exploitable, else `needs_validation` |
| Sensitive route guarded only by edge middleware | `confirmed` |
| Server Action / API handler missing authn or authz | `confirmed` |
| Object fetched by id with no ownership scope (IDOR) | `confirmed` |
| Passwords hashed with MD5/SHA-x or unsalted | `confirmed` |
| Tokens in `localStorage`/`sessionStorage` | `confirmed` |
| Verification hidden inside an un-inspectable SDK | `needs_validation` |
| Role check present but reachability of bypass unclear | `needs validation` |

Cross-references: [`data-access.md`](data-access.md) for the query-layer side of IDOR and injection, and [`../../rules/evidence-gate.md`](../../rules/evidence-gate.md) for how to grade source-only findings.
