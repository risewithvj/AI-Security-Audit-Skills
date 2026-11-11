<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Data Access & Input Validation

The data layer is where a vibe-coded app's convenience becomes a breach. AI assistants generate queries that work for the demo, then leave two things implicit: that the input is well-formed, and that the caller is allowed to touch the rows the query can reach. For an HR/payroll/KYC system those rows are PAN, Aadhaar, UAN, salary, and bank details — exactly what a regulator and an attacker both care about.

This checklist is **source-only**. Where a fact cannot be settled by reading the code — say, whether an ORM method sanitises a particular input — mark it `needs_validation` rather than assuming. See [`../../rules/evidence-gate.md`](../../rules/evidence-gate.md).

---

## 1. Authorization on the query itself

Most data-layer breaches in generated apps are not injection — they are *missing authorization*. The query runs fine; it just returns someone else's data.

### 1.1 Insecure Direct Object Reference (IDOR)

A handler takes an id from the request and fetches that record, with nothing confirming the record belongs to the caller. Swap the id, read another person's data.

```javascript
// WRONG — any logged-in employee reads any payslip by changing the id
app.get('/api/payslip/:id', auth, async (req, res) => {
  const slip = await db.payslip.findUnique({ where: { id: req.params.id } });
  res.json(slip);
});

// RIGHT — scope the lookup to the caller (HR gets a widened scope elsewhere)
app.get('/api/payslip/:id', auth, async (req, res) => {
  const slip = await db.payslip.findFirst({
    where: { id: req.params.id, empId: req.user.empId },
  });
  if (!slip) return res.sendStatus(404);
  res.json(slip);
});
```

The id does not have to be a database primary key. `/employee/1042/form16`, `?uan=100123456789`, a predictable document GUID — any attacker-controllable reference that selects a record without an ownership filter is an IDOR. Return `404` rather than `403` so you don't confirm that the record exists.

**Check:** every `findUnique`/`findFirst`/`SELECT ... WHERE id =` driven by request input — does the `where` clause also pin the owner (or a verified role)? If not → `confirmed`.

### 1.2 Authorization belongs in the query, not just the route

A route-level role check ("is this user HR?") is good, but the *scope* still has to live in the `where` clause. An HR manager for the Chennai branch should not read Mumbai employees just because the route said "HR allowed." Carry the tenant/branch/owner constraint down into every query.

### 1.3 List endpoints leak in bulk

IDOR's quieter sibling: a `GET /api/employees` that returns *all* rows because the generated query never filtered by the caller's organisation or branch. One request, the whole directory. Confirm list queries are scoped, paginated, and bounded.

Authentication-side ownership and role enforcement are covered in [`authentication.md`](authentication.md) §4; this file is the query-layer view of the same gap.

---

## 2. Injection: never let input become code

### 2.1 Raw SQL string-building

Concatenating input into SQL is the textbook injection. One crafted value and an attacker reads or drops the `employees` table.

```javascript
// WRONG — input is spliced into the SQL text
const rows = await db.query(
  `SELECT * FROM employee WHERE pan = '${req.query.pan}'`
);

// RIGHT — parameterised; the driver keeps data and code apart
const rows = await db.query(
  'SELECT * FROM employee WHERE pan = $1',
  [req.query.pan],
);
```

**Check:** any query built with template literals, `+`, `.format()`, f-strings, or `%` interpolation on request-derived values → `confirmed`.

### 2.2 ORMs are not automatically safe

An ORM parameterises *values*, but it does not stop you from handing it an attacker-controlled *structure*.

**Operator / filter injection.** Passing a raw request body straight into a `where` lets an attacker inject operators. Sending `{ "pan": { "contains": "" } }` turns an exact-match lookup into "match every row."

```javascript
// WRONG — req.body shapes the filter; attacker controls the operators
const emp = await prisma.employee.findFirst({ where: req.body });

// RIGHT — validate to a known shape first, then build the filter yourself
const q = EmployeeQuery.parse(req.body);        // Zod: { pan: string }
const emp = await prisma.employee.findFirst({ where: { pan: q.pan } });
```

**Raw escape hatches.** Methods like Prisma's `$queryRawUnsafe` / `$executeRawUnsafe` (and the equivalents in other ORMs) bypass parameterisation entirely. Never feed them user input; use the tagged-template safe variant instead.

```javascript
// WRONG — unsafe raw with interpolated input
await prisma.$queryRawUnsafe(`SELECT * FROM employee WHERE name = '${name}'`);

// RIGHT — tagged template parameterises the value
await prisma.$queryRaw`SELECT * FROM employee WHERE name = ${name}`;
```

**Check:** `*Unsafe` raw methods, or any ORM `where`/`orderBy`/`select` assembled directly from a request object → `confirmed` if input is unvalidated.

### 2.3 Beyond SQL

The same "input became code" failure appears as NoSQL operator injection (Mongo `$where`, `$gt` smuggled via JSON), command injection (shelling out with input), and path traversal (reading `../../etc/...` from a user-supplied filename when serving an employee's uploaded KYC document). Apply the same rule: validate the shape, never interpolate input into an interpreter.

---

## 3. Validate every input at the boundary

### 3.1 Runtime schemas, not type annotations

TypeScript types vanish at compile time. A malformed request sails straight past them. Validate with a runtime schema (Zod, Yup, Joi, Pydantic) at **every** entry point:

- API route handlers and controllers
- Server Actions
- Webhook receivers (payment, KYC-provider callbacks)
- Form submissions
- URL path params, query strings, and headers you trust

```javascript
// A TypeScript type checks NOTHING at runtime
type NewEmployee = { name: string; pan: string };

// A schema actually rejects bad input before it reaches the DB
const NewEmployeeSchema = z.object({
  name: z.string().min(1).max(100),
  pan:  z.string().regex(/^[A-Z]{5}[0-9]{4}[A-Z]$/),   // PAN format
});
```

**Check:** a handler that reads `req.body`/`req.query`/`params` and uses it without a runtime-validation step → `needs_validation` at least; `confirmed` if that value reaches a query or sink.

### 3.2 Mass assignment

Spreading a request body into a create/update lets the caller set fields you never intended — `isAdmin: true`, `ctc: 9999999`, `kycVerified: true`.

```javascript
// WRONG — attacker adds { role: 'hr_admin', kycVerified: true }
await db.employee.update({ where: { id }, data: req.body });

// RIGHT — allowlist the writable fields explicitly
const { name, phone } = NewEmployeeSchema.parse(req.body);
await db.employee.update({ where: { id }, data: { name, phone } });
```

Always project to an explicit set of writable fields. Never pass a raw body as `data`.

---

## 4. Over-fetching and data minimisation

Even with authorization correct, returning *more columns than needed* is a leak and a DPDP concern.

- **Project explicitly.** `SELECT *` / a bare `findUnique` ships password hashes, full Aadhaar, and bank details to callers that asked for a name and photo. Use `select`/column lists.
- **Mask sensitive fields** at the query or serializer layer — return the last four of Aadhaar, not the whole number, unless the caller genuinely needs it.
- **Minimise by default.** Under DPDP, collecting or exposing personal data beyond the stated purpose is a finding in itself. The query is where minimisation is actually enforced.

```javascript
// WRONG — hands the browser the entire row
const emp = await db.employee.findUnique({ where: { id } });

// RIGHT — only what the screen needs
const emp = await db.employee.findUnique({
  where: { id },
  select: { name: true, designation: true, aadhaarLast4: true },
});
```

Passing whole records to client components is covered from the auth angle in [`authentication.md`](authentication.md) §5; here it is a query-design rule.

---

## Verdict rules for this checklist

| Observation | Verdict |
|-------------|---------|
| Record fetched by request-supplied id with no owner/role scope (IDOR) | `confirmed` |
| List/collection endpoint not scoped to caller's org/branch | `confirmed` |
| SQL built via string interpolation on request input | `confirmed` |
| `*Unsafe` raw query or ORM filter built from unvalidated request body | `confirmed` |
| Request input reaches a query/sink with no runtime validation | `confirmed` |
| Request body spread into `data` (mass assignment) | `confirmed` |
| Over-fetching / returning unmasked personal data beyond need | `confirmed` (flag DPDP) |
| ORM method whose internal sanitisation can't be confirmed from source | `needs_validation` |
| Injection/IDOR plausible but reachability unclear | `needs validation` |

Cross-references: [`authentication.md`](authentication.md) for the identity/ownership side of these gaps, and [`../../rules/evidence-gate.md`](../../rules/evidence-gate.md) for grading source-only findings.
