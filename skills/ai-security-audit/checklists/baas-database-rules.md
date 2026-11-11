<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Backend-as-a-Service Database Access Rules

When a team builds on Supabase, Firebase, or Convex, the database is reachable directly from the browser. There is no server tier in between to quietly enforce "this employee may only see their own payslip." The authorisation logic lives entirely in declarative rules — RLS policies, Firestore security rules, or per-function auth checks — and if those rules are weak or missing, the whole table is one HTTP request away from the public internet.

This is the single most common critical finding in assistant-generated and vibe-coded apps. Code generators happily emit a schema and wire up the client SDK, but they rarely finish the access-control story. The result is an HRMS where any logged-in user can pull every employee's CTC, PAN, and Aadhaar through the auto-generated REST API.

This checklist is source-only. You are reading migrations, `.sql` files, `firestore.rules`, `storage.rules`, and Convex function definitions — never a live project. If a policy's effect cannot be determined from the files in front of you (for example, the rules file isn't in the repo, or a `SECURITY DEFINER` function's body is external), record `needs_validation` rather than guessing. See `rules/evidence-gate.md`.

---

## 1. The exposure model: why "it has auth" is not enough

Two facts drive almost every finding here:

- **The anon / public key is meant to be public.** It ships in the client bundle. Possessing it grants nothing by itself — but it *does* let anyone reach the REST/SDK endpoints. Access is decided purely by the rules behind those endpoints.
- **A row that any authenticated user can read is effectively public to your whole user base.** On a self-service HR portal where anyone can sign up, "logged in" is not a meaningful trust boundary. The question is always *which rows* and *which columns*, scoped to *this specific user*.

Keep both in mind when reading every policy below. A rule that merely checks "is the caller authenticated" fails the second fact.

---

## 2. Supabase / PostgREST — Row-Level Security

Supabase exposes every table in the `public` schema through PostgREST. RLS is the only thing standing between a browser holding the anon key and the raw table.

### 2.1 RLS must be ON for every exposed table

Tables created through the SQL editor or a raw migration have **RLS off** unless you explicitly enable it. An exposed table with RLS disabled is world-readable and world-writable to anyone with the anon key.

Audit approach: enumerate every `CREATE TABLE` in the `public` schema and confirm a matching `ENABLE ROW LEVEL SECURITY`. A migration-time guard that sweeps the schema is a good defensive pattern to look for:

```sql
-- Defensive sweep: force RLS on anything in public that lacks it
DO $$
DECLARE t text;
BEGIN
  FOR t IN
    SELECT tablename FROM pg_tables WHERE schemaname = 'public'
  LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
  END LOOP;
END $$;
```

Verdict rule: an exposed `public` table with no `ENABLE ROW LEVEL SECURITY` anywhere in the migrations is `confirmed`. If you cannot see the full migration history (rules may live elsewhere), mark `needs_validation`.

### 2.2 RLS enabled but no policies = locked, not open

A subtlety that trips up reviewers: a table with RLS **on** and **zero policies** denies all access by default. That is safe. It is not a vulnerability — though it frequently indicates a feature that is silently broken (reads return empty, writes fail). Flag it as a correctness note, not a security finding.

### 2.3 Over-broad predicates — the real danger

The common failure is a policy that *looks* scoped but checks nothing meaningful. Both of these hand every row to every signed-in user:

```sql
-- BAD: literally everyone authenticated reads every payslip
CREATE POLICY payslip_read ON public.payslips
  FOR SELECT TO authenticated
  USING (true);

-- BAD: "is the caller logged in" is not ownership
CREATE POLICY payslip_read ON public.payslips
  FOR SELECT TO authenticated
  USING (auth.uid() IS NOT NULL);
```

A correct policy ties each row back to the caller:

```sql
-- GOOD: an employee sees only their own payslips
CREATE POLICY payslip_read_own ON public.payslips
  FOR SELECT TO authenticated
  USING ((SELECT auth.uid()) = employee_id);
```

Treat `USING (true)` and `USING (auth.uid() IS NOT NULL)` on `SELECT`, `UPDATE`, or `DELETE` as `confirmed` horizontal-access findings on any table holding personal or financial data. Cross-reference `api-authorization.md` and `data-isolation-and-lifecycle.md` for the IDOR framing — RLS is just access control expressed in SQL.

### 2.4 Missing `WITH CHECK` lets users rewrite ownership

`USING` governs which existing rows a statement may touch. `WITH CHECK` governs what the *new* row values are allowed to be. Omit `WITH CHECK` on `INSERT`/`UPDATE` and a user can reassign a record to someone else — or insert rows impersonating another employee.

```sql
-- BAD: no WITH CHECK — an employee can move a leave request onto a colleague's id
CREATE POLICY leave_update ON public.leave_requests
  FOR UPDATE TO authenticated
  USING ((SELECT auth.uid()) = employee_id);

-- GOOD: the row must still belong to the caller after the write
CREATE POLICY leave_update ON public.leave_requests
  FOR UPDATE TO authenticated
  USING ((SELECT auth.uid()) = employee_id)
  WITH CHECK ((SELECT auth.uid()) = employee_id);
```

An `INSERT` or `UPDATE` policy on a user-scoped table with no `WITH CHECK` is `confirmed`.

### 2.5 Sensitive columns on a self-updatable row

If employees can `UPDATE` their own row in a `profiles` or `employees` table, and that same table carries privilege or money columns, they can escalate themselves: set `role = 'hr_admin'`, flip `is_approver = true`, or bump `leave_balance = 999`. A row-scoped policy does **not** protect individual columns.

Two sound fixes to look for:

- **Split the sensitive fields out** into a table that PostgREST does not expose, and change them only through a vetted `SECURITY DEFINER` function that validates the request.
- **Use column-level grants** so the client can only touch benign fields:

```sql
REVOKE UPDATE ON public.employees FROM authenticated;
GRANT  UPDATE (display_name, phone, emergency_contact)
  ON public.employees TO authenticated;
-- role, ctc, pan_number remain off-limits to the client
```

A self-updatable table that mixes editable profile data with privilege/salary/KYC columns and lacks either mitigation is `confirmed`.

### 2.6 The forgotten tables

The main table usually gets a policy. Its companions often do not. Walk every table and specifically check:

- Join / mapping tables (`employee_departments`, `user_roles`).
- Audit and activity logs — these leak the most context when exposed.
- Metadata, attachment, and comment tables.

Each table reachable through the REST API needs its own policies. "The parent is protected" is never an argument for a child table in PostgREST.

### 2.7 `SECURITY DEFINER` functions bypass RLS

A `SECURITY DEFINER` function runs with the definer's rights and ignores RLS on the tables it touches. If such a function sits in `public`, the anon key can call it over RPC. Treat each one as a privileged endpoint and verify:

- It lives in a non-exposed schema (e.g. `private`), not `public`.
- It pins `SET search_path = ''` to block search-path hijacking.
- It re-checks the caller's identity and authorises the action internally — it cannot lean on RLS, which it has already bypassed.

A `public` `SECURITY DEFINER` function with no internal auth check is `confirmed`. If the body isn't in the repo, `needs_validation`.

### 2.8 Storage buckets are tables too

Supabase Storage sits on top of the `storage.objects` table, so it needs policies of its own. Leave them off and every signed-in account can read, replace, or wipe any stored object — a colleague's cancelled-cheque scan from vendor KYC, say. Confine each object path to a folder keyed on the owner's UID:

```sql
CREATE POLICY kyc_upload_own ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'kyc-docs'
    AND (storage.foldername(name))[1] = (SELECT auth.uid())::text
  );
```

Buckets holding KYC, payslips, or ID documents with no path-ownership policy are `confirmed`.

---

## 3. Firebase / Firestore — Security Rules

Firestore applies no access control by default beyond what `firestore.rules` declares. The same two failure modes as RLS appear, in a different syntax.

### 3.1 The rules you must never ship

```
// BAD: the entire database is open to the world
match /{document=**} {
  allow read, write: if true;
}

// BAD: any authenticated user touches everything
match /payslips/{id} {
  allow read, write: if request.auth != null;
}
```

Bind access to identity instead:

```
// GOOD: a document only its owner can read or write
match /employees/{uid} {
  allow read, write: if request.auth.uid == uid;
}
```

`allow read, write: if true` is `confirmed` on any non-public collection. `if request.auth != null` on sensitive data is `confirmed` for the same reason as Supabase's `auth.uid() IS NOT NULL`.

### 3.2 Field-level control on writes

Document-level ownership still lets the owner set *any field*. On a self-service profile that means `isAdmin: true` or `leaveBalance: 999`. Constrain which keys a write may change:

```
match /employees/{uid} {
  allow update: if request.auth.uid == uid
    && request.resource.data.diff(resource.data)
         .affectedKeys()
         .hasOnly(['displayName', 'phone', 'emergencyContact']);
}
```

### 3.3 Subcollections are not covered by the parent

This is the most-missed Firestore trap. A rule on `/employees/{uid}` does **not** extend to `/employees/{uid}/salaryHistory/{doc}`. Each subcollection needs its own `match` block. An unmatched subcollection either inherits a permissive catch-all (bad) or is silently denied (broken). Enumerate every subcollection path in the app and confirm an explicit rule. A sensitive subcollection with no rule of its own, under a permissive `/{document=**}`, is `confirmed`.

### 3.4 Validate types, sizes, and server time

Rules are also your write-validation layer. Enforce shape so a client cannot store a 5 MB string as a "name" or backdate a record:

```
match /auditLog/{id} {
  allow create: if request.auth != null
    && request.resource.data.actorName is string
    && request.resource.data.actorName.size() <= 80
    && request.resource.data.createdAt == request.time;  // server clock, not client
}
```

### 3.5 Roles via custom claims, not a lookup document

For role checks, prefer `request.auth.token.role` (a custom claim set by trusted server code) over reading a `/users/{uid}` document inside the rule. Claims can't be forged by the client and cost no extra read. A rule that decides "is HR admin" by reading a user document the client can also write is a privilege-escalation path — `confirmed` if the same user can edit that document.

### 3.6 Cloud Storage rules

On any upload path, a `storage.rules` block should pin down three facts: the declared `request.resource.contentType`, the `request.resource.size`, and who owns the destination path. Drop any one and an attacker can smuggle in an executable dressed up as a payslip, or write into a colleague's folder. An upload path that skips the content-type, size, or ownership guard is `confirmed`.

---

## 4. Convex

Convex has no declarative rules file — authorisation lives inside each function, so it must be read function by function.

- **Every public `query` and `mutation` resolves the caller** via `ctx.auth.getUserIdentity()` and handles the unauthenticated (`null`) case explicitly. A public function that skips this is open to anyone.
- **Authentication is not authorisation.** After identifying the caller, each mutation must confirm the caller actually owns the specific document being changed — not merely that *someone* is logged in. A mutation that loads a record by id and edits it without an ownership check is a `confirmed` IDOR.
- **Internal-only logic must use the internal variants** — `internalQuery` / `internalMutation` / `internalAction`. Anything declared as `query` / `mutation` is publicly callable by name, regardless of whether the UI ever calls it. A helper that assumes it's unreachable but is exported as `mutation` is `confirmed`.

---

## 5. Reviewer quick-reference

| Platform | Pattern to flag | Correct shape | Verdict when present |
|----------|-----------------|---------------|----------------------|
| Supabase | Exposed `public` table, no `ENABLE ROW LEVEL SECURITY` | RLS on + scoped policies | `confirmed` |
| Supabase | `USING (true)` / `USING (auth.uid() IS NOT NULL)` | `USING (auth.uid() = owner_id)` | `confirmed` |
| Supabase | INSERT/UPDATE policy, no `WITH CHECK` | add matching `WITH CHECK` | `confirmed` |
| Supabase | Self-updatable row with role/CTC/KYC columns | column grants or split table | `confirmed` |
| Supabase | `public` `SECURITY DEFINER` fn, no internal auth | `private` schema + `search_path=''` + checks | `confirmed` / `needs_validation` |
| Supabase | Storage bucket, no path-ownership policy | `foldername(name)[1] = auth.uid()` | `confirmed` |
| Firestore | `allow ... : if true` on non-public data | bind to `request.auth.uid` | `confirmed` |
| Firestore | `if request.auth != null` on sensitive data | ownership predicate | `confirmed` |
| Firestore | Subcollection with no explicit `match` | per-subcollection rules | `confirmed` |
| Firestore | Role decided by a user-writable doc | custom claims | `confirmed` |
| Convex | Public fn without `getUserIdentity()` / ownership check | auth + ownership in-function | `confirmed` |
| Convex | Internal helper exported as `mutation`/`query` | `internalMutation` / `internalQuery` | `confirmed` |
| Any | Rules file / fn body not in repo | — | `needs_validation` |

See also: `api-authorization.md` and `data-isolation-and-lifecycle.md` (IDOR and horizontal/vertical access), `secrets-and-config.md` (service-role key leakage — a service-role key in client code or a committed `.env` bypasses all RLS and is a critical standalone finding), `india-pii-hotspots.md` (PAN/Aadhaar/UAN exposure through unscoped tables), and `rules/evidence-gate.md`.
