<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# API authorization (BOLA, BOPLA, BFLA, business flows)

Broken authorization is the most common critical finding in real VAPT work, and scanners almost never find it. Spend reasoning here.

## When to use

Any REST, GraphQL, RPC, server action, or BaaS-backed API where one principal must not reach another principal's objects, fields or functions.

## Build the authorization matrix first

From recon, write a small table for the unit: **resource x action x who may do it x where it is enforced (file:line)**. Every row without an enforcement location is a candidate to trace. This matrix also goes into the report appendix when it helps the owner.

## BOLA / IDOR (API1:2023)

For every route or resolver that takes an object identifier (path, query, body, header, GraphQL argument, file key, signed-URL key):

1. Where does the identifier come from? Anything the client sends is attacker-controlled, including hidden fields and values the UI "never changes".
2. Between the entry and the data access, is there a check binding the object to the caller? Ownership (`where: { id, ownerId: user.id }`), tenant scope (`orgId` from the **session**, not the request), role plus scope, or an RLS policy that uses `auth.uid()`.
3. Is the check on **every** path to the same object: list, get, update, delete, export, download, search, bulk, nested resources (`/orgs/:orgId/users/:userId` where only `orgId` is checked), and background jobs triggered by the user?
4. Does the check use the right identity? Common breaks: trusting `userId` or `orgId` from the body or a header; checking the parent but not the child; checking on read but not on write; caching an authorized response under a key without the user.
5. File and document storage: object keys or IDs guessable or sequential, signed URLs that never expire or are not bound to the user, storage buckets readable without auth.

Confirmed when the trace shows a caller-controlled identifier reaching a data access with no binding check, and the returned or changed object belongs to someone else. Sequential or guessable IDs raise likelihood; they are never the finding on their own.

## BOPLA / mass assignment / excessive data exposure (API3:2023)

- **Writes:** is the request body spread or bound directly into a model (`Object.assign(user, req.body)`, `Model.update(req.body)`, `@ModelAttribute`, Rails `permit!`, Django `ModelSerializer` with `fields = '__all__'`, Mongoose `findByIdAndUpdate(id, req.body)`)? Can a user set `role`, `isAdmin`, `orgId`, `ownerId`, `price`, `status`, `verified`, `salary`, `approved`?
- **Reads:** does the API return whole records (password hashes, tokens, internal flags, other users' PII, salary, Aadhaar/PAN) and rely on the UI to hide fields? Check serializers, DTOs, `select` lists, GraphQL types.
- **GraphQL:** field-level auth on sensitive fields, introspection in production, nested queries that reach objects without checks, batching and aliasing that bypass rate limits.

## BFLA (API5:2023)

- Admin or staff functions reachable by normal users: routes under `/admin`, `/internal`, `/manage`, server actions exported from admin files, GraphQL mutations without role checks.
- Role checks done only in the frontend (hidden buttons, route guards in React/Angular/Vue) with no server check.
- HTTP method confusion: `GET` protected but `POST`/`PUT`/`DELETE`/`PATCH` on the same path not, or method override headers.
- Feature flags or plan checks enforced only on the client.

## Sensitive business flows (API6:2023)

Flows where automation or repetition causes harm: OTP send and verify, password reset, referral credits, coupon redemption, leave or expense approval, payout requests, bulk export, account creation. Check for missing server-side limits, missing one-time-use enforcement, and state that can be replayed.

## Authentication on APIs (API2:2023)

Covered in depth by [web-protocol-and-auth.md](web-protocol-and-auth.md). In this unit just confirm: every non-public route sits behind real verification (signature checked, expiry checked, audience checked), and tokens are not long-lived master keys shared across users.

## Inventory (API9:2023)

Old versions (`/v1/` still served next to `/v2/`), debug or test routes, forgotten admin APIs, mobile-only endpoints with weaker checks. The wildcard hunter should list every route registered in code and compare it with the routes the frontend uses.

The sharp case is a **deprecated or left-over endpoint that is still mounted and reachable but skips the current authorization**. When authz is tightened in a new version, the old one frequently keeps the loose checks it shipped with — the `/v2/` handler enforces tenant scope and role, while `/v1/` of the same resource still answers and does not. Watch for: previous API versions left in the router; debug, health, metrics, `/actuator`, GraphQL playground, or admin consoles bound alongside the app; B2B, partner, or legacy integration interfaces that predate the current session model and authenticate with a weaker scheme (or none); and internal-only handlers that are in fact routable from outside. For each, confirm two things from source — that the route is actually registered/reachable (not dead code behind a disabled flag), and that it reaches the same sensitive state as the current path without the current gate. A reachable deprecated endpoint that performs a sensitive read or mutation while bypassing the authorization the live endpoint enforces is `confirmed`; if reachability depends on deployment routing you cannot see in the repo, `needs_validation` naming the route and the missing routing fact.

## Typical smallest fixes

- Scope the query by the session identity: `findFirst({ where: { id, ownerId: session.userId } })`, not a separate check that can be forgotten.
- One shared authorization helper or policy used by every route for that resource; delete the per-route copies.
- Explicit allowlists of writable fields (DTOs, `pick`, strong params) instead of binding the whole body.
- Serializers that return only the fields the caller may see.
- Server-side role checks on every admin route, in the router group, not per handler.
- Regression test: user A requests user B's object and gets 403/404.
