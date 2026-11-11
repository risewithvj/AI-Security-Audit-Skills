<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Data Isolation and Lifecycle Hunting

> **Source-only note (v1):** nothing in this skill runs the target. Where a step below mentions a "bounded local test", a "dummy tenant" or a "fixture", answer it from the code; when the code alone cannot answer it, the verdict is `needs_validation` and you name the fact you could not see. Keep the `checklists/...` path convention and route every finding through the evidence gate in `rules/evidence-gate.md`.

## What this file is for

A single record in an Indian HR/payroll product rarely lives in one place. A payslip row is written to Postgres, indexed in search, cached in Redis, counted in an analytics table, streamed to a log sink, zipped into a Form-16 export, and copied into last night's backup. Each of those copies may carry its own access rules and its own retention clock. **This checklist traces a single data item across each of its copies and each change of state** — tenant separation, row-level control, retention and deletion, backups, cache and search leakage, sensitive data in logs, and data residency.

Use it when the target:

- holds multi-tenant or access-controlled records (employee masters, salary structures, KYC documents);
- fans data out into search, cache, analytics, previews, replicas or backups;
- hands out object links, signed URLs or portability packages;
- migrates schemas or backfills ownership columns;
- or makes a promise about deletion, consent withdrawal, revocation or retention.

Two neighbouring files carry related work: `core-attack-classes.md` owns endpoint-level access control (the IDOR on a single request), and `cloud-and-deployment.md` owns provider-level storage configuration (the bucket policy, the KMS grant). This file owns the *lineage between them*.

For a large codebase, carve the review along the data's physical homes: primary datastore, cache/search layer, object/blob storage, analytics and logging, export/backup pipeline, deletion/revocation flow, and in-flight migrations. Work one lane at a time.

## Operating rules for this domain (paste into every subagent prompt here)

```
- An org_id or employee_id column on a row is a label, not a wall. For every read AND
  every write, point to the WHERE clause, cache key, object path, RLS policy or scope
  that actually binds the row to the caller's tenant.
- Follow the copies. Data that is safe in the primary table can leak through search,
  cache, analytics, exports, previews, logs, replicas and backups, each governed by its
  own ACL and its own retention window.
- Deletion, consent withdrawal and revocation are contracts over ALL copies in scope:
  live rows, history, cache, index, exports, restores and queued jobs — not just the
  primary row.
- A retention setting or a privacy toggle is not, by itself, a vulnerability. You need a
  real access boundary (or a real deletion/revocation promise) PLUS an unauthorised reader
  or a later operation that defeats it.
- Return `confirmed` only when the lineage is fully visible in source or proven with two
  dummy tenants locally. Return `needs_validation` when CDN behaviour, object-store policy,
  replica lag, retention config or backup access sits outside the repo.
```

---

## Lane 1 — Tenant and object isolation

The question in this lane is always the same: between the caller and the row, what enforces the boundary, and does every path honour it?

| Weakness | What to look for | Indian HR/payroll illustration |
|---|---|---|
| **Unbound tenant/owner on a data path** | A read, list, count, update, delete or bulk operation that locates a record without pinning it to the authenticated org/employee — or that takes the identity from a request body it should not trust. Diff the interactive path against nested-relationship, background-job, admin, importer and legacy paths. | `GET /payslips/:id` scopes by `org_id`, but the "email my payslip" cron job and the CSV importer look up by `id` alone, so an employee of one company receives another company's salary slip. |
| **Namespace / composite-key collision** | Cache keys, blob paths, uniqueness constraints, search document IDs, temp filenames or dedup keys that leave out tenant or environment. Two principals then collide on one logical key even though their rows have distinct owners. | `cache.get("payslip:" + employeeId)` without `org_id`; employee #42 at Company A and employee #42 at Company B share a Redis slot, so one sees the other's net pay. |
| **Policy vs. query disagreement** | Row-level security, ORM default scopes, authorization filters and raw/service-role clients applying *different* predicates. Inspect joins, aggregates, aliased subqueries, views, transactions, `unscoped`/admin clients and error branches where tenant context is dropped. | RLS enforces `org_id = current_setting('app.org')` on `employees`, but a nightly PF-reconciliation script connects as the superuser role (RLS bypassed) and a reporting view joins `salaries` without re-applying the policy. |
| **Blob / signed-reference overreach** | Share links, signed URLs, version IDs, attachment IDs or object keys that grant operations or a namespace wider than the issuer's own access, or that stay valid after the backing ACL changes. The grant has to pin down tenant, expiry, audience, the precise object and version, and the operation itself. | A pre-signed S3 URL for an Aadhaar scan is issued with a 7-day TTL and no object-version pin; after the employee resigns and the ACL is tightened, the old URL still downloads the KYC document. |

Isolation hunting usually pays off fastest at the *non-interactive* entrances — service-role DB clients, queue workers, migrations, global uniqueness checks and cache-key construction — because those omit the request-scoped identity that the UI endpoints carry.

```js
// Smells: tenant label present on the row but absent from the WHERE clause.
async function getPayslip(req, id) {
  // BAD: id alone — any authenticated user reaches any org's payslip
  return db.query('SELECT * FROM payslips WHERE id = $1', [id]);
}
async function getPayslipScoped(req, id) {
  // Better: bind to the caller's org on the read itself
  return db.query(
    'SELECT * FROM payslips WHERE id = $1 AND org_id = $2',
    [id, req.auth.orgId]
  );
}
```

---

## Lane 2 — Derived copies and quiet disclosure

A record can be perfectly guarded in the primary table and still leak through a copy that was built with weaker rules or that never got the memo when the original changed.

**ACL and lifecycle drift in search, cache and index.** When a primary record's permissions or lifecycle change, every derived copy — the search document, the Redis entry, the vector embedding, the thumbnail, the RSS/feed item, the preview card, the materialised view — must be re-filtered or invalidated. Check both ingestion-time filtering *and* retrieval-time filtering, and check that invalidation actually fires. *Example:* an employee is moved out of the "Finance" department, but the ElasticSearch index still tags their salary document with the old department ACL, so a Finance viewer keeps finding it in autocomplete.

**Logs, traces, analytics and diagnostics as a second reader.** Treat every sink that receives private content as a reader with its own (often broader) audience and longer retention. Confirm the real data class and a realistic reader before reporting — a public employee code or an operator-only debug line under the intended policy is not a leak; a PAN, an Aadhaar number, a bank account or a bearer token written to a log that support, analytics or an external APM can read, is. *Example:* a Flask view logs the full request body of the salary-revision API, so Aadhaar and PAN land in CloudWatch where the whole ops team and a third-party log aggregator can read them — a DPDP safeguard failure, not just untidy logging.

```python
# BAD: dumps PAN/Aadhaar/bank details straight into the log sink
app.logger.info("salary revision payload: %s", request.get_json())

# Better: log an identifier and an outcome, never the sensitive body
app.logger.info("salary revision", extra={
    "employee_ref": emp.public_ref,   # non-sensitive surrogate
    "approved_by": approver.id,
    "status": "queued",
})
```

**Enumeration and aggregate oracles.** A count, a filter, an ordering, a distinct error, a uniqueness-constraint response, a timing difference or a notification behaviour can disclose protected state even when the record itself is hidden. Require a concrete confidential predicate plus an observable distinction — not generic response variance. *Example:* the "invite employee" form returns "email already registered" versus "invitation sent", letting an outsider enumerate which people work at a given company; or a salary-band filter that returns a count of `0` vs `1` reveals whether a named colleague earns above a threshold.

---

## Lane 3 — Export, backup, restore and migration

Bulk and administrative paths are where scope silently widens: one authorization check guards the *request*, but the *artifact* it produces or consumes was assembled with different rules.

**Export / backup scope creep.** An export, snapshot, DPDP data-portability package, generated report or backup pulls in other tenants, object fields the requester cannot see, soft-deleted rows, secret values or history above their access. Authorize each item *after* selection, and separately authorize the download of the finished artifact. *Example:* a manager's "download my team's attendance" export is built from a query that forgot the manager's `team_id` filter and returns the whole company, then the ZIP is served from a guessable URL.

**Import / restore authority creep.** A restore or import sidesteps the validation, uniqueness, ACL, schema or ownership rules, clobbers live resources, or re-creates rows in a tenant the requester cannot write to. Treat archive contents as untrusted input and authorize the *resulting* operation — never trust the record's prior provenance. *Example:* an HR admin uploads a "restore employees" JSON whose `org_id` values point at another company; the importer honours the embedded IDs and injects records into a tenant the admin has no rights over.

**Migration defaults and ownership confusion.** Old rows that predate a `tenant_id`/ACL/lifecycle column, incompatible IDs that collide, or a partial rollout in which the newer and older readers each fall back to a different default. Walk the backfill, the dual-write/dual-read logic, backward-compatibility branches, rollback and resumed-after-crash migration paths. *Example:* a migration adds `org_id` with a default of the first company created; legacy payslip rows all inherit that org, exposing historical salary data to the wrong tenant until the backfill finishes.

**Backup and replication boundary drift.** Support snapshots, restore/staging environments, replicas in another region, storage accounts and encryption keys that carry a wider identity or tenant scope than the primary data — and, for DPDP/data-residency, a copy that lands outside India when the policy requires it to stay in-country. Source can confirm only what is in the repo (the replication config, the region constant, the bucket region); hosted access, actual retention and real replica placement are `needs_validation`. *Example:* the primary RDS instance is in `ap-south-1`, but a read replica and the automated snapshot copy are provisioned in `us-east-1`, moving KYC data abroad — a residency breach visible in IaC but needing operator confirmation of the live state.

---

## Lane 4 — Deletion, revocation and the rest of the lifecycle

A deletion or a consent withdrawal is only honoured if *every* copy in the stated boundary honours it. These are the classic ways a "deleted" record keeps living.

- **Soft-delete / tombstone bypass.** A direct lookup, search hit, traversal across a relation, an object link, a restore path or a background processor ignores the `deleted_at`/status predicate and still returns or acts on the record. Also check whether a soft-deleted identifier can be *re-registered* while references to the old one survive. *Example:* an employee is off-boarded (`status = 'deleted'`), but the payroll-run job selects `WHERE active IS NOT false` and pays them one more cycle; separately, their old email is re-used for a new joiner who inherits dangling leave-balance rows.

- **Stale authorization through a derived copy.** Removing a membership, tightening an ACL, withdrawing DPDP consent, revoking a token or downgrading a role fails to invalidate the sessions, caches, push subscriptions, queued jobs or materialised data that keep authorising future operations. *Example:* an employee withdraws consent to share data with a background-verification vendor, but a cached consent flag and an already-enqueued webhook still push their KYC to the vendor an hour later.

- **Retention / queued-work overrun.** The primary row is deleted on time, yet queued processors, retries, exports, analytics rollups or generated artifacts re-create or retain the data past the promised window. Look for idempotent deletion and tombstone propagation into those downstream systems. *Example:* a resigned employee's record is purged after the DPDP retention period, but a monthly analytics snapshot and a retry-stuck "send Form-16" job still hold their PAN and salary.

- **Restore re-introduces disallowed state.** A backup, undo, undelete or replica recovery brings back permissions, memberships, credentials or data that the policy in force today no longer permits. Re-authorize restored state and re-apply every lifecycle change made *after* the snapshot. *Example:* restoring last month's backup after an incident resurrects three terminated accounts and a revoked API key, re-granting access that compliance had deliberately removed.

---

## Cross-cutting techniques (use alongside every lane above)

- **Draw the lineage for one record.** Pick a single protected row — say, one employee's salary structure — and sketch its primary write, read queries, cache entry, search document, emitted events, export artifact, backup copy, deletion and restore. At every edge, write down the principal and the tenant. Gaps in the drawing are your findings.
- **Replay with two dummy tenants.** Drive the same local service methods as two fabricated orgs, then repeat the drive *after* an ACL change, a deletion, an account switch and a restore. Watch for cross-visibility at each step. Never use real employee, PAN, Aadhaar or bank data for this — synthesise fixtures.
- **Start at the back doors.** Service-role/bypass DB clients, queue workers, migrations, global uniqueness checks and cache-key builders are where request-scoped identity most often goes missing. Begin there, not at the polished REST endpoint.

---

## Before you report anything from this file

Every finding must clear all five:

1. **Name the five parts.** The attacker or lower-trust principal; the protected data or lifecycle state; the affected owner/tenant; the alternate copy or operation involved; and the resulting unauthorised disclosure or mutation.
2. **Show policy *and* the gap.** Cite the intended source-of-truth (the RLS policy, the scope, the retention rule) and the exact path that omits or contradicts it. Confirm no other layer quietly enforces the same tenant/lifecycle condition.
3. **Prove it locally and minimally.** Use dummy tenants and non-sensitive fixtures to demonstrate the cross-scope read or the stale-lifecycle behaviour. Stop at the smallest observable record or operation that proves it — do not exfiltrate.
4. **Escalate what you can't see.** If the proof needs external cache behaviour, object-store policy, replica placement, analytics access, backup access or a retention window that isn't in the repo, mark it `needs_validation` and state the exact owner-observed check that would settle it.
5. **Grade honestly.** Return `confirmed` only with complete, source-visible (or locally proven) lineage and a concrete boundary impact. Otherwise return `needs_validation` with the precise unresolved fact — the storage policy, the ACL, the invalidation step, the retention window or the restore behaviour you could not confirm.
