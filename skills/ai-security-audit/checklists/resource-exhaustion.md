<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Resource Exhaustion and Availability Hunting

> **Source-only note (v1):** this skill never runs the target. Anywhere the text below mentions a "bounded local test", "local fixture" or "sandbox", resolve the point from the source itself; when the source cannot answer it, record `needs_validation` together with the precise fact you still need. Reference sibling guides through `checklists/...` paths and apply the evidence gate in `rules/evidence-gate.md`.

## Scope of this guide

Open this file when an untrusted request, message, file, piece of tenant state, or agent task can burn CPU, memory, disk, sockets, worker slots, paid API budget, or queue space — or can wedge, deadlock, or crash a service other users depend on. The point throughout is to separate a *source-reviewable availability bug* from an ordinary performance complaint. The hard rule: you never prove one of these by stressing a shared or live system.

Two neighbours: `memory-safety-and-binary.md` owns memory-integrity corruption, and `protocols-rpc-and-messaging.md` owns broker delivery semantics. But a crash an untrusted input can reach belongs *here* whenever the blast radius is shared, even if the parser that crashes is documented elsewhere.

## Baseline rules of engagement — paste these into each agent prompt covering this area

```
- Demand three things together: a path from input to cost, a bound that is missing or ineffective, and harm to someone else — another user, a shared service, a safety function, or the operator's own bill. Work that only slows the requester's own process is not a service vulnerability.
- "There's no rate limit" is not a finding on its own. Before you call a path unbounded, check body/message/file size caps, concurrency ceilings, queue depth, deadlines, database constraints, upstream gateway limits, and per-tenant quotas.
- No stress tests, no saturation runs, no production load. Reason about asymptotics, use tiny boundary fixtures, mock the paid calls, apply hard local CPU/memory/time limits, and write deterministic cancellation tests.
- Spell out attacker cost, service work, whether it persists, its scope, and how recovery happens. One cheap input with superlinear or sticky shared effect is a different animal from needing sustained volume.
- Mark `confirmed` when a source-visible bound failure is shown safely. Mark `needs_validation` when upstream caps, deployed topology, autoscaling, paid quota, or recovery behaviour sit outside the repo.
```

## Attack family A — amplification: small input, large work (subagent_type: `general`)

**Superlinear parsing, matching, or evaluation**
A small, accepted input triggers catastrophic regex backtracking, deeply nested parsing, recursive validation, symbolic evaluation, graph walking, template expansion, or adversarial sort/hash collisions. Work out the accepted depth or cardinality and the complexity class, then plot a bounded growth curve locally. *Example:* a PAN-format validator built from a backtracking regex that goes quadratic on a crafted 40-character string in a KYC upload field.

**Decompression and representation blow-up**
Compressed, sparse, nested, aliased, or cleverly encoded input expands far past the size that was checked on the wire or on disk — zip bombs, decompression bombs, billion-laughs XML, pixel-flood images, malicious fonts, protocol compression tables. Verify the size check happens *after* each expansion and at every parser stage, not just at ingress.

**Database and downstream fan-out**
A tiny request becomes a broad table scan, a pathological join, a large fan-out, an unbounded sort or aggregation, or a burst of downstream calls when nothing caps query nesting, the number of filter values, page size, or how far expansion fields reach. Confirm the resource scope isn't one that authorization deliberately grants anyway. *Example:* a payroll report endpoint accepts `?expand=employees.payslips.deductions` with no depth limit, turning one call into millions of row reads.

## Attack family B — things that pile up (subagent_type: `general`)

**Unbounded buffering and cardinality**
Request bodies, out-of-order stream fragments, uploads, sessions, distinct cache keys, metrics label values, log fields, subscriptions, or pending jobs grow with no per-item *and* no aggregate cap. Check that cleanup and expiry fire on disconnect, timeout, cancellation, and partial parse. *Example:* a per-employee metrics label keyed by UAN creates unbounded cardinality that eventually OOMs the metrics backend.

**Leaked descriptors, handles, and temp resources**
Malformed or cancelled work skips its cleanup and holds on to sockets, file handles, DB cursors, timers, subprocesses, temp files, or object references. Confirm the leak accumulates across bounded local iterations and drains a shared pool.

**Work that keeps running after cancellation**
A client timeout, a dropped connection, a cancelled job, or a failed authorization returns control to the caller but leaves database, model-inference, network, or worker activity still churning in the background. Follow how cancellation and deadlines flow down into each layer the request reached.

## Attack family C — quotas and scheduling (subagent_type: `general`)

**Expensive work before authentication**
Heavy parsing, key lookups, cryptography, decompression, or outbound requests run *before* the request is authenticated and before the first size/rate gate. Weigh the requester's minimal effort against the shared service cost, and check what the upstream edge already limits.

**Quota accounting that the attacker can steer or reset**
Accounting is keyed on something the attacker influences — IP, route, tenant, key prefix, task ID — letting one principal escape its own budget or spend another's. Review integer overflow in counters, distributed races, retry and reconnect behaviour, and account-switching. *Example:* a free-tier API quota keyed by `X-Forwarded-For` which the caller sets directly, giving unlimited verification calls.

**Starvation of workers, pools, and scheduling priority**
Jobs that are either low-ranked or steered by the attacker keep hold of shared locks, worker threads, DB connection-pool slots, event-loop turns, or scheduler priority that unrelated users need. The finding needs a path that defeats queue/concurrency fairness or clings to a slot past its deadline.

## Attack family D — failure and recovery (subagent_type: `general`)

**A fatal error or deadlock an untrusted input can reach**
Untrusted input drives a `panic`, an abort, a fatal assertion, an exception nobody catches, a `process exit`, a deadlock between locks, or a loop that never terminates inside a shared process. Establish the supervisor's scope — does one worker die, or the whole service? A restartable isolated worker lessens the blow, yet the underlying flaw is still present.

**Retry storms and fail-open amplification**
A timeout, a dependency error, a half-processed message, or a failed health check sets off synchronized or unbounded retries with no jitter, ceiling, circuit breaker, or dedup. Show that one bounded failure source can snowball into persistent aggregate work.

**Poison records and head-of-line blocking**
A single malformed record or message keeps failing repeatedly at the front of a shared queue — or at the front of a partition, a startup scan, a migration, or a recovery loop. Review the skip/quarantine policy, offset handling, and whether other tenants are stuck behind that same stalled item.

**Recovery and capacity rollback that is itself unsafe**
Any path that restarts, restores, falls back, or cleans up may rebuild state with no bound, disregard the quotas now in force, or reload the exact input that set off the failure once more. Recovery correctness is part of availability, not an afterthought.

## Universal moves (apply across all four families)

- Lay out a table mapping each input to the resources it consumes: the first size/cardinality that gets accepted, any work performed ahead of auth, downstream fan-out, what persists, which shared pool is touched, who owns the limit and the cleanup, and how recovery works.
- Hold aggregate caps against per-object caps side by side. Ten thousand valid one-byte items can slip under a per-message limit while still draining state that spans the whole tenant or the whole process.
- Confirm things only within a sealed-off fixture that clamps CPU, memory, and time hard and steps growth up in tiny increments. Stub out every external and paid call, and halt as soon as the absent bound or the broken cancellation surfaces.

## Checks to clear before you file ANY finding in this guide

1. Spell out the untrusted input, the requester's work, the service amplification or retained resource, the shared blast radius, and the recovery story. A missing limit with no concrete shared impact is hardening, not a finding.
2. Confirm no source-visible bound — upstream edge, parser, queue, tenant quota, or framework default — already stops the path. Controls you can only see at deploy time make it `needs_validation`.
3. For superlinear behaviour, fix the accepted complexity and show bounded local growth. For a leak, show repeatable retention past the point cleanup should have run. For a fatal path, identify the process/supervisor isolation.
4. Rank by low requester effort, unauthenticated reachability, cross-tenant scope, persistence, and weak recovery — never by whether you managed to degrade availability for real.
5. Give back `confirmed` only when safe local proof pairs with a meaningful shared effect. Otherwise give back `needs_validation`, and spell out the specific recovery observation, quota, deployed topology, or upstream limit that an owner has yet to verify.
