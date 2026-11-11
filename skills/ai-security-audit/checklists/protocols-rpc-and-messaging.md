<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Protocols, RPC, and Messaging Hunting

> **Source-only note (v1):** this skill never runs the target. Anywhere the text below mentions a "bounded local test", "local fixture" or "sandbox", resolve the point from the source itself; when the source cannot answer it, record `needs_validation` together with the precise fact you still need. Reference sibling guides through `checklists/...` paths and apply the evidence gate in `rules/evidence-gate.md`.

## Scope of this guide

Open this file whenever the codebase speaks a wire protocol beyond plain HTTP request/response: gRPC and streaming RPC, GraphQL transports, Thrift, Cap'n Proto, Protobuf, hand-rolled binary framing, webhooks, and anything riding a broker — queues, topics, pub/sub, event buses. The questions here are about *who* the peer really is, *what* a decoded message actually means, how it is routed, and whether it can be replayed, reordered, or duplicated against the application's intent.

Three neighbours divide the remaining work:

| Concern | Where it lives |
| --- | --- |
| Parser memory corruption on the wire bytes | `memory-safety-and-binary.md` |
| HTTP request framing, headers, auth smuggling | `web-protocol-and-auth.md` |
| Availability impact of any of the above | `resource-exhaustion.md` |

For a large platform, slice the review one path at a time: by producer/consumer pair, by whether the peer is external or an internal service, and by message style — synchronous unary RPC, long-lived stream, or fire-and-forget async.

## Baseline rules of engagement — paste these into each agent prompt covering this area

```
- The word "internal" authenticates nothing. For each hop, state the peer identity and trace exactly how it becomes the principal the authorization check uses.
- Passing schema validation only proves shape. It says nothing about who sent the message, what resources they may touch, what order it arrived in, or whether the values are safe. Follow each decoded field to its policy decision and its side effect.
- A broker's delivery promise is not the application's promise. Record the retry, ordering, acknowledgement, dedup, and transaction semantics in writing before you reason about any state change.
- A disagreement finding needs two real consumers (or two schema versions, or two wire encodings) AND one decoded value whose difference matters to security.
- Mark a path `confirmed` only when the source is complete end to end and you have a bounded local producer/consumer test. Mark it `needs_validation` when broker ACLs, mesh identity, topic bindings, or cross-version compatibility live outside the repo.
```

## Attack family A — how the bytes are read (subagent_type: `general`)

**Parsers that disagree on boundaries or canonical form**
Two components read the same frame differently: length fields, compression, repeated fields, unknown fields, character encoding, integer width, Unicode normalization, or whether the envelope or the body wins. Line up the generated stub against any hand-written parser, the gateway against the backend, one language binding against another, the old version converter against the new. The finding exists only when a decoded principal, resource, or operation diverges.

**Unions, enums, and defaults landing in the wrong branch**
An unknown enum variant, an absent discriminator, a protobuf zero-value, or a backward-compat mapping slips into a code path that assumed an already-validated case. Read the dispatch: is it exhaustive? What does the `default` branch do? How does a consumer built against last quarter's schema interpret a field added this quarter? *Example:* a payroll event carries `approval_status`; an old consumer that never heard of the new `ESCALATED` value treats the unknown enum as its zero-value `APPROVED` and releases the salary revision.

**Envelope metadata trusted over body content (or vice versa)**
Authorization keys off routing headers or envelope fields that look trustworthy, while the handler then acts on a *different* tenant, account, subject, or sender named in the body. Decide which source is authoritative and prove the client cannot set it. *Example:* an RPC envelope carries the authenticated `org_id`, but the handler reads `payload.employee.org_id` when fetching the payslip — a tenant can then request another company's records.

## Attack family B — RPC identity and authorization (subagent_type: `general`)

**Interceptor coverage that skips methods or message types**
The authn/authz interceptor fires on unary calls but not on streams, or not on reflection, health, gateway-transcoded REST paths, legacy compat services, or on each individual message inside a stream. Enumerate every method registration and every route, then confirm the same guard reaches all of them.

**Channel identity confused with application principal**
mTLS, SPIFFE/workload identity, a bearer token in metadata, a forwarded-identity header, or broker credentials authenticate the *connection* — but then a field supplied by the caller selects which tenant or user is in play. A deterministic policy has to bind the claimed principal to the identity of the channel; trusting that field is never acceptable.

**Authorization checked once for a stream or batch that later shifts scope**
A subscription, bulk upload, or streaming call is authorized at open time, but subsequent items name other resources, or the stream keeps delivering after the caller's role, group membership, or token was revoked. Find every place the scope can move and pin the subscription to the principal it opened under.

**Reply and callback correlation that another caller can satisfy**
Correlation IDs that are predictable, reused, or shared across tenants let one party's response, webhook, cancellation, or ack complete somebody else's pending request. Bind each outstanding operation to the authenticated peer, tenant, operation, and lifecycle stage.

## Attack family C — broker and queue isolation (subagent_type: `general`)

**Topic, routing-key, consumer-group, or partition selection across tenants**
A publisher or subscriber can name another tenant's topic, use a wildcard, join a foreign consumer group, read a different partition, or point at someone else's reply or dead-letter queue. Check broker-enforced ACLs where you can see them, and check how the application builds namespaces in code. A tenant string sitting *inside* the payload is not isolation. *Example:* queue names are formed as `kyc.verify.{tenant}`, but `tenant` comes straight from a request field, so a vendor onboarding caller can subscribe to `kyc.verify.*` and read other vendors' PAN/Aadhaar documents.

**Dead-letter, retry, and diagnostic fan-out leaking data**
Messages that fail land in DLQs, error topics, traces, or operator dashboards still carrying secrets or another tenant's content, readable by a lower-trust consumer. Review redaction and access policy on the *failure* path, not only on the happy path.

**An untrusted producer treated as the control plane**
A message body claims to be an admin command, a provider callback, a replication entry, or a migration instruction, and is honoured without independently authenticating the producer and the event type. Require a signature and a source/account/audience binding before any privileged handling.

## Attack family D — replay, ordering, transactions (subagent_type: `general`)

**Duplicate delivery hitting a non-idempotent side effect**
At-least-once delivery or a client retry repeats an effect because dedup is absent, executes *after* the mutation has happened, or keys on something that collides between operations or between tenants. Pin down what delivery model the broker actually guarantees, then point to the side effect that is not idempotent on its own. *Example:* a redelivered "disburse PF contribution" message with no idempotency key pays the same employee twice.

**Stale or out-of-order messages overwriting newer state**
Something older — stale state, a membership since revoked, a task already cancelled, or an authorization from before step-up — lands *after* the newer state and overwrites it. Look for sequence/version checks, tombstones, partition reassignment, and restore/replay flows.

**Ack-before-commit or commit-before-ack defects**
The consumer acknowledges before the durable write, so a crash silently drops security-relevant work; or it commits before an unreliable ack, so a retry duplicates the mutation. Evaluate any transactional outbox/inbox and the crash-recovery path.

**Multi-consumer transitions that partially commit**
Several consumers together implement one authorization or business transition, but a retry and partial failure leave only some of them committed. Identify the invariant that must become durable atomically, or be compensated against *current* authorization.

## Universal moves (apply across all four families)

- For each message family, draw the full path: producer → broker/transport → gateway → consumer → storage. At every hop, write down the authenticated peer, which field is authoritative for tenant/resource, what validation runs, and what the side effect is.
- Push a single tiny fixture through each schema version and language binding the repo contains. Put it through messages that are reordered, replayed, out of bounds, unknown, missing, and duplicated — none of it under generated load.
- Trace the one operation across its other routes too: the ordinary path, a retry, a dead-letter hop, a replay, a migration, reflection, a stream, and gateway-transcoded traffic. The security decision must hold no matter which transport carries it.

## Checks to clear before you file ANY finding in this guide

1. Describe the realistic producer or peer, the message that gets accepted, the authenticated channel identity, the principal or resource affected, and the unauthorized mutation or disclosure that results.
2. For a disagreement claim, cite both parsers/consumers and the exact decoded value that differs. If either side safely rejects the input, there is no finding.
3. For a replay or ordering claim, nail down the actual delivery guarantees, then reproduce the broken invariant over a transport that is bounded and local or held in memory.
4. When the claim concerns isolation or authorization, account for every layer the source reveals — interceptor, broker ACL, gateway, consumer. Anything attached only at deploy time makes the candidate `needs_validation`.
5. Return `confirmed` only with the full message lifecycle and an observed, meaningful result. Otherwise return `needs_validation`, and call out precisely which delivery fact, route, service identity, or broker detail is still required.
