<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Attack Classes

> **Source-only discipline (v1).** This skill reads code; it never runs the target. Anywhere a check below mentions a "local fixture", "bounded test" or "sandbox", resolve the question by reading source. If the source genuinely cannot answer it, record the verdict as `needs_validation` and name the one fact you are missing. All paths below use the `checklists/...` convention, and every finding passes through the gate in `rules/evidence-gate.md`.

## How to read this file

This is the general-purpose catalogue of attack classes for an application-level audit. It is deliberately broad: not every class fits every target, and large systems should be split per subsystem rather than audited as one blob. Pull the classes that match what Phase 1 told you about the stack, then add target-specific classes that Phase 1 surfaced. The goal of each class is the same — find a candidate, prove the boundary, prove the result — not to generate a long list of theoretical worries.

Treat validation as a reading exercise plus, at most, a small local fixture. Do not build working exploit chains, do not probe live or shared environments, and do not act on production state. An audit is finished when every candidate is either dismissed with reasoning or raised with evidence.

### The two verdicts

| Verdict | When to use it |
|---|---|
| `confirmed` | Source evidence plus any bounded local check together establish both the attacker's entry boundary and a concrete, meaningful result. Nothing is left to assumption. |
| `needs_validation` | One deployment-, provider-, platform-, identity-, or runtime-specific fact is outside what the source can tell you. State that fact explicitly, and name the safe check (owner-observed or local) that would settle it. The spelling `needs validation` is also accepted. |

## Routing to the specialist checklists

Most of the heavy, domain-specific coverage lives in companion files. When your target matches one of the profiles below, work through that file's classes in addition to (or instead of) the general ones here. Keep these links intact — they are part of the skill's contract.

| If the target involves… | Go to |
|---|---|
| Firmware and JITs, binary loaders, concurrent runtimes, FFI boundaries, parser/decoder code, kernel modules, and C/C++/Rust-`unsafe` — memory safety, concurrency hazards, integer/ABI defects, privileged interfaces | [memory-safety-and-binary.md](memory-safety-and-binary.md) |
| Model-driven actions assembled from prompts, plus MCP clients and servers, agents that call tools, long-lived memory, RAG pipelines, and chatbots — context handling, memory poisoning, action binding, tool schemas, MCP identity, output safety | [ai-llm-and-mcp.md](ai-llm-and-mcp.md) |
| mTLS alongside API keys; the linking and recovery of accounts; passkeys and MFA; SAML plus OAuth/OIDC; JWT and CSRF; session handling; hand-rolled HTTP parsing; and the gateways, CDNs, reverse proxies, APIs and web apps in front of them | [web-protocol-and-auth.md](web-protocol-and-auth.md) |
| DOM rendering plus WebSockets and CORS; messaging between windows; storage in the browser; service workers; webviews embedded in a host; extensions for the browser; and SPAs | [client-side.md](client-side.md) |
| How dependencies resolve, inputs that are generated, CI, the signing/promotion/release chain, auto-update, and both plugins and extensions | [supply-chain-and-release.md](supply-chain-and-release.md) |
| Runtime configuration and the events a provider emits, ingress, edge and serverless, a service mesh, Kubernetes and containers, infrastructure declared as code, and IAM | [cloud-and-deployment.md](cloud-and-deployment.md) |
| Streaming RPC and webhooks; pub/sub, brokers and queues; bespoke wire formats; Thrift, Cap'n Proto and Protobuf; plus GraphQL and gRPC transports | [protocols-rpc-and-messaging.md](protocols-rpc-and-messaging.md) |
| Untrusted work that can draw down operator-funded spend, quotas, queues and workers, or the shared pool of connections, disk, memory and CPU | [resource-exhaustion.md](resource-exhaustion.md) |
| Restore and retention, deletion and migration, backup and export flows, analytics, cross-object links, search and caches, and multi-tenant stores | [data-isolation-and-lifecycle.md](data-isolation-and-lifecycle.md) |
| D-Bus, Binder, XPC and Unix sockets; local daemons; helpers running with elevated rights; components the app exports; bridges exposed to webviews; deep links; and native mobile or desktop apps | [desktop-mobile-and-ipc.md](desktop-mobile-and-ipc.md) |

Each class below is assigned to a `general` subagent. For complex authorisation models, split one agent for authentication-bypass work and another for authorisation-logic work.

---

## 1. Injection

The core move is always the same: follow an untrusted value from where it enters the system to where it does something dangerous. What qualifies as "dangerous" is relative to the target:

- **Web apps and HR portals:** SQL and ORM queries, HTML rendered to a browser, OS shell calls, template engines, constructed file paths, HTTP redirects, object deserialisation.
- **Libraries:** any routine that accepts caller data and operates on it without validating — buffer handling, parsers, format strings.
- **CLI tools:** command assembly, path handling, environment-variable interpolation.
- **Back-end services:** query building, message serialisation, log writing, LDAP/XPath lookups.
- **Browser-side code:** DOM-based XSS, prototype pollution, `postMessage`/origin trust and the rest — covered by [client-side.md](client-side.md) when that profile is in scope.

Do not stop at the direct, obvious path. The interesting bugs are indirect: a value is stored cleanly, then later read back and dropped into a dangerous context by unrelated code. Watch for injection carried by **field names, object keys, headers and metadata**, not only by values. And watch for tainted data reaching *downstream* machinery — analytics pipelines, search indices, caches, and log stores.

> *Indian HR example.* A payroll screen accepts an employee's bank-account IFSC as a form value and parameterises it correctly in the INSERT. But a nightly reconciliation job reads that same stored value and builds a shell command to call a bank SFTP client: `sh -c "sftp ... ${ifsc}"`. The write path was safe; the second-order read path is a command-injection sink. The value never looked dangerous at entry.

```js
// Second-order sink — the stored value is trusted on the way out
const row = await db.query('SELECT remarks FROM payslip WHERE id = $1', [id]);
res.send(`<div>${row.remarks}</div>`);   // stored XSS: remarks was never re-encoded
```

Treat **input sanitisation and output encoding as different jobs** — a value scrubbed once on the way in is not safe in every later context. Denylist "HTML sanitisers" routinely miss `<svg onload=>`, `<img onerror=>`, `javascript:`/`data:` URLs, or event-handler attributes, and some rewrite the string in a way the browser then re-parses into live markup (mutation XSS). The payload need not come back to the author: a display name, a comment, a feedback note, or a ticket subject that another user — or an admin reviewing the queue — loads is stored XSS if it renders without context-correct encoding at that sink. When a field is shown on *someone else's* page, trace the output side even if the write looked clean, and confirm the escaping matches the context (HTML body vs attribute vs URL vs JS). The browser-rendering specifics and sanitiser-version bypasses live in [client-side.md](client-side.md).

## 2. Access control (authorisation and IDOR)

Confirm a caller cannot reach state or data outside its authority. Finding that *a* permission check exists is not enough — the check must gate the **right permission** on the **right resource** through the **right mechanism**. Interrogate each of these:

- Is there a second route to the same state change that is gated by a weaker (or no) permission?
- Will a value supplied in the body of the request quietly defeat the limit the permission layer believed it was applying (mass-assignment of `role`, `org_id`, `is_admin`)?
- Are there endpoints that verify *authentication* but forget *authorisation*?
- Does one resource have several access paths whose checks disagree?
- Do bulk, batch, export and import operations enforce permissions **per item**, or only once at the top?

> *Indian HR example.* `GET /api/payslip/88214` returns a PDF after checking the session is logged in, but never checks that `payslip.employee_id` belongs to the caller. Any authenticated employee can walk IDs and pull colleagues' salary slips — a classic IDOR over payroll data, and a DPDP exposure of financial personal data. Separately, `POST /api/leave/approve` checks the caller is a manager but not that the applicant reports to *that* manager, so any manager can approve any employee's leave.

## 3. Resource and file handling

- **Path traversal** — reading or writing outside the intended directory, including via symlinks, percent/double encoding, and null-byte truncation. (Think: KYC document store where `GET /kyc/download?file=../../etc/passwd` escapes the Aadhaar-upload folder.)
- **SSRF** — making the server fetch an attacker-chosen URL, including via open redirects, DNS rebinding, and URL-parser differentials between the validator and the fetcher.
- **Unsafe deserialisation**, **archive extraction** (zip-slip when importing a bulk-employee ZIP), and **temp-file handling**.
- **Memory safety** where the language allows it: buffer overflows, use-after-free, integer overflow (defer deep work to [memory-safety-and-binary.md](memory-safety-and-binary.md)).
- **File-operation races** — TOCTOU gaps between the check on a path and the use of it.

## 4. Cryptography and secrets

- Weak or non-cryptographic randomness for security-sensitive values — session tokens, reset tokens, API keys, nonces (e.g. `Math.random()` generating a payslip-download token).
- Hardcoded secrets, and secrets that leak into logs, error messages, URLs, or anything a client can see.
- Broken key derivation, missing HMAC/signature verification, nonce or IV reuse.
- Timing side-channels on secret comparison (token or HMAC compared with `==` rather than a constant-time compare).
- Misused primitives: ECB mode, unauthenticated encryption, static IVs, MD5/SHA-1 for passwords.
- **Failure behaviour:** when a crypto call throws, does the error path silently fall through to plaintext or to "allow"?

> *Indian KYC example.* Aadhaar numbers are stored encrypted, but the IV is a hardcoded constant and the mode is AES-ECB, so identical Aadhaar values produce identical ciphertext — an attacker with read access to the column can cluster and correlate records even without the key.

## 5. Business logic

Hand-reasoned logic flaws are where the high-impact findings hide; scanners cannot see them. For each important workflow, work through:

- **State-machine violations.** Can a step be skipped, reversed, or driven into an invalid state? What happens if a completed flow is replayed? When a flow fails midway — say the middle of three steps aborts — does the first step get unwound, or does it stay half-applied?
- **Business-impacting races.** Concurrent operations that land the system in an invalid state: double-approval of an expense claim, double-crediting of a reimbursement, lost updates on a salary field. Focus on check-then-act sequences that are not atomic.
- **Numeric and quantity abuse.** Negative amounts, zero, overflow, precision loss, and string/number coercion (a `-50000` leave-balance adjustment that *adds* leave; a reimbursement of `"1e9"`).
- **Authority mismatch.** Not "is there a check" but "is it the check the *business rule* needs?" Can input to operation A achieve what operation B's restriction was meant to block?
- **Implicit trust.** Data read back from storage, config, a sibling service, or a plugin and treated as clean because "entry validated it" — yet some other route is what actually wrote that data.
- **Time-based logic.** Scheduling, expiry, rate windows, and clock skew. How does it behave right at the boundary? What if two components hold different timezones (IST versus UTC on a payroll cut-off)?
- **Defaults and fallbacks.** How secure is the system once config goes missing, a feature flag is turned off, a dependency becomes unreachable, or a migration is still in flight? Does it fail open?

> *Indian payroll example.* A salary-revision workflow needs two approvals (HR manager, then finance). The approve endpoint increments an `approvals` counter but does not record *who* approved, so the same HR manager calling it twice satisfies the "two approvals" rule and pushes an unauthorised hike through.

## 6. Feature abuse and data leakage

Legitimate features bent to unintended ends. Hunt for flaws in the *design*, not only the code:

- **Export/backup as exfiltration.** When a user with minimal rights kicks off a backup, snapshot, or export, does the result carry data above their level — colleagues' records, draft or deleted content, or old revisions that ought to have been purged long ago? (A team-lead "export my team" that quietly bundles in CTC for the entire department.)
- **Import/restore as injection.** Can an import clobber existing records, mint rows that sidestep the usual validation, or land data in collections the user has no UI path to write? Are the UI's authorisation rules applied here too?
- **Search, filter and sort as an oracle.** Can a query confirm that a record the user may not read *exists*? Through filter parameters, can a user prod at roles, statuses, or fields kept out of their view? When a query sorts on a concealed column, does the ordering of results betray that column's values?
- **Enumeration via side effects.** Across message, timing, size, or status code, does the "no access" response look any different from the "does not exist" one? Can accounts be harvested through registration, invite, or password-reset flows (say by PAN or email)?
- **Preview, draft and staging leakage.** Does a preview token cover just its one item, or does it open the door wider? Can draft material leak out via list APIs, sitemaps, feeds, or search? Might cache headers push a CDN into handing private content to the public?
- **Notifications and webhooks as SSRF.** Is there a callback, webhook, or notification URL a user can point wherever they like and have the server go fetch? Is it checked against internal ranges — and does that check still hold *once a redirect fires*?

## 7. Chained flaws and trust boundaries

A behaviour that is individually permitted or contained becomes a vulnerability once a later component or lifecycle step leans on a guarantee it was never actually given:

- **Multi-step boundary failures.** Map precisely what a low-privilege principal can read, write, invoke and retain, then wire only *concrete* outputs into later trust decisions. Prove every prerequisite; never assume the downstream effect lands.
- **Cross-component trust gaps.** Component A validates and hands off to B. Compare the exact guarantee A produces against what B assumes — truncation, type coercion, normalisation, tenant scope, plugin/extension reach.
- **Second-order use.** Data that sat safely in storage turns hostile once a fresh context consumes it: a slug ends up as a filesystem path, a field name is read as a JSON path, already-escaped text flows back into a raw renderer, and a saved string is later interpreted as a policy expression, template, regex, or URL.
- **Scope and capability creep.** A token, API key, plugin grant, OAuth scope, MCP capability, or AI capability widens after delegation, refresh, caching, a role change, or composition. Name the exact operation the resulting principal should not be allowed.
- **Timing and ordering.** Look hard at the windows around validate/consume, check/use, revoke and cache-expiry, soft-delete, migration, and initial setup. Confirm stale state is genuinely accepted before you write it up.
- **Rollback and recovery.** Cancellation, reverting a revision, restore, and undelete each have to re-assert *today's* ownership, authorisation, and validation. Identify exactly which invalid state gets restored (e.g. restoring a terminated employee's active payroll access).

## 8. Wildcard — outside the assigned classes

You have no category. Your job is to find what the standard classes miss. Read code that looks dull or security-irrelevant. Chase incomplete, experimental, compatibility, and fallback features — but hold them to the same boundary-and-result standard as everything else.

Starting prompts (not a ceiling):

- What is the oddest code in the repo? Why does it exist, and what breaks if it is abused?
- Which features feel half-built, experimental, or bolted on? Least-reviewed means weakest.
- What happens when the API is exercised in ways no frontend would ever attempt? Users are boxed in by the UI, but the API imposes no such limits. Which requests the client could *in principle* send does it simply never send?
- Are there features, headers, parameters, or endpoints that are undocumented or concealed? Comb the route tables, middleware, and config for anything the docs never mention.
- What breaks when features that were never meant to meet are wired together? Caching with preview and localisation. Webhooks with plugins and import. API keys with impersonation and OAuth.
- Anything telling in the git history? Security fixes that got reverted, auth checks commented out, secrets that were committed and later stripped (yet still live in history).
- Which actions available to a valid account touch *other* users, shared integrity, availability, or operator-funded cost? Check containment, quotas, authorisation, and recovery around them.
- Which operations cannot be undone or call for a stronger confirmation step? Tie the approval and the authorisation to the ultimate resource, action, and principal.
- What does the code assume about its environment — local database, accurate clock, trustworthy DNS, case-sensitive filesystem?
- What are the tests *not* testing? Compare the edge cases the author clearly considered (tests exist) against the ones they did not.

Chase down each anomaly within your scope until its invariant is nailed down. When something seems off, go on reading until you can say flatly whether or not it is safe. If a comment claims a function is safe, verify the claim. If a variable is named `temp`, `hack`, or `legacy`, read it closely.

## 9. The obvious things

While other agents chase subtle bugs, this agent checks the basics — the exposures everyone assumes someone else already handled. This work is not creative; it is literal and exhaustive. Check every item and report every result.

- Secrets, tokens, API keys, or passwords baked straight into the source. Grep for `password`, `secret`, `apikey`, `token`, `Bearer`, `-----BEGIN`, and the usual default passwords.
- Security-flavoured `TODO`/`FIXME`/`HACK`/`XXX` comments: `TODO: add auth`, `FIXME: validate PAN`, `HACK: skip permission check`.
- Is debug/dev mode properly gated, or can it be switched on in production via env var, query parameter, or header?
- Do test, example, or seed credentials work in production?
- Is there an unprotected `/debug`, `/admin`, `/test`, `/status`, `/health`, `/metrics`, `/env`, `/.env`, or `/config` endpoint?
- Are `.env`, `.env.local`, `credentials.json`, `*.pem`, or `*.key` files committed to the repo?
- Does `.gitignore` genuinely catch local config, uploads, and secrets?
- Are the dependencies pinned, and does the tree carry any known CVEs? Check the lockfiles.
- Any `eval()`, `exec()`, `child_process`, `Function()`, `vm.runInContext`, or dynamic `import()` fed with untrusted input?
- Do the CORS headers use `*`, or does a wildcard origin sit next to `Access-Control-Allow-Credentials`?
- Do any cookies lack `HttpOnly`, `Secure`, or `SameSite`?
- Any open redirects? Parameters like `redirect`, `return`, `next`, `url`, `goto`, `continue` flowing into a redirect without validation.
- Is TLS enforced, or are there plain-HTTP endpoints?
- Do production error responses leak stack traces, internal paths, or raw SQL errors?

> **Trace before you report.** Every item this agent raises must be followed through the full code path, not judged on surface appearance. A cookie missing `HttpOnly` only matters if it carries sensitive data and JS does not need to read it by design. An error message echoing a field name only matters if that field is ever populated with sensitive data. A raised flag is not a finding until you have traced the impact.
