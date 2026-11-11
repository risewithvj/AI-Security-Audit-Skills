<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Client-Side and Browser Hunting

> **Source-only note (v1):** this skill never runs the target. Anywhere this page mentions a "bounded local test", a "local fixture", or a "sandbox", resolve the question from the code itself. If the code cannot answer it, the verdict is `needs_validation` and you name the fact that is missing. All paths are written as `checklists/...`, and the proof bar lives in `rules/evidence-gate.md`.

## What this page is for

Pull this checklist up whenever a trust decision, or the rendering of attacker-reachable content, lands inside a browser. That includes single-page HR portals, salary-slip viewers, browser extensions, embedded webviews in a mobile onboarding app, service workers, offline-capable KYC forms, and any code that writes influenceable data into the DOM, listens for cross-window messages, or leans on browser storage. The defining trait of these paths is that they carry inputs the server never witnesses — URL fragments, `window.name`, `postMessage` payloads, and content already sitting in a cache.

Run it next to `core-attack-classes.md`. Here we concentrate on browser sources and sinks, origin boundaries, client persistence, and cross-site state oracles. When the browser talks to a native layer across a webview bridge, cross over to `desktop-mobile-and-ipc.md`. For server-side CSRF, session handling, and auth redirects, use `web-protocol-and-auth.md`.

## Operating discipline (paste into every agent prompt for this domain)

```
- Every client-side candidate pairs a source you can steer with a sink that executes or discloses. Name both, and show the attacker-influenced value arriving at the sink.
- Impact has to land on a victim's session, a different origin, or shared persistence. Poisoning only your own data, or reading back what you yourself injected, is not a finding.
- Framework auto-escaping, the same-origin policy, CSP, COOP/CORP, service-worker scope limits, and today's default noopener behaviour are genuine defences. Confirm they are absent or bypassed before you claim impact.
- Browser storage and caches are keyed by origin and can survive a logout. For each record, work out who writes it, who reads it, and which account, tenant, or worker-lifecycle event is supposed to purge it.
- Reserve `confirmed` for a full source chain plus a bounded local browser test. Fall back to `needs_validation` whenever the answer depends on a renderer, an extension permission, a deployed header, or browser-policy behaviour you cannot see in source.
```

---

## Group A — DOM sinks and object-state corruption (subagent_type: `general`)

These three classes share a theme: the attacker never touches the server, yet still reaches an executing sink or warps a trusted object.

| Class | What to prove | Not a finding on its own |
|-------|---------------|--------------------------|
| DOM-based XSS | Browser-only source reaches an HTML/JS-executing sink unescaped | Values the framework already escapes |
| DOM clobbering | Injected `id`/`name` shadows a trusted global, and the shadow is used in a security decision | Markup injection with no security-relevant read |
| Prototype pollution | Attacker key reaches a recursive write, then a gadget consumes the polluted prop | Pollution with no reachable gadget |

**DOM-based XSS.**
Follow `location` members, `document.referrer`, `window.name`, incoming message data, storage reads, and other browser-maintained document state as they flow toward `innerHTML`, `outerHTML`, `document.write`, string-to-code APIs (`eval`, `setTimeout` with a string, `Function`), executable URL assignments, jQuery's HTML helpers, or a framework's escape hatch (`dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`). If the framework interpolation is auto-escaped, there is no finding. Example to watch for: an employee self-service portal that reads the department name from `location.hash` to pre-filter a payslip list and drops it straight into `resultsDiv.innerHTML`.

**Stored XSS through an incomplete or bypassable sanitiser.**
Separate from the DOM-only case above: here the payload is persisted server-side and later rendered into *another* user's page. The trap is treating input-time sanitisation as if it were output encoding. A denylist that strips `<script>` but misses `<svg onload=>`, `<img onerror=>`, `javascript:` URLs, or event-handler attributes; a sanitiser whose parse tree differs from the browser's so the cleaned string mutates back into live markup when re-parsed (mutation XSS); or a markdown/BB-code renderer that emits raw HTML — any of these lets a value survive storage and execute on display. Follow fields that are shown back on someone else's screen: a username or display name in a notification, a profile "about me" on a public card, a comment or feedback note an admin reviews, a support-ticket subject. The source chain is: attacker writes the field → store accepts it (sanitiser passed or absent) → a *different* account loads a page that interpolates the stored value without context-correct output encoding. A value that clears the server sanitiser yet renders unescaped in a victim's browser is `confirmed`; where the only question is whether the deployed sanitiser/library version blocks the specific vector, drop to `needs_validation` and name the exact bypass you cannot test from source.

**DOM clobbering.**
An attacker-supplied `id` or `name` attribute masks a global variable, a form property, a config object, or an init flag that the code later trusts. You must demonstrate two things: a markup path that keeps the attribute intact (for instance, a rich-text leave-note field whose sanitiser preserves `id`), and a security-relevant use of the shadowed value — say, a `window.featureConfig.kycBypass` that silently resolves to a clobbered DOM node.

**Prototype pollution (and the gadget).**
A key you control flows into a recursive writer — a deep merge, a `set`-by-path helper, a query-string expander — and lands on prototype state (`__proto__`, `constructor.prototype`). That alone is not enough. You then need a reachable gadget that reads the polluted property and shifts authorization, code execution, navigation, or rendering. A plain `JSON.parse`, a shallow copy, or pollution with no consumer does not clear the bar. Indian-SaaS example: a bulk employee-import screen that deep-merges a parsed CSV row into a defaults object, then a downstream check reads `user.isAdmin` off the prototype to show the payroll-admin panel.

---

## Group B — crossing origins: messages and network (subagent_type: `general`)

Here the boundary is the origin, and the defence is an exact origin (and sometimes source) check plus credential policy.

**`postMessage` — origin and source trust.**
On the receiving side, flag a handler that takes a sensitive action from `event.data` with no exact-origin allowlist and — when several frames share one origin — no `event.source` check. On the sending side, flag sensitive data posted to a `*` target that any embedder can read. Matching the origin by substring, prefix, suffix, or an unanchored regex is not an origin check (`origin.indexOf('cielhr.com') > -1` happily accepts `cielhr.com.evil.in`). Concrete case: an embedded KYC-verification iframe that posts the verified PAN back to the parent with `parent.postMessage(pan, '*')`.

**Cross-site WebSocket hijacking.**
A WebSocket upgrade accepts ambient cookies from any origin, with no `Origin` validation and no channel-specific token, so the victim's logged-in session can be driven to read or change data. Confirm both the upgrade behaviour and a message handler that does something security-relevant — e.g. a live payroll-run status socket that also accepts a "approve run" command frame.

**Credentialed CORS trust.**
The server reflects the request `Origin` (or matches it loosely) while also allowing credentials and returning sensitive bodies. Note that browsers reject a bare `*` together with credentials, so report only the actual reflected or allowlisted origin path, and point at the cross-origin data read or mutation it enables — for instance an `/api/employee/{id}/salary` endpoint that echoes `Origin` into `Access-Control-Allow-Origin` with `Allow-Credentials: true`.

---

## Group C — service workers and browser persistence (subagent_type: `general`)

Service workers and client storage outlive a single page view, so the recurring risk is one account's data surfacing for another.

**Worker registration and scope takeover.**
A worker script gets registered from attacker-influenceable content, or a path under the control of an over-broad `Service-Worker-Allowed` scope, or an `importScripts` call mutated without integrity control. Pin down the final script URL, the MIME type it responds with, its origin, the scope it asserts, and the owner of each script pulled in. There is no issue when a same-origin worker is registered at the scope it was designed for. Keep an eye on directories holding uploaded assets: once HR letter templates sit beneath a path from which a worker can register, a takeover has begun.

**Cache and identity confusion.**
The worker stores a personalised response — a payslip PDF, a roster of direct reports — in cache while leaving account, tenant, authorization state, or request mode out of the cache policy, and then serves it back once the user logs out or switches accounts. Walk through how fetch events are routed, how caches are named and keyed, where navigation falls back, how caches get cleaned up, and whether an offline or error branch can return a response that belonged to a prior user. The realistic trigger is a shared kiosk on which one employee signs in right after another.

**Storage disclosure and stale authorization.**
Private responses, tokens, draft documents, or cached authorization decisions are left behind in `localStorage`, `sessionStorage`, IndexedDB, Cache Storage, extension storage, or in-memory client state, where a separate account — or a less-trusted component on the same origin — can then read them. On its own, persisting a token proves nothing; you have to exhibit a plausible lower-privilege reader, or show the value still being honoured once it has been revoked or the user has logged out. Example: an Aadhaar KYC draft kept in `localStorage` on a shared desk machine, still readable after the first applicant walks away, which is also a DPDP storage-limitation problem.

**Cross-context and broadcast confusion.**
Shared workers, origin-wide caches, `BroadcastChannel`, or `storage` events relay commands or identity from one tab to another with nothing tying that traffic to the session now in effect. Exercise tenant changes, private versus normal windows, account switching, and lingering tabs able to overwrite fresher auth state — for instance a tab left open on Company A's payroll that receives a `BroadcastChannel` login event from a Company B tab and adopts the wrong tenant.

---

## Group D — cross-site information leaks (subagent_type: `general`)

The attacker cannot read the response, but can still infer protected state from side signals while the browser attaches the victim's credentials.

**XS-Leaks and cross-origin state oracles.**
While the victim's cookies ride along, an attacker page distinguishes protected cross-origin states by watching response size, cache state, timing, redirect behaviour, frame or window counts, or the load and error events a resource fires. You must pin down one concrete secret-bearing predicate — does a given employee record exist, does this user hold the approver role, is this PAN already enrolled. Generic timing jitter or the mere availability of a public asset does not clear the bar.

**Window and opener state disclosure.**
Protected state leaks either through the metadata a cross-origin window is allowed to expose or through the outcome of its navigation, or else a held-onto opener or named-window reference hands an attacker-controlled page the ability to drive a privileged navigation. Inspect `noopener`, frame protections, COOP, exact-origin comparison, and whether what can be observed is genuinely confidential.

---

## Group E — UI redress and navigation (subagent_type: `general`)

**Clickjacking.**
A state-changing action that can be framed lacks an effective `frame-ancestors` directive, `X-Frame-Options`, or some equivalent UI isolation. You must name the sensitive action and show it can complete while framed — for example a one-click "approve salary revision" button that can be overlaid in a transparent iframe. Missing frame headers on read-only pages are hardening notes, not findings.

**Client-side navigation confusion.**
A client-controlled source drives a redirect or navigation with no scheme-and-destination policy, including executable `javascript:` or `data:` targets (a `returnUrl` param from the login page flowing into `location.href`). Reverse tabnabbing only applies where the code explicitly retains `window.opener`, calls `window.open` without isolation, or targets a browser that lacks implicit `noopener`.

---

## Cross-cutting techniques (apply across every group above)

- Work backwards: start from the storage, message, worker, navigation, and DOM sinks, then follow the trail back to whichever browser-only and server-controlled sources feed them. Note, per path, the browser policy supposed to block it.
- Against a local test origin with dummy accounts, run through logout, account switch, offline fallback, worker update, and stale-tab scenarios. Never touch production users, origins, or shared services — and never real PAN, Aadhaar, UAN, or salary data.
- For XS-Leaks, write down only the predicates you can prove from source plus local browser behaviour, then name the response header or rendering change that would close the oracle.

## Verdict rules (clear these before you report anything on this page)

1. Cite all five: the source, the sink, the browser policy in play, the affected origin or session, and the observable mutation or disclosure.
2. With prototype pollution, exhibit both the recursive write and a gadget that matters to security. With DOM clobbering, exhibit that the markup endures and that the shadowed value genuinely gets consumed.
3. Where service workers and storage are involved, establish lifecycle reachability — a cache entry or write under attacker control has to resurface for some other account, tenant, or subsequent authorization state.
4. Across CORS, WebSocket, messaging, and XS-Leaks, exhibit the precise origin or source validation at stake together with the protected action or state it leaks, and verify that SameSite policy, cookie flags, COOP/CORP, and CSP are not already cutting off the path.
5. Reserve `confirmed` for a complete client path backed by bounded local evidence. Short of that, return `needs_validation` and name the exact renderer behaviour, browser version, extension permission, or deployed header the owner still has to check.
