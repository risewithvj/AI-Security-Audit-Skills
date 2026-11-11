<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Web Protocol, Session and Identity Review

> **Source-only discipline (v1):** this skill reads code; it never runs the target. Anywhere below you see the words "bounded local test", "local fixture" or "sandbox", answer the question from the source itself. When the source alone cannot decide the matter, the verdict is `needs_validation` and you must name the one fact that is missing. Keep the `checklists/...` path convention and defer to the evidence gate in `rules/evidence-gate.md`.

---

## 1. Is this file the right tool?

Open this checklist whenever the target makes decisions at the HTTP wire, the cache, the browser-credential boundary, or the identity layer. That covers HR portals, payroll APIs, KYC onboarding services, reverse proxies, CDNs, API gateways, hand-rolled HTTP servers, and anything that issues or consumes sessions, JWTs, OAuth/OIDC, SAML, password-reset links, MFA, passkeys, API keys, or mutual TLS.

Run it alongside `core-attack-classes.md`. The access-control checklist asks a different question — *may this principal perform this action?* The questions here are narrower and sharper: can the HTTP or identity plumbing be made to **misattribute** which principal, which request, which assurance level, or which token an action belongs to? A payroll mutation may be perfectly access-controlled yet still land on the wrong employee's record because two proxies disagreed about where one request ended.

**Scoping tip.** Choose the relevant classes during Phase 1. A big target decomposes cleanly into: wire framing + caching, browser sessions, federated login, strong auth + recovery, machine credentials, and session lifecycle. Remember the surface scales with the plumbing — one stock app server sitting behind a fully managed proxy exposes almost no *source-confirmable* smuggling surface, whereas a custom parser or a self-operated proxy chain exposes a great deal.

---

## 2. Operating rules to paste into every agent prompt for this domain

```
- A framing or cache bug needs TWO readings of one request, response, or cache key.
  State both components by name and the exact normalised value each one computed.
- For any credential, locate the signature/secret check AND every binding its role
  demands: issuer, audience, origin, RP, client, session, principal, resource,
  assurance level, expiry, and single-use state.
- Treat Host, Forwarded, X-Forwarded-*, Origin, Referer, redirect targets, callback
  state, and any URL derived from the request as TRUST INPUTS. Trace each one to the
  identity or the response it ends up steering.
- An absent header, cookie flag, MFA prompt, or rate limit is NOT a finding on its own.
  You must also show an accepted invalid request, a cross-principal effect, an assurance
  downgrade, or a leaked credential.
- Mark `confirmed` only from a full source trace plus a bounded local request/token test.
  Use `needs_validation` whenever a proxy, IdP, browser, certificate, secret, or live
  config decides the outcome and is not visible in the repo.
```

---

## 3. Wire framing and caching

| Class | What goes wrong | What to prove from source |
|---|---|---|
| **Request smuggling / desync** | The edge and the origin disagree on where a request ends or how a header is read. | Inspect handling of duplicate `Content-Length`, `Transfer-Encoding`, HTTP/2 or HTTP/3 downgrade to HTTP/1.1, header-name normalisation, forbidden connection-level headers, and CR/LF rewriting. Nail down which bytes one component counts as this request and which its neighbour counts as the next one. |
| **Cache poisoning via unkeyed input** | A request field alters a cached body or a security header but never enters the cache key. | Line up the cache-key recipe against every response that varies — forwarded host/scheme, specific cookies, query normalisation, language/device hints, and authorisation state. |
| **Cache deception / caching private responses** | A private dynamic route is routed as a public static asset, or a response whose identity and authorisation inputs were never keyed gets stored. | Compare edge cacheability against the app's own route parsing, suffix and path-parameter normalisation, and the response's own cache directives. |
| **Host / forwarded-header trust** | Attacker-controlled host or proxy metadata drives tenant routing, absolute URLs, the OAuth callback target, recovery links, the cache key, or even the source IP that authorisation leans on. | Establish who can set the header and whether a trusted ingress strips the client-supplied copy before it reaches the app. |
| **Response-header injection** | Tainted data reaches `Location`, `Set-Cookie`, CSP, or another header carrying control characters or odd normalisation. | Confirm the framework does not already reject it, then require a genuinely security-relevant change to the response. |

> **Indian HR example — host-header reset poisoning.** A payroll portal builds its password-reset email from the incoming `Host`:
> ```js
> // reset-mail.js — the Host header is attacker-controlled
> const link = `https://${req.headers.host}/reset?token=${token}`;
> await sendMail(employee.email, `Reset your payslip login: ${link}`);
> ```
> If the edge forwards an attacker's `Host`, the reset token for an employee's payslip account is delivered to an attacker-controlled domain. Confirm from source whether ingress pins `Host` to an allowlist before reporting.

---

## 4. Browser-session classes

**Classic CSRF.**
The browser attaches ambient credentials to a state-changing endpoint, and that endpoint accepts a cross-site request with no effective anti-CSRF token, no same-site request binding, and no strict `Origin`/`Referer` check. Catalogue *every* cookie-authenticated mutation — HTML form posts, JSON-ish bodies, multipart uploads, method-override routes, and any legacy endpoints. Note that `SameSite` only protects the specific cookie and the specific browser contexts actually in play; login CSRF and cross-site subresource loads can behave differently. *Indian example:* a `POST /salary-revision/approve` that flips an approval using only the manager's session cookie is a textbook target.

**Session fixation and invalidation.**
Session identifiers must rotate on login, account switch, MFA completion, impersonation start, and any other privilege change — and must become worthless after logout, password change, token revocation, and account disable. Check server-side sessions, refresh tokens, signed cookies, websocket state, cached copies, and any fallback endpoints. *Indian example:* an HR admin "impersonate employee" feature that reuses the same session ID lets a fixed pre-login session ride straight into the impersonated context.

**Cookie scope and transport.**
A sensitive cookie carries an over-broad `Domain` or `Path`, can travel over cleartext, or clashes with a sibling cookie that some other component selects differently. A bare missing flag stays a hardening note — promote it to a finding only when a realistic lower-trust origin, network position, or browser code path can read or overwrite the credential. *Indian example:* a KYC session cookie scoped to `Domain=.example.in` leaks to a marketing subdomain that a vendor operates.

---

## 5. Federated-identity classes

Fix the **role** first. The jobs an authorization server owns — vetting redirect-URI allowlists, minting authorization codes — are not a relying party's responsibility. By contrast, failures of verification or of binding sit with whichever component actually consumes the artefact.

**JWT verification and claim binding.**
Confirm the signature is checked; confirm the algorithm and key source are pinned *server-side*; then confirm `exp`, `nbf`, `aud`, and `iss`. Treat `kid`, `jku`, and `x5u` as attacker-influenced key selectors. Watch for duplicate or case-normalised headers and for any decode-without-verify path. A token validly signed by a trusted issuer but minted for another service is still invalid here.
```js
// VULNERABLE — algorithm not pinned; attacker can present alg:none or HS256-over-the-RSA-public-key
jwt.verify(token, publicKey);           // bad
jwt.verify(token, publicKey, { algorithms: ['RS256'],
            audience: 'payroll-api', issuer: 'https://sso.example.in' });  // good
```
The presence of a `verify()` call does not by itself close this — the **library version and the exact options** decide it. Old releases of several JWT/JOSE stacks (for example early `jsonwebtoken` lines, and dependency chains that still resolve to them) accept `alg:none` / an empty signature, or honour whatever algorithm the token header names, so a `verify()` with no explicit `algorithms` allowlist silently permits algorithm confusion: a token the attacker "signs" with HMAC using the server's *public* RSA key as the secret validates, because the code hands the same public key to both an RS256 and an HS256 code path. Read the pinned version from the lockfile and the verify options together — a current library *with* a pinned single-algorithm allowlist and a key source that cannot be reinterpreted as an HMAC secret is sound; an unpatched version, a missing `algorithms` option, or a verify that feeds a public key into a routine that would also accept it as a symmetric secret is a finding. An unsigned or `none`-algorithm token accepted on a protected route is `confirmed`; where only the deployed library version is in doubt, record `needs_validation` naming that version.

**OAuth/OIDC request and callback binding.**
Where the target *is* the authorization server, enforce exact `redirect_uri` ownership. Everywhere, bind `state` to the session; apply PKCE and authorization-code binding where relevant; validate the ID token's issuer, audience, signature, and `nonce`; and in multi-provider setups bind the chosen IdP to the flow. Compare the first callback against the paths used for retries, for deep links or mobile, and for account linking — any of those often drops a check. *Indian example:* an employee-SSO login that trusts `state` without session binding lets an attacker splice their own authorization code onto a victim's login.

**SAML signed-object and assertion binding.**
The element whose signature you validate must be the very element you treat as identity. Review unsigned or fallback paths, safe XML-parser configuration (XXE, DTDs), canonicalisation quirks, and freshness/binding fields — validity window, audience/recipient, `InResponseTo` correlation, and replay state.

---

## 6. Strong auth, passkeys and account transitions

**MFA enrolment and assurance downgrade.**
Enrolling, replacing, disabling, or generating recovery codes, creating a trusted device, and any fallback login must each require the intended prior assurance. Verify that a mere first factor cannot enrol or swap the second factor without the policy-mandated fresh authentication, and that a disabled or stale factor stops authorising sessions. *Indian example:* an HR self-service portal that lets a password-only session register a new TOTP seed is an assurance downgrade.

**Step-up binding and bypass.**
A passed challenge must upgrade the *right* session, account, tenant, action, or API request — and no alternate route may skip it. Tie each challenge to the principal, the live session, the target assurance level, expiry, single-use completion, and — where it matters — the particular operation or resource. Trace it through the interface, the API, batch jobs, recovery, and any resumed flow. *Indian example:* a step-up prompt on the web "release salary" button that the bulk payroll API does not enforce.

**WebAuthn / passkey verification.**
During registration, anchor the following to the session that started the ceremony: the challenge, the RP ID, the origin you expect, the credential, the user or `userHandle`, the algorithm, and whatever user verification your policy demands. When a login comes in, check the challenge, the RP and origin, that the credential really belongs, the signature, and the presence or verification you asked for. Scrutinise the discovery and linking flows for a `userHandle` mapped to the wrong account, or a credential mapped to the wrong account. Signature-counter regressions matter only if the product actually treats them as a cloning signal.

**Account linking and identity collision.**
Binding a fresh identifier — an external account, device, phone, email, passkey, or IdP — onto an account already on file must require all of: a session that is currently authenticated, proof that the new identifier is genuinely owned, whatever step-up the policy dictates, and callback state pinned to the account where the link *started*. Comb the relink, unlink, and invite-acceptance routes for collisions on a verified identifier or across tenants. *Indian example:* a KYC profile that lets a new PAN be linked without re-verifying the logged-in user enables identity grafting.

**Password reset and wider recovery.**
Across the whole system, the weakest authentication path is usually one of these: changing an email or phone, migrating a device, redeeming backup codes, admin- or support-driven recovery, or a reset token. Verify token randomness, binding to user and action, expiry, one-time state, rate/accounting limits, trust in the delivery URL, and invalidation of prior tokens and sessions. A response difference that only confirms a public account exists is not automatically a finding.

---

## 7. Machine credentials — API keys and mTLS

**API-key scope and resource binding.**
Some key ends up good for a wider set of environments, actions, resources, or tenants than the authority recorded for it on the server — or a request parameter quietly overrides what that record pinned. Walk the lookup logic, how a prefix is compared against the full secret, scope enforcement, rotation, the revocation cache, bulk endpoints, and any mix-up between publishable and secret key types. *Indian example:* a payroll integration key scoped to one company that a `company_id` body parameter silently widens to every tenant.

**API-key exposure and unsafe transport.**
Keys leak through client bundles, URLs, redirects, logs, error traces, build artefacts, or any response a less-trusted principal gets to see. Something merely labelled "key" that is really a public identifier is no secret — pin down the key *type* and the authority that leaking it would actually hand over.

**mTLS peer and application-identity confusion.**
Here a service will honour client-certificate identity headers no matter which network peer sent them; or it does verify the chain yet resolves attacker-shapeable subject text onto the wrong account; or it admits a certificate whose trust domain, extended key usage, audience, or validity policy is simply wrong. When a trusted proxy is the one terminating mTLS, verify three facts in the source: nothing but that proxy can connect, inbound identity headers get stripped, and the backend binds only the *sanitised* identity onto the request.

**Certificate lifecycle fallback.**
An expired, revoked, missing, or renewal-failed certificate silently degrades to bearer-only or anonymous operation; or a long-lived pooled connection keeps its authorisation after revocation. Missing deployment revocation data makes this `needs_validation`; an in-repo fail-open branch is directly source-confirmable.

---

## 8. Cross-cutting moves (apply across sections 3–7)

- **Trace the full credential lifecycle:** issue → store → transmit → consume → refresh → revoke. Do it for every credential and every challenge, and hold the normal path up against the retry, migration, legacy, account-switch, and error paths.
- **Count every entrance to a single identity, and every route that reaches one sensitive operation.** What governs in practice is the flimsiest parallel path, not the most polished screen in the UI.
- **Diff normalisation side by side** across parser, proxy, router, cache, and application. To validate locally, push the same bounded request fixtures through each component rather than aiming traffic at a running deployment.
- **For recovery and linking, draw the before/after account graph.** Every edge must name the current principal, the proof of the new identity, the required assurance, the callback/session binding, and the revocation effect.

---

## 9. Validation gate — clear every item before you report a finding here

1. **Source-visibility gate first.** The deployed auth mode, secrets, how a browser treats cookies, certificate trust, IdP policy, edge cache keys, and proxy chains can all sit outside the repo. Where they do, log a precise `needs_validation` candidate instead of claiming how infrastructure you cannot see behaves.
2. **Framing and cache findings** must name both components and the divergent parse or cache key, and — using bounded local fixtures — must demonstrate impact that crosses requests, crosses users, or exposes a private response.
3. **A finding on mTLS, an API key, recovery, an account link, a passkey, MFA, or a token** must cite the verification line together with whichever binding is absent — principal, session, resource, origin, audience, action, or assurance — and must show the server waving through the invalid credential or transition.
4. **CSRF findings** must name the ambient credential, the state-changing route, the accepted cross-site request shape, the browser cookie policy, and the effective check that is absent. Routes gated by a bearer token that is not ambient, and actions that only read, fall outside this.
5. **Check framework and library defaults.** When the version or configuration is unknown, use `needs_validation`; a critical claim you have not verified must never be quietly recast as some milder `confirmed` finding.
6. **Hand back `confirmed`** only alongside an end-to-end source trace and an observable unauthorised identity, state, or disclosure. For `needs_validation`, state the missing fact and the safe local or owner-observed check that would settle it.
