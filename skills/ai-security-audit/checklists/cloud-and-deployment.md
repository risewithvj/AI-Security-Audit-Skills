<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Cloud and Deployment Hunting

> **Source-only framing:** nothing in this skill runs the target. Wherever a step below mentions a "bounded local test", an isolated "fixture", or a "sandbox", resolve the question from the repository itself. If the source genuinely cannot resolve it, the correct verdict is `needs_validation` with the one missing fact named. All checklist references use `checklists/...` paths and the gate defined in `rules/evidence-gate.md`.

## Where this file applies

Open this checklist when the repository carries the plumbing of *how* and *where* the software runs: cloud identity and roles, infrastructure-as-code (Terraform, CloudFormation, Pulumi, ARM/Bicep), Kubernetes and Helm, service mesh, serverless or edge functions, ingress and load-balancer config, object storage, managed data/event services, container images and Dockerfiles, CI/CD pipelines, and per-environment overlays.

The question this domain answers is narrow: does each deployed piece get *only* the identity, network reach, isolation, secrets, and policy it was meant to have? A repository usually encodes **intent**, not the live account state. So your job is to split two piles cleanly — defects you can prove from source right now, versus things that need an owner to observe the running environment.

Hand off to the neighbours when the question drifts:

| If the question is really about… | Go to |
| --- | --- |
| Build, signing, and promotion trust | `supply-chain-and-release.md` |
| HTTP/proxy semantics and auth flows | `web-protocol-and-auth.md` |
| Tenant scoping inside a datastore | `data-isolation-and-lifecycle.md` |
| URL parsing / redirect internals (SSRF plumbing) | `core-attack-classes.md` |

## Standing rules for every agent prompt in this domain

Paste these into any subagent you spin up here. They keep verdicts honest.

```
- A manifest is not a live fact. Before calling anything exposed, establish which
  environment actually consumes the file, what overlay/default/flag rewrites it, and
  whether the code path is even reachable.
- Tie every workload identity to concrete operations and resources. A broad role is
  only a finding when lower-trust input can steer it to an action it should not reach.
- Ingress, proxies, mesh sidecars, metadata endpoints and admission webhooks are genuine
  trust boundaries — but count a control only when both its config AND its attachment
  are visible in the repo.
- A reference to a secret is not disclosure of a secret. You need a lower-trust reader:
  a log sink, an output/artifact, a shared mount, or an unsafe fallback.
- confirmed = active in-repo config plus local rendering/policy evaluation.
  needs_validation = account policy, network wiring, runtime admission, hosted metadata,
  or drift that only the owner can observe.
```

## Attack-class catalogue

I group the classes by the boundary they attack rather than by product. Each block names the defect and the exact things to read. Unless noted, run these under `subagent_type: general`.

### A. Identity and access (cloud IAM, workload identity, federation)

**A1 — Identity does more than its job.** A pod, Lambda/Cloud Function, edge worker, node, or service account is able to operate across APIs, resources, accounts, or tenants that sit outside its remit, and untrusted request or job input chooses the target. Read the policy conditions, resource ARNs/patterns, service-account bindings, namespace-to-identity mapping, and any fallback credential.

> *HR example:* a payslip-export function is bound to a role with `s3:GetObject` on `arn:aws:s3:::payroll-*` with no object-prefix condition. The employee ID that selects the object key comes straight from the request. Any authenticated employee can walk `payroll-prod/<other-emp>/payslip.pdf`. The policy breadth plus the caller-controlled key is the confirmed defect.

**A2 — Cross-account / cross-tenant role confusion.** `AssumeRole`, external IDs, OIDC token exchange, workload federation, or a resource policy accepts an identity claim that is not pinned to the intended source — wrong account, audience, GitHub repo, namespace, or workload. You must show *both* the trust policy and the claim the caller controls.

> *CI example:* a GitHub OIDC trust policy scoped only to `token.actions.githubusercontent.com:aud` but not to `sub` (repo/branch). Any repo in the org, including a fork's workflow, can mint the role and reach the PF/ESI settlement bucket.

**A3 — App authorisation outsourced to cloud metadata.** The application trusts caller-supplied identity headers, resource tags, labels, or account IDs as if they were authenticated, without checking they originated from a trusted proxy or the control plane. Application-level authz and cloud IAM are two separate gates; a pass on one is not a pass on the other.

### B. Network edge, mesh, and control-plane reachability

**B1 — Something internal is reachable from a lower-trust network.** An ingress rule, Service, listener, security group, LB annotation, `hostPort`, or a server binding to `0.0.0.0` exposes an admin console, debug port, metrics endpoint, kubelet, control-plane API, or internal service to a broader network than intended. Pure *absence* of a network control is `needs_validation`; a repo-defined public route that lands on a sensitive handler can be `confirmed`.

> *Example:* a Terraform `aws_security_group` ingress of `0.0.0.0/0` on port 9200 (Elasticsearch holding KYC documents) is a config smell — but whether the instance has a public IP and a route is account state, so this is `needs_validation` unless the repo also wires the public subnet and IP.

**B2 — Trusted-proxy / mesh identity bypass.** A backend accepts a forwarded identity, an mTLS subject, or authz metadata from peers outside the intended ingress or sidecar; or a second port / health path / legacy route skips the mesh entirely. Check that upstream headers are stripped, whether peers can actually reach the port, and what happens when the sidecar or proxy is simply absent (fail-open?).

**B3 — Metadata / internal-service reach (SSRF-to-cloud).** An untrusted URL, host, or scheme selection can hit the instance/container metadata endpoint (`169.254.169.254`, `metadata.google.internal`), a control-plane socket, or an internal API — using the workload's own credentials. The URL-parsing and redirect-following mechanics belong to `core-attack-classes.md`; *here* you establish the deployed network path, the metadata service version (IMDSv1 vs IMDSv2), and the identity that would be lifted.

> *Example:* a vendor-KYC service fetches a logo from a vendor-supplied URL. If IMDSv1 is in play and no egress/allowlist exists, the vendor can point the URL at the metadata endpoint and exfiltrate the instance role credentials that can read the KYC bucket.

### C. Containers, Kubernetes, and orchestration

**C1 — Host or control-plane authority leaks into a workload.** A lower-trust workload can request privileged mode, extra capabilities, host namespaces (`hostPID`/`hostNetwork`), host-path mounts, device mounts, the container runtime socket, or an over-scoped service-account token — any of which crosses into node or control-plane authority. A missing seccomp profile or a writable root filesystem is hardening, *not* a finding, unless a reachable operation actually traverses that boundary.

> *Example:* a Helm values default of `securityContext.privileged: true` on a batch job that processes attendance CSVs, combined with the Docker socket mounted in, is a confirmed container-escape path — the job already handles tenant-uploaded files.

**C2 — Admission / policy path inconsistency.** A single deployment route applies policy for image provenance, namespace, resource, secret, or privilege, while a second route — another controller, a Job, an upgrade hook, a restore, or a compatibility shim — does not. Confirm the alternate route *and* the object it actually produces.

**C3 — Namespace / label trust confusion.** NetworkPolicy, admission rules, secret access, or workload-identity binding keys off namespaces, names, annotations, or labels that a principal of lower trust is free to set itself. Compare who controls the selector against what the match grants.

### D. Secrets and configuration lifecycle

**D1 — Precedence drift silently weakens a control.** Dev defaults, chart values, env vars, CLI flags, feature gates, injected sidecars, or a per-region overlay turn off authentication, TLS, tenant scoping, or audit logging in a real environment. Render the *final* config per maintained deployment, rather than reading only the base template.

> *Example:* `values.yaml` sets `auth.enabled: true`, but `values-staging.yaml` overlay flips it to `false` and staging is internet-reachable. The confirmed finding is the rendered staging object, not the base file.

**D2 — Secrets cross a workload boundary.** Secrets leak into logs, crash dumps, process arguments (`ps`-visible), a shared environment, a broadly mounted volume, build artefacts, service discovery, or a read API another workload or tenant can hit. Check the secret's *type* and authority — a public endpoint, a key ID, or an account number is not itself a credential.

> *Example:* a pipeline prints the full `env` for debugging, and `DB_PASSWORD` for the salary database rides along into the CI log, which contractors can read. Confirmed secret-in-pipeline exposure.

**D4 — IaC / deployment config (and the keys inside it) committed into the source tree.** Infrastructure-as-code and deployment descriptors belong in the repo by design, so the finding is not their mere presence — it is a *secret or private key living inside one*, or an IaC/config file *misplaced where it becomes reachable or should never have been versioned at all*. Read the actual contents of: Terraform (`*.tf`, and especially `*.tfvars` and committed `*.tfstate`, which stores resolved values in clear), Kubernetes `Secret` manifests (base64 is encoding, not protection) and other manifests, Ansible vars/inventories, Helm `values*.yaml`, `docker-compose*.yml`, CI YAML (`.github/workflows`, `.gitlab-ci.yml`, etc.), and cloud/service config (`serverless.yml`, `*.pem`/`*.key`, service-account JSON, `kubeconfig`, `.npmrc`/`.pypirc` with tokens). Two things promote a config file to a finding: (1) it carries a real credential, private key, connection string, or signing secret — trace the key *type* and the authority it grants, the way §D2 does; and (2) it sits under a path the application actually serves — IaC, a `.tfstate`, a `docker-compose.yml`, or a `.env` dropped into `public/`, `static/`, a web root, or a container layer the runtime exposes, making it fetchable over HTTP. A committed private key or live credential in any of these is `confirmed` (and, as with git history generally, deletion does not undo exposure — rotation is required). A plausibly-reachable IaC/state file under a web-served path is `confirmed`; if whether that path is actually served depends on deployment config you cannot see, `needs_validation` naming the file and the serving question. For the credential-type taxonomy and the placeholder test, cross-check `secrets-and-config.md`.

**D3 — Renewal / outage fallback leaves stale or weaker identity.** When a workload credential is not mounted, refreshed, rotated, or revoked on schedule, a stale credential stays live, or the app silently accepts a less-trusted identity mode on outage. Inspect startup, readiness, reconnect, and cached-client behaviour.

### E. Managed storage, events, and edge runtimes

**E1 — Bucket / signed-URL policy confusion.** Bucket or container policy, object-key layout, CDN origin config, or signed URLs fail to pin principal, operation, object namespace, audience, or expiry. Do not stop at reads — review `List`, versioning, and write/upload paths too.

> *Example:* a signed URL for uploading a PAN-card image has no object-key prefix constraint and a 7-day expiry, letting the holder overwrite any applicant's document. The list/write surface, not just the read, is the finding.

**E2 — Event-source identity confusion.** A worker or function takes fields in the event *body* as the source identity without validating the provider-signed envelope, the subscription/topic, the account, the region, and replay state. Lay the dead-letter, retry, pull, and push paths side by side — they often differ.

**E3 — Edge/origin boundary mismatch.** A serverless or edge runtime presumes a tenant policy, isolation model, filesystem, API, or secret that is not the same at the origin runtime, and falling back to origin shifts the authority or the cache behaviour. Confirm which config selects each path.

## Cross-cutting moves

Apply these over the whole catalogue, not to one class:

- **Build the environment matrix.** For every maintained environment, render it and tabulate: external ports, workload identity, network peers, mounted secrets, and the cloud resources touched. Any difference between environments needs an owner or a policy to explain it.
- **Follow the taint into IAM.** Take a low-trust event, label, object, or request and trace it until a cloud call fires. Name the exact workload credential that performs the final operation and the condition that *should* have scoped it.
- **Diff the unusual paths.** Normal deploy is the easy case. Also diff migration, restore, node drain/maintenance, failover, and the local/emulator path. Then ask what happens when the mesh, admission controller, identity service, secret store, or policy engine is unavailable — fail-open is where findings hide.

## Validation gate (run before you report ANY finding from this file)

1. Fix the **active source path** and the **effective deployed object**. If you cannot, the verdict is `needs_validation`, and you must name the rendered manifest or the owner-observed attachment that is missing.
2. Spell out the chain: the lower-trust caller or workload, the cloud or application identity, the controllable selector, the affected resource, and the unauthorised operation or disclosure.
3. Check the orchestrator and provider **defaults that ship with the pinned version**. Never assume a public IP, a reachable metadata service, a permissive firewall, or an attached admission webhook — verify or downgrade to `needs_validation`.
4. Local checks may render templates, evaluate policy (e.g. OPA/conftest on the rendered output), examine container/user namespaces within an isolated fixture, or stand up an emulator carrying dummy identities. Never probe a live endpoint and never mutate a shared cloud resource.
5. Grade `confirmed` only when a complete active-source trace pairs with a concrete boundary result. Otherwise return `needs_validation` (also written `needs validation`) naming the exact deployed policy, identity binding, overlay, network wiring, or drift observation still required.
