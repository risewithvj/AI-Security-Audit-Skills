<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Phase 1: Recon and map

Goal: one accurate map of the system, so no later role has to re-read the whole tree. The map puts our "read once, reuse everywhere" discipline into practice.

## Inputs

- `stack.json` from `aisa.py init`: languages, frameworks, package managers, BaaS, IaC, CI, AI/LLM SDKs, mobile, entry-point guesses, and the checklists and Semgrep rule packs it suggests. It is a hint, not a fact; recon confirms or corrects it.

## Recon agents (run in parallel when sub-agents exist)

Each returns facts with repository-relative `file:line`. None of them reports findings or writes files.

**1a. Product and stack**
- What the product does, who uses it, who operates it, and which actions are trust-sensitive (money, PII, admin, data export).
- Languages, frameworks, versions from lockfiles, runtimes, and the deployment model visible in the repo (Dockerfile, IaC, `vercel.json`, `netlify.toml`, `firebase.json`, `supabase/`, Helm charts, serverless config).
- Entry points and subsystem boundaries.

**1b. Principals and controls**
- Each kind of user or caller (anonymous, signed-up user, tenant admin, platform admin, service account, webhook sender, cron, AI agent/tool) and what they may do by design.
- Where authentication happens for each surface. Where authorization happens per resource (ownership, tenant scope, role checks, RLS policies, security rules).
- Which controls live in the repo and which depend on something the repo does not show (cloud IAM, WAF, IdP config, dashboard settings).

**1c. Entry surfaces and sinks**
- Every place outside input enters: HTTP routes and server actions, GraphQL resolvers, RPC, queues and webhooks, file uploads, CLI args and env, cron payloads, deep links, model context and tool arguments, browser messages.
- For each, the main transformations and the security-relevant sinks (DB queries, HTML output, shell, file paths, outbound fetch, deserialisers, templates, payment calls, email/SMS, LLM prompts and tool calls).

**1d. Data inventory**
- Which sensitive data the system stores or moves: credentials, tokens, payment data, government IDs (Aadhaar, PAN, passport), bank accounts, salary, health, biometrics, children's data, location. Where it is stored, encrypted or not, and who can read it.

If the repo is large, add one focused recon agent per major subsystem instead of making the four agents shallower.

## Write `architecture.md` (parent, about 1,000 words max)

1. Product, principals, protected resources, sensitive data.
2. Stack and deployment model as visible in the repo.
3. The request entry points, and the source-to-sink paths that actually carry untrusted input.
4. Trust boundaries and the strongest control on each, with `file:line`.
5. Controls outside the repo that matter (these become `needs_validation` facts later).
6. Selected checklists and why each was selected (the boundary that needs it, not just a dependency name).
7. Skipped checklists and why, one line each.
8. Prior-run coverage gaps to prioritise.

## Seed `coverage-ledger.json` (parent)

One unit per material combination of **surface x boundary x attack class** (per subsystem for `deep`; coarser for `quick`). Format:

```json
{
  "coverage_id": "POST /api/payslips/:id::requireOwner::Access control",
  "surface": "POST /api/payslips/:id (src/routes/payslip.ts:14)",
  "boundary": "employee may read only own payslips",
  "subsystem": "api",
  "attack_class": "checklists/core-attack-classes.md#Access control",
  "checklists": ["checklists/api-authorization.md", "checklists/india-pii-hotspots.md"],
  "starting_paths": ["src/routes/payslip.ts", "src/controllers/payslip.ts"],
  "priority": 1,
  "status": "planned",
  "agent_id": null,
  "reviewed_paths": [],
  "result_ids": [],
  "notes": ""
}
```

Status values: `planned`, `in_progress`, `covered` (checked, nothing found), `candidate` (produced candidates; `result_ids` non-empty), `blocked` (partial, with reason in `notes`), `deferred` (not reached, reason in `notes`), `not_applicable`, `out_of_scope`. `covered`, `candidate` and `blocked` need non-empty `reviewed_paths`.

Priority 1 is money, auth, tenant/PII data, admin and file handling. Then everything else.

Check it:
`python <skill dir>/scripts/aisa.py ledger --run <run>`

Fix every error before Phase 2. The ledger is the coverage claim in the report; "auth reviewed" in prose is not coverage.

## Discipline check before leaving Phase 1

- Did any checklist get selected only because a package name appeared? Remove it unless a real boundary needs it.
- Is anything trust-sensitive missing from the ledger? Add it now; it is cheaper than a critic finding it later.
