<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Phase 3: Hunt

Goal: work through the ledger, unit by unit, and return structured candidates that can be verified.

## Read the flagged files first (scanners-first)

Do not read the whole tree. A hunter opens, in full, only files that something already pointed at:

1. Files flagged by the scanners (`leads.json` — Semgrep/Gitleaks/Trivy/OSV hits and exposed-file leads).
2. Files on the **risk map**: `stack.json` → `likely_entry_files` and `india_pii_files`, plus whatever `architecture.md` marked trust-sensitive (auth, payments, tenant data, admin, uploads, background jobs).
3. Files matched by a **checklist trigger** for the detected stack (the checklist selected a surface that lives in this file).

Everything else is skimmed only when a trace from (1)–(3) leads into it. Any area never opened for this reason goes into the report's **Not checked** list by name, in one line. This keeps token spend on the code that actually carries risk.

## Budget scales the fan-out

`run-metadata.json` → `budget` sizes the waves (effort cap, not coverage of risk):

| `--budget` | Hunters per wave | Waves | Trade-off |
|---|---|---|---|
| `small` | fewest (highest-priority units only) | one wave + one critic | cheapest; lower-priority surfaces lean on scanners + the risk map and are named under Not checked |
| `normal` *(default)* | one hunter per planned unit | repeat until the critic adds nothing | balanced |
| `large` | adds variant hunters and a second critic pass | widest | most thorough; highest token spend |

Risk still wins: Critical/High surfaces are always hunted and always get the full verifier jury (Phase 4), whatever the budget.

## Waves

1. Take ledger units with status `planned`, highest priority first.
2. Give each unit to one **hunter** with the prompt in [../templates/agent-prompts.md](../templates/agent-prompts.md#hunter). The hunter gets: the unit, `architecture.md`, its leads from `leads.json`, the attack class block, the selected checklists, [../rules/ponytail-rules.md](../rules/ponytail-rules.md) and [../rules/evidence-gate.md](../rules/evidence-gate.md). Nothing else.
3. Hunters run in parallel and do not see each other's results.
4. The parent updates the ledger from each hunter's result: `covered`, `candidate`, `blocked` or `deferred`, with `reviewed_paths`.
5. After the wave, a **critic** reads the ledger and `architecture.md` (not the candidates) and lists gaps: missing surfaces, units marked covered on too few paths, attack classes never assigned to a high-priority surface. Accepted gaps become new `planned` units.
6. Repeat until a critic pass adds nothing (`standard`, `deep`) or after one wave plus one critic (`quick`). Units still open at the end are `deferred` with the reason.

## Always-on hunters (one each per run, regardless of the ledger)

- **Obvious things**: the literal checklist in [../checklists/core-attack-classes.md](../checklists/core-attack-classes.md#Obvious things). Thorough, not creative.
- **Insecure defaults**: [../checklists/insecure-defaults.md](../checklists/insecure-defaults.md).
- **Wildcard**: anything outside the standard classes, especially half-finished features, hidden routes and API calls the UI never makes.
- **Variant hunter** (after the first wave): for every candidate, search for the same pattern elsewhere. One IDOR usually means five.

## Candidate format

Each hunter returns JSON only:

```json
{
  "unit": "<coverage_id>",
  "reviewed_paths": ["src/routes/payslip.ts", "src/controllers/payslip.ts"],
  "candidates": [
    {
      "title": "Any employee can download any other employee's payslip",
      "class": "Access control / IDOR",
      "proposed_verdict": "confirmed",
      "attacker": "Any logged-in employee",
      "control": "employeeId path parameter",
      "intended_rule": "Employees may read only their own payslips",
      "trace": [
        {"file": "src/routes/payslip.ts", "line": 14, "snippet": "router.get('/payslips/:employeeId', auth, getPayslip)", "note": "entry; auth only checks login"},
        {"file": "src/controllers/payslip.ts", "line": 31, "snippet": "const slip = await repo.find(req.params.employeeId)", "note": "no ownership check"}
      ],
      "missing_check": "No comparison of req.user.id with employeeId before repo.find",
      "result": "Returns another employee's payslip PDF with bank account and salary",
      "missing_fact": null,
      "leads": ["semgrep:..."]
    }
  ],
  "not_checked": "Did not read the admin export path; out of this unit"
}
```

`snippet` must be copied exactly from the cited line (whitespace trimmed). The validator re-reads it.

For a `needs_validation` proposal, `missing_fact` names the one fact outside the repo that decides it, and `result` states what happens if that fact goes the wrong way.

The parent appends every candidate to `candidates.json` with an id `C-001`, `C-002`, ... and never edits a hunter's claim; corrections happen in Phase 4.
