<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Phase 4: Verify and de-duplicate

Goal: kill every false positive before it reaches the report. This phase is why the report can be trusted.

## 1. De-duplicate

Group candidates by root cause: same missing check in the same function, or the same broken helper used by many routes. One root cause becomes one finding with all affected locations listed. Keep the original candidate ids in `merged_from`.

## 2. Independent votes

For each unique candidate, start fresh **verifiers** with the prompt in [../templates/agent-prompts.md](../templates/agent-prompts.md#verifier).

**Vote by risk, not by profile (saves tokens without losing accuracy).** Spend the three-vote jury only where a wrong call is expensive; wave the cheap stuff through with one vote, but never let a single vote silently overturn the hunter. This is the `vote_policy` in `run-metadata.json`:

| Candidate severity (hunter's claim) | Votes |
|---|---|
| **Critical / High** | 3 independent verifiers |
| **Medium / Low / Info** | 1 verifier |
| Single vote **disagrees with the hunter** (confirms→rejects, or raises/lowers severity) | re-run with 3 before deciding |

`deep` adds one more fresh verifier re-checking every final Critical/High record. A `quick` or `small --budget` run still uses 3 votes for Critical/High — risk overrides the profile here. State the vote count you used on each finding.

Each verifier receives only: the claim (title, attacker, control, intended rule, result), the cited locations, `architecture.md`, the matching checklist, [../rules/evidence-gate.md](../rules/evidence-gate.md) and [../rules/false-positive-patterns.md](../rules/false-positive-patterns.md). It does **not** receive the hunter's reasoning or any other vote. Its job is to **refute**.

Each verifier:

1. Re-reads every cited `file:line` and confirms the code is there.
2. Rebuilds the path from a real entry point and names every defence on it (middleware, guards, schema validation, ORM scope, RLS, framework default).
3. Runs the 15 false-positive patterns.
4. Writes the devil's-advocate paragraph, then decides.
5. Returns `{"vote": "confirmed|needs_validation|rejected", "reason": "...", "corrected": {...}}`. `corrected` holds a fixed trace, title, severity or missing fact when the claim was partly wrong.

## 3. Decide

| Votes | Verdict |
|---|---|
| All `confirmed` (or 1 of 1 in quick) | `confirmed`, confidence High |
| 2 `confirmed`, 1 other | `confirmed`, confidence Medium, dissent recorded |
| Majority `needs_validation`, or confirmed votes depend on an outside fact | `needs_validation` with the missing fact |
| Majority `rejected` | `rejected` with the reason |
| Any split you cannot settle from source | `needs_validation` |

Never upgrade a verdict past what the votes support. A tie never becomes `confirmed`.

## 4. Write `findings.json`

The parent writes the final records using [../schema/findings.schema.json](../schema/findings.schema.json): ids `F-01`, `F-02`, ... for confirmed by priority; `V-01`, ... for needs_validation; `R-01`, ... for rejected. For each confirmed finding fill the full record (see the schema): plain-English summary, business impact, root cause, CWE, OWASP, CVSS 4.0, the smallest safe fix with a code example, the production risk of that fix, and one regression test.

## 5. Validate (machine check)

```
python <skill dir>/scripts/aisa.py validate --run <run>
```

It checks, and fails the run until fixed:

- the schema for every verdict;
- severity and CVSS only on `confirmed`, vector syntax valid, severity band matches score;
- **every cited file exists in the target and every snippet matches the cited line** (within 3 lines, to allow for small edits);
- no unredacted secrets anywhere in the record;
- every confirmed finding has a fix, a production-risk note and a regression test;
- no "might", "could potentially", "consider" in confirmed titles and summaries;
- every ledger unit referenced exists.

Fix errors by correcting the record, never by weakening the check.

## 6. Chains

Run the exploit-chain pass from [../rules/false-positive-patterns.md](../rules/false-positive-patterns.md#Exploit chains). A new chain candidate goes through steps 2 to 5 like any other.
