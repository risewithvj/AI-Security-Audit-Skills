<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# The evidence gate

Nothing reaches `confirmed` on confidence alone. A candidate has to assemble a complete case, drawn entirely from the source, before it clears the gate. The moment a single required piece is missing, it is not confirmed — full stop.

## The case a finding must build

Picture the gate as a form with six required fields. The source has to supply an answer for all six; a blank anywhere stops the finding.

| # | Field | What it establishes | Illustration (HR/payroll app) |
|---|---|---|---|
| 1 | **Attacker** | The lower-trust principal doing the acting | "any authenticated employee", "an unauthenticated internet visitor", "a tenant admin belonging to org B" |
| 2 | **Input under their control** | The thing the attacker gets to send or choose | "the `employeeId` path parameter on `GET /api/payslips/:employeeId`" |
| 3 | **Rule that should hold** | The control meant to stop this | "an employee may only view their own payslips" |
| 4 | **Reachable trace** | Entry point through to sink, each hop as `file:line` with the code on that line | `routes/payslip.ts:14` → `controllers/payslip.ts:31` → `repo/payslip.ts:52` |
| 5 | **Where the rule fails** | The exact point the check is absent or broken | "nothing between line 31 and line 52 compares `req.user`; the owner is never checked" |
| 6 | **Concrete result** | The specific bad outcome that follows | "another employee's payslip PDF is returned, bank account number and all" |

Two further conditions apply before the verdict can be `confirmed`:

- **Defences were examined and ruled out.** The verifier enumerates every control on the traced path that might have stopped the attack — middleware, decorators, ORM scopes, row-level security, any gateway rule visible in the repo, framework defaults — and shows, with `file:line`, why each one does not apply here.
- **A second, independent read agrees.** Verifiers who did not hunt the issue arrive at `confirmed` on their own. See [../phases/04-verify.md](../phases/04-verify.md).

## The three verdicts

Exactly three outcomes exist. The vocabulary is fixed.

| Verdict | When it applies | Carries severity? | How it lands in the report |
|---|---|---|---|
| `confirmed` | All six fields filled from source, defences eliminated, independent verifiers concur | Yes | As a vulnerability |
| `needs_validation` | A specific, source-grounded hypothesis, blocked by **exactly one named fact the repo cannot show** — a proxy rule, a cloud policy, an IdP setting, a production environment value, a runtime behaviour | **No** | As "requires manual verification", paired with the precise safe check that would settle it |
| `rejected` | The source contradicts it, or one of the fields simply cannot be filled | No | Not in the report body; retained in `findings.json` for re-runs and surfaced only as a count |

Treat `needs_validation` as its own category, not a weaker shade of confirmed. It is a sharp question handed to the owner: "this is what I found in the code, and this single external fact decides whether it bites." If you cannot name that one missing fact, the candidate does not qualify for `needs validation` — it is `rejected`.

## Things that never clear the gate

- **A bare hygiene gap.** A missing security header, an unset cookie flag, no rate limit, no MFA prompt, a generic "not best practice" — none of these pass by themselves. They pass only once you demonstrate the injection, account takeover, cross-user read, or unauthorised spend they actually enable.
- **Assumptions about anything outside the repo.** Behaviour you are guessing at for a CDN, WAF, cloud IAM policy, Supabase dashboard setting or Vercel environment variable is not confirmable from source. That is `needs_validation`.
- **A user who can only affect themselves,** or who is simply doing what their role is meant to permit.
- **A raw scanner hit nobody traced** to a reachable sink.
- **A dependency CVE with no reachability shown.** You must demonstrate that the vulnerable function is actually reached, or at minimum that the package loads in production. A CVE that is present but never shown reachable belongs in the dependency table as "present, not shown reachable" — never as a confirmed vulnerability.

## Severity cannot outrun the proof

The severity you assign is capped by the result you actually demonstrated. If you cannot state the concrete damage in one plain sentence, the true severity sits below where your instinct wants to put it. Scoring details live in [severity-and-scoring.md](severity-and-scoring.md).
