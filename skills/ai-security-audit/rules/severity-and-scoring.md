<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Severity and scoring

Severity is assigned to a finding only once its verdict is `confirmed`. A finding still sitting at `needs_validation` carries no severity at all. The number you choose must mirror what the trace actually proves — the concrete outcome and the preconditions you were able to reach from source — and not the most alarming thing the bug could theoretically lead to.

## How to read the bands

Work from the demonstrated effect outward. Each band below is pinned to a worked anchor from an Indian HR / payroll / KYC setting so you can calibrate quickly. Place a finding at the band whose anchor it most closely resembles in *realised* impact.

| Band | What qualifies | Anchor finding |
|---|---|---|
| **Critical** | Code runs without any login, the whole datastore falls open, arbitrary accounts can be seized — or one ordinary logged-in account can read or rewrite the sensitive records of **every** tenant or employee. | A public `/export/payslips` route streams every employee's payslip PDF (with PAN and net pay) to anyone, no session required. |
| **High** | A named security control is completely beaten and the result has teeth. | A junior-HR session can call the salary-revision approval API for another company's employees (cross-tenant write); the PF-remittance webhook is processed even with no HMAC signature; the final payable amount in a vendor invoice is trusted straight from the client. |
| **Medium** | A genuine boundary is crossed, but the reach is small, the preconditions are unusual, or only a thin slice of data is touched. | An IDOR that discloses only an employee's designation and department (no identifiers); CSRF that toggles a non-critical notification preference; an SSRF that reaches only an allowlisted internal reporting host. |
| **Low** | Internal detail that is not a secret leaks, or the gain is tiny relative to the effort. | A 500 page on the KYC-upload form prints a full Java stack trace with the framework version; login timing lets you distinguish registered from unregistered emails on a low-value flow. |
| **Info** | Real but barely consequential — mostly useful as one link in a longer chain. | Payslip records use sequential numeric IDs, but ownership is correctly checked on every fetch, so the IDs reveal nothing exploitable. |

**Separating High from Medium.** Ask one question: for an action that matters, is the control *entirely* bypassed (High), or merely made weaker while still partly holding (Medium)?

## Let the data type pull the rating up

In HR, payroll, KYC, health and financial systems, "I can see another person's record" is never routine. Once the exposed record contains Aadhaar, PAN, passport, UAN, a bank account, salary figures, health or biometric data, children's data, or login credentials, treat the cross-record read as **High at minimum**, and usually **Critical**. Always spell out in the impact exactly which of these fields the attacker obtains — a reviewer should not have to guess.

## Calibrating edge cases

- **Derived figures weigh less than raw rows.** If a cross-tenant leak surfaces only aggregates — headcounts, a distribution of attendance statuses, salary totals, chart labels, computed percentages — and no actual personal rows, the right home is normally **Low** or **Medium**, not High. Reserve High and above for pulling another tenant's **raw personal records**: the names, phone numbers, emails and the sensitive fields listed above. Say outright in the impact which of the two you are looking at.
- **When the exploit hinges on an unguessable id you can't obtain.** Some attacks only work if you already hold another tenant's random identifier (say a UUID), and nothing in scope ever discloses one. This is still a real finding — do not wave it away as a false positive. Encode the constraint honestly: set **`AT:P`** (Attack Requirements: Present) in the vector, note in the impact that no reachable route emits that id, and keep the rating at the **bottom** of its band. Conversely, if any route does hand those ids out — a listing endpoint, an enumeration quirk, a log line — then it is **`AT:N`** and you should point to exactly where the leak is.

## Writing the CVSS 4.0 vector

Every `confirmed` finding ships with a CVSS 4.0 base vector and its score. Score the demonstrated behaviour, nothing more:

- **AV** — Network for anything reachable over a web route; Local only when the exploit genuinely demands local access.
- **AT** — Present when a race, a particular configuration, or some atypical runtime state has to line up first.
- **PR** — None for a fully anonymous attacker; Low for any registered user; High when admin rights are required.
- **UI** — None unless a victim has to click through or open something for the attack to land.
- **VC/VI/VA** describe the vulnerable system itself; **SC/SI/SA** describe knock-on systems — another tenant's data stored elsewhere, or a downstream service you can reach through this bug.
- **VI (Integrity)** — a write with no real consequence is `VI:N`, not `VI:L`. Choose `VI:N` when all the attacker can alter is something **no security-relevant logic ever reads back**: a view counter, a `last_login` timestamp, a telemetry or analytics field, or a cosmetic label that is always escaped before it is shown. Keep `VI:L` or `VI:H` for writes that steer a decision, a balance, a price, an access check, workflow state, or what another user ends up seeing. The test is simply: does any security-sensitive code consume this value later? If not, it is `VI:N`. The identical reasoning governs `SI` for a downstream system.

Emit the full vector string, for example `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`. Running `aisa.py validate` confirms the vector parses and that the severity band you declared lines up with the score band:

| Score | Band |
|---|---|
| 9.0 to 10.0 | Critical |
| 7.0 to 8.9 | High |
| 4.0 to 6.9 | Medium |
| 0.1 to 3.9 | Low |
| 0.0 | Info |

When the anchor table and the computed band pull in different directions, revisit the vector first — most mismatches are a mis-scored metric. Remember that CVSS 4.0 captures *technical* severity and has no idea whether the leaked rows are Aadhaar numbers or payslips. Because of that, the reported severity may sit **at most one band above** the CVSS band, and when it does, `severity_rationale` must justify the bump in a single sentence (for instance: "any logged-in employee can pull every colleague's Aadhaar and bank-account details"). It must never drop below the CVSS band. `aisa.py validate` enforces both the ceiling and the floor. Keep the vector itself honest and move only the reported severity, always with a stated reason.

## Confidence is a separate axis

Confidence is not severity; score it independently:

- **High** — the trace is complete, every candidate defence has been ruled out, and all 3 of 3 verifiers concur.
- **Medium** — the trace is complete, 2 of 3 verifiers agree, and the single dissenting view is recorded.
- A `confirmed` finding is never low-confidence. If confidence is that shaky, the verdict belongs at `needs_validation`, not `confirmed`.

## Ordering findings in the report

Rank primarily by severity. Within a band, promote findings that unlock the most other findings (chains rise to the top). As a final tie-breaker, surface the cheap fixes first so quick wins are visible early.
