<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Phase 5: Report

Goal: a report a CTO can read in five minutes and an engineer can fix from, built only from validated records.

## Build

```
python <skill dir>/scripts/aisa.py report --run <run>
```

This reads `run-metadata.json`, `findings.json`, `coverage-ledger.json` and `leads.json` and writes:

- `AI-Security-Audit-Report.docx`: the formal VAPT-style report.
- `AI-Security-Audit-Report.pdf`: when LibreOffice or Microsoft Word is available (`--pdf` to require it).
- `summary.md`: a short plain-text summary for the chat reply.

The report is generated from the records. Do not hand-write report content that is not in `findings.json`; if something is missing, fix the record and rebuild.

## Report structure

1. Cover page: application, target, date, testing type ("Source-code security audit, white-box"), overall risk rating, totals ("N Confirmed | M Require Verification"), classification, prepared by, reviewed by.
2. Executive summary: what was audited, the headline risk in plain English, the vulnerability summary table, severity distribution cards.
3. Scope and methodology: in-scope paths, stack, the six phases, scanners that ran (with versions) and those that did not, profile and verification votes.
4. Detailed findings: one block per confirmed finding with Location, Description, Business Impact, Root Cause, Evidence (trace with file:line), Recommendation (with code), Production risk of the fix, Regression test, CWE / OWASP / CVSS.
5. Findings requiring manual verification: each `needs_validation` with "Why it needs verification" and the exact safe check.
6. Dependency and secret hygiene: dependency CVEs present but not shown reachable, with fixed versions; secrets to rotate (redacted).
7. Coverage: ledger summary (covered, candidate, deferred, out of scope), leads raised vs traced vs dismissed, and **Not checked**.
8. Standards mapping: OWASP Top 10:2025, OWASP API 2023 and LLM 2025 where relevant.
9. Priority remediation order.
10. Compliance exposure (only regulations relevant to the data in scope; "puts at risk", not legal conclusions).
11. Disclosure and method note: source-only, no target code executed, no live systems contacted, generated with AI-Security-Audit-Skills.

## Reply to the user

After the report builds, reply with:

- the overall risk in one line and the counts by severity;
- the top three fixes in priority order, one line each;
- what was not checked, one line;
- the report file path(s).

Do not paste the whole report into the chat.
