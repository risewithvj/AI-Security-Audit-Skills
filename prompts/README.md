<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Phase-by-phase prompts

Paste one prompt at a time into Claude Code inside the project you want to audit. Each prompt runs one phase and stops, so you can review before moving on. If the skills are installed, `/ai-security-audit` runs all phases in one go; these prompts are for step-by-step control or for using the kit without installing.

`<kit>` means the folder of this repository. Use `python` on Windows and `python3` on macOS/Linux.

| Step | Prompt file | What you get |
|---|---|---|
| 0 | [00-scope.md](00-scope.md) | Run folder, stack detection, agreed scope |
| 1 | [01-recon.md](01-recon.md) | `architecture.md` and the coverage ledger |
| 2 | [02-scanners.md](02-scanners.md) | `leads.json` with triage |
| 3 | [03-hunt.md](03-hunt.md) | `candidates.json` |
| 4 | [04-verify.md](04-verify.md) | Validated `findings.json` |
| 5 | [05-report.md](05-report.md) | DOCX/PDF report and summary |
| DPDP | [dpdp-audit.md](dpdp-audit.md) | DPDP Compliance Audit Report |
| Resume | [resume.md](resume.md) | Continue a stopped run |
