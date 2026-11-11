<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# START: one-line audit for Claude Code

Use this when the skills are not installed and you just have this folder. Open Claude Code in the project you want to audit and type one line:

```
Read <path to>/AI-Security-Audit-Skills/START.md and run a full security audit of this project.
```

For the DPDP audit:

```
Read <path to>/AI-Security-Audit-Skills/START.md and run a DPDP audit of this project.
```

---

## Instructions for Claude Code

You were pointed at this file. Do this, in order, and do not skip the phase files:

1. Let `<kit>` be the folder that contains this START.md.
2. For a security audit, read `<kit>/skills/ai-security-audit/SKILL.md` and follow it exactly in full audit mode, with the current project as the target. For a DPDP audit, read `<kit>/skills/ai-dpdp-audit/SKILL.md` and follow it.
3. Run the engine from the kit: `python <kit>/skills/ai-security-audit/scripts/aisa.py ...` (`python3` on macOS/Linux). Start with `doctor`. If `python-docx` is missing, ask once to run `python -m pip install python-docx jsonschema cvss`.
4. Phase by phase, read the phase file before doing the phase: `phases/00-scope.md`, `01-recon.md`, `02-scanners.md`, `03-hunt.md`, `04-verify.md`, `05-report.md`. For each phase, use the matching prompt in `<kit>/prompts/` as your checklist.
5. Hard rules: read-only on the target; do not run the target's code; do not contact its live systems; never print secrets or personal data; no finding without file and line evidence that `aisa.py validate` accepts.
6. Finish with the report path and a five-line summary.

If a session ends mid-audit, a new session can resume with:

```
Read <path to>/AI-Security-Audit-Skills/START.md, run "aisa.py status", and continue the audit from where it stopped.
```
