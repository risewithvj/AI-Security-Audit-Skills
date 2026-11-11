<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Phase 4: Verify and de-duplicate

```
Continue the audit. Read <kit>/skills/ai-security-audit/phases/04-verify.md and <kit>/skills/ai-security-audit/rules/false-positive-patterns.md.
De-duplicate candidates by root cause. For each, run fresh, isolated verifiers with the Verifier prompt (votes per the profile). Decide verdicts by the table in 04-verify.md.
Write findings.json following <kit>/skills/ai-security-audit/schema/findings.schema.json, then run:
python <kit>/skills/ai-security-audit/scripts/aisa.py validate --run "<run>"
Fix records until it passes. Never weaken a check. Run the exploit-chain pass. Show me the verdict counts. Stop after Phase 4.
```
