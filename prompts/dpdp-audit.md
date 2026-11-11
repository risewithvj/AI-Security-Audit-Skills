<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# DPDP Act audit (all phases)

```
Read <kit>/skills/ai-dpdp-audit/SKILL.md and <kit>/skills/ai-dpdp-audit/reference/dpdp-obligations.md and run a full DPDP audit of this project.
Start with: python <kit>/skills/ai-security-audit/scripts/aisa.py init --target . --framework dpdp
Then: aisa.py pii --run "<run>" for the PII inventory, the obligation review by group G1 to G12, independent verification, aisa.py validate, and aisa.py report.
Never print personal data values. Mark anything that depends on contracts, policies or dashboards as needs_validation, not as a gap. End with: this is an engineering review, not legal advice.
```
