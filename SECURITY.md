<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Security policy

## Reporting a vulnerability in this project

Please do not open a public issue. Use GitHub's **Report a vulnerability** (private vulnerability reporting) on this repository, or email **risewithvj@gmail.com** with "AI-Security-Audit-Skills security" in the subject. Include the affected file, what an attacker could do, and steps to reproduce. You will get a reply within 5 working days.

Examples of in-scope issues:

- A way for text inside an audited repository to make the skill run commands, skip checks, or change the report (prompt injection).
- The engine writing outside the run folder, modifying the audited target, or leaking secrets or personal data into reports.
- The validator accepting a finding whose cited code does not exist.

## Using this project responsibly

- Audit only code you own or are authorized to review.
- The skills are read-only and source-only by design: they do not execute the target's code or contact its live systems. Do not modify them to do so without written authorization from the system owner.
- Reports contain sensitive information. Store and share them as confidential documents. Run folders are created outside the audited repository so they are not committed by accident.
- The DPDP skill is an engineering review, not legal advice.
