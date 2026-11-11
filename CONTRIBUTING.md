<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Contributing

Thank you for helping make AI security audits more trustworthy.

## Good first contributions

- **A new checklist entry** that real audits keep finding, with the confirmed-when condition and the smallest fix.
- **A new bundled Semgrep rule** in `skills/ai-security-audit/semgrep-rules/`, plus a planted example in `tests/fixtures/` and a line in the CI check.
- **A false-positive pattern** you have seen AI reviewers fall for, added to `rules/false-positive-patterns.md`.
- **Stack detection** for a framework we miss, in `scripts/aisa_lib/stack.py`.
- **DPDP evidence** patterns in `skills/ai-dpdp-audit/reference/dpdp-obligations.md` or `scripts/aisa_lib/pii.py`.

## Rules

1. Keep the evidence bar. Nothing may make it easier for an unproven finding to reach a report.
2. Keep the engine standard-library only, except python-docx (required) and jsonschema/cvss (optional).
3. Run `python -m unittest discover -s tests` before opening a pull request. Tests must pass on Windows, macOS and Linux.
4. Keep the file header on every file you add (author, GitHub, LinkedIn, MIT). Contribute only original writing, or material you hold the rights to release under the MIT License.
5. Plain English. Short sentences. Explain a term the first time it appears.
6. Never commit real secrets or real personal data, including in fixtures.
