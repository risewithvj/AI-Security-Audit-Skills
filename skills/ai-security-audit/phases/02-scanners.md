<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Phase 2: Scanners

Goal: let fast, cheap tools find the pattern-shaped leads so the AI spends its effort on what tools cannot see.

## Run

```
python <skill dir>/scripts/aisa.py scan --run <run>
python <skill dir>/scripts/aisa.py normalize --run <run>
```

`scan` runs whichever of these are installed, read-only, against the target:

| Tool | Finds | Mode used |
|---|---|---|
| Semgrep (Community) | Insecure code patterns across 30+ languages | Rule packs chosen from `stack.json` (`p/default`, `p/owasp-top-ten`, plus stack packs). Uses `--metrics=off`. Needs network the first time to fetch rule packs; if offline it falls back to the cached or bundled rules and says so |
| Gitleaks | Secrets in files and Git history | `gitleaks detect --redact` (history included when `.git` exists) |
| Trivy | Vulnerable dependencies, IaC and Dockerfile misconfiguration, secrets | `trivy fs --scanners vuln,misconfig,secret` |
| OSV-Scanner | Known vulnerabilities in lockfiles | `osv-scanner scan source -r` |

Each tool writes to `raw/`. A tool that is missing, times out or fails is recorded in `run-metadata.json` under `scanners` with the reason, and the report lists it under "Not checked". Never claim a check ran when it did not.

`normalize` merges all tool output into `leads.json`: one record per lead with tool, rule, CWE, file, line, message, a stable fingerprint, and duplicates across tools merged. Secrets are already redacted.

## Rules for leads

- **A lead is not a finding.** Every lead goes to a hunter as a starting point, inside the ledger unit that owns its file, or is closed with a reason.
- **Triage leads, do not copy them.** For each lead decide in one line: `trace` (send to a hunter), `noise` (test file, vendored code, placeholder, unreachable, with the reason), or `dependency` (handled below).
- **Dependencies.** A dependency CVE becomes a candidate only if the vulnerable function or feature is used on a reachable path, or the advisory says the package is unsafe in any use. Otherwise it goes to the report's dependency table as "present, not shown reachable", with the fixed version. This keeps the report honest and short.
- **Secrets.** A secret hit becomes a candidate when it is a real credential (not a placeholder, not a test key with no real access) in a file that is committed or shipped (client bundle, mobile app, Docker image layer). A secret only in Git history still counts: it must be rotated. Never print the value.

Record the triage in `leads.json` (`triage` and `triage_reason` fields) so the report can say how many leads were raised, traced and dismissed.
