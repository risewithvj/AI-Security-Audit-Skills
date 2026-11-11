<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Phase 0: Scope and safety gate

Goal: agree what is audited, by whom, and under which rules, before reading any code in depth. Takes one or two minutes.

## Steps

1. **Run the doctor.**
   `python <skill dir>/scripts/aisa.py doctor`
   Note which scanners are missing. Offer the printed install commands once. Continue either way.

2. **Confirm the target and scope** in one short message (skip anything the user already said):
   - Target folder (default: current project root).
   - Scope: whole repo, or named folders/services. Anything outside scope is recorded `out_of_scope`, never `covered`.
   - Profile: `quick`, `standard` (default) or `deep`. Propose `deep` when the app holds payments, HR, payroll, health, KYC or multi-tenant data.
   - Report details for the cover page: organisation or client name, application name, "Prepared by" and "Reviewed by" names. Defaults come from `~/.ai-security-audit/config.json` if it exists.

   If the user is not available to answer, use the defaults, say which ones at the top of the run, and continue.

3. **Create the run.**
   `python <skill dir>/scripts/aisa.py init --target "<target>" --profile <profile> [--scope "path1,path2"] [--client "..."] [--app "..."] [--prepared-by "..."] [--reviewed-by "..."]`

   This writes `run-metadata.json` and `stack.json` and prints the run folder path. Use that path as `<run>` in every later command.

4. **Read prior runs.** `init` lists earlier runs for the same repo. If one exists, read its `findings.json` and `coverage-ledger.json`:
   - A prior `confirmed` finding whose cited code is unchanged is re-verified, not re-hunted.
   - A prior `needs_validation`, `deferred` or `out_of_scope` unit becomes current work.
   - A prior `rejected` claim is not raised again unless the cited code changed.

5. **State the rules once** to the user, in two lines: read-only, source only, nothing executed from their code, no contact with their live systems, and the report will list what was not checked.

## Audit the project in place

Point `--target` at the project folder where it already lives and read it there. The audit is read-only, so there is no safety reason to copy it, and a copy loses `.git` (so Gitleaks cannot scan secret history) and can drift from the real code. Never duplicate the project just to audit it.

If a copy is genuinely unavoidable (for example the only access is a zip export), copy the **whole** folder including the `.git` directory so Gitleaks can still scan commit history, tell the user you are auditing a copy, and record the copy path and its source commit in `run-metadata.json`.

## Gate

Do not start Phase 1 until `run-metadata.json` exists. If `init` fails (for example the target path does not exist), stop and report the error. Never guess a target.
