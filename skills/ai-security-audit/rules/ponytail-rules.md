<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Auditor working discipline

A single sentence drives everything in this file: **a finding counts only if you can demonstrate it, and the right remedy is the narrowest change that shuts the hole.** The discipline below applies to every role in the pipeline — recon, hunter, verifier, critic, reporter. None of these roles gets to skip it.

## 1. Where to spend effort

Attention is the scarce resource in an audit, so budget it deliberately.

- **Build the map before you go hunting.** Recon reads the project once — the README, build and deploy configuration, dependency manifests, every entry point (HTTP routes, event handlers, scheduled jobs, CLI commands, queue consumers) and the test suite — and records the result in `architecture.md`. From then on, every downstream role works off that map instead of walking the tree again.
- **Only test what is actually present.** A Django service gets no Supabase checks; code with no JWT gets no JWT checks. The loaded checklists are decided by `stack.json`, nothing else. Anything that was deliberately not loaded is listed in one line under "Not checked".
- **Concentrate on the expensive mistakes.** Money movement, authentication, tenant-scoped data, PII, file upload and download, admin-only actions, async/background work, and any state shared across processes deserve depth. In an Indian HR product that means payroll runs, PF/ESI postings, PAN/Aadhaar/UAN fields and payslip retrieval long before it means a settings page. Plain CRUD gets read only when a trace actually walks into it.
- **Let the scanners do the pattern work.** Semgrep, Gitleaks, Trivy and OSV-Scanner are cheap and tireless at spotting shape-matched leads. Reserve human reasoning for what no scanner sees: who is allowed to do what, business rules, isolation between tenants, and the trust assumptions between services.
- **One assignment, one question.** A hunter receives a single ledger unit paired with a single attack class. Many small, bounded tasks outperform one agent trying to hold the whole codebase in its head.
- **Stop once the invariant is decided.** The moment you can write either "safe because X at `file:line`" or "vulnerable because Y at `file:line`", that path is finished. Reading further is wasted spend.

## 2. Claim nothing you cannot exhibit

Every assertion in an audit has to be backed by something you can point at.

- **No story, no finding.** A candidate must name the attacker, the input they supply, the code that input reaches, and the wrong thing that then happens. Miss any of those four and you do not have a finding yet.
- **Search the whole tree before using an absolute.** Words like "no auth check", "unused", "never validated" or "the only caller" are claims about the entire codebase. Before writing one, grep everywhere — routes, middleware, decorators, config, tests, and both string-based and dynamic references.
- **Cite lines that actually say what you claim.** Every location you reference must contain the code you are describing. `aisa.py validate` re-opens each cited line and fails the run when the quoted snippet does not match the file.
- **Hedging language disqualifies a confirmed finding.** "Consider", "might", "could potentially" have no place in something marked confirmed. If you are genuinely unsure, the verdict is `needs_validation`, accompanied by the single fact that would resolve it.
- **Aesthetics are not vulnerabilities.** Naming, formatting and generic "best practice" complaints are out of scope unless they tie to a reachable boundary being crossed.
- **A recorded trade-off is reviewed, not flagged.** When code carries a `shortcut:` marker or a comment justifying a safety decision, your job is to check whether that justification holds. It becomes a finding only when the stated reasoning is actually wrong.

## 3. Fixing: smallest change that holds

Think like a senior engineer who refuses to do more work than the problem demands. Walk this ladder and take the first rung that fully closes the gap:

1. **Can it simply be removed?** A debug route, an orphaned endpoint, a leftover admin toggle — deleting dead danger is the cleanest fix there is.
2. **Does the project already ship the right tool?** An existing guard, middleware, or policy helper, applied the same way the neighbouring code applies it.
3. **Does the platform already solve it?** Parameterised queries, built-in CSRF protection, the `secrets` module, ORM-level tenant scoping — use what the framework or standard library gives you.
4. **If none of the above,** make the smallest possible change at the last trusted decision point.

Do not propose a new framework, a rewrite, an extra architectural layer, or configuration the problem never asked for. Respect the existing structure. Spell out every caller, test and fixture the change touches, and state plainly what might break for real users.

## 4. Close with the honest boundary

Every report, and every intermediate agent result, finishes with two lines:

- **`Not checked:`** what you did not read, did not run, or treated as out of scope — in ordinary language.
- **`Assumed:`** the load and deployment posture you took as given (for example, "exposed to the public internet, many concurrent users").

Never state or imply that "the application is secure". State only what was examined.

## 5. Write so a non-engineer follows

Keep sentences short and words ordinary. The first time a technical term appears, explain it. Each finding opens with four plain-language beats, one or two sentences apiece:

- **What this is** — the feature or code in everyday terms.
- **Problem** — what an attacker gets out of it.
- **Fix** — the smallest change that stops it.
- **If we skip it** — the real-world cost of leaving it.

The full technical record — traces, line citations, defence analysis — sits below that summary for the engineers who will act on it.
