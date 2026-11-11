<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

<div align="center">

<img src="docs/assets/readme-hero.svg" alt="AI Security + DPDP Audit — one prompt, any AI, or a Claude Code CLI. Proof-backed source-code review." width="100%" />

[![Release](https://img.shields.io/github/v/release/risewithvj/AI-Security-Audit-Skills?style=for-the-badge&color=FF2A1F)](https://github.com/risewithvj/AI-Security-Audit-Skills/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/risewithvj/AI-Security-Audit-Skills/ci.yml?style=for-the-badge&label=CI)](https://github.com/risewithvj/AI-Security-Audit-Skills/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-FF2A1F?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/risewithvj/AI-Security-Audit-Skills?style=for-the-badge&color=FFD700)](https://github.com/risewithvj/AI-Security-Audit-Skills/stargazers)
[![Pages](https://img.shields.io/website?url=https%3A%2F%2Frisewithvj.github.io%2FAI-Security-Audit-Skills%2F&style=for-the-badge&label=live%20site&up_color=138808)](https://risewithvj.github.io/AI-Security-Audit-Skills/)

**[🌐 Get your prompt](https://risewithvj.github.io/AI-Security-Audit-Skills/) · [📊 Benchmark scorecard](https://risewithvj.github.io/AI-Security-Audit-Skills/benchmark/juice-shop-web-ai.html) · [🧾 Sample report](examples/sample-security-audit-report.pdf)**

</div>

---

## What it is

A **proof-backed source-code security + India DPDP audit** you run two ways: paste **one prompt** into any AI with your project zip, or install the **Claude Code** skills and ask it to audit the repo. Every confirmed finding carries **file-and-line evidence**; it is **recommendations only** and never modifies your code.

> **No case, no finding. No proof, no severity. No guess, ever.**

**Jump to:** [Quick start](#quick-start) · [Benchmark](#benchmark) · [Features](#features) · [How it works](#how-it-works) · [Sample report](#sample-report) · [FAQ](#faq) · [Roadmap](#roadmap)

---

## Quick start

<details open>
<summary><b>🌐 Web AI — no install</b></summary>

1. Zip your project (drop `.git`, `node_modules`, builds — never `.env`).
2. Open the **[prompt picker](https://risewithvj.github.io/AI-Security-Audit-Skills/)**, choose a tier (Lite / Pro / God / Deep 4-pass), copy the prompt.
3. Attach the zip to any AI (ChatGPT, Claude.ai, Codex, Gemini…), paste, send.

You get vulnerabilities with file + line + fix, hardening notes, and an honest "Not checked" list. Nothing runs on your machine and your code is sent nowhere by the prompt.
</details>

<details>
<summary><b>⌨️ Claude Code — CLI skills</b></summary>

**Windows (PowerShell)**
```powershell
git clone https://github.com/risewithvj/AI-Security-Audit-Skills; powershell -ExecutionPolicy Bypass -File .\AI-Security-Audit-Skills\install\install.ps1
```
**macOS / Linux (bash)**
```bash
git clone https://github.com/risewithvj/AI-Security-Audit-Skills && bash AI-Security-Audit-Skills/install/install.sh
```
Add `-WithScanners` / `--with-scanners` to bundle Semgrep + Gitleaks. Then in Claude Code: *"run a full security audit of this project"* (or *"a DPDP audit"*). No install at all? See **[START.md](START.md)**.

Two skills, one kit:

| | Skill | What it does |
|---|---|---|
| 🔍 | **`/ai-security-audit`** | White-box source audit of any stack — web, API, mobile, cloud/IaC, AI/LLM, MCP |
| 🇮🇳 | **`/ai-dpdp-audit`** | India **DPDP Act 2023 + Rules 2025**: PII map, consent, safeguards, breach readiness, erasure, rights |

</details>

---

## Benchmark

Fresh **v1.5.1** run on **OWASP Juice Shop**, scored against a **mechanically-frozen Core 30** (picked from Juice Shop's own categories/tags before scoring — [the rule](tests/benchmark/core30.md)). Same rules for every tool.

| Tool | Core / 30 | Full / 60 (strict) | Full / 60 (coverage) | False positives |
|---|:---:|:---:|:---:|:---:|
| **AISA CLI (this engine)** | **25** | **46** | **53** | 0 |
| Codex (web) | 11 | 23 | 46 | 0 |
| Claude.ai (web, partial) | 10 | 23 | 45 | 0 |
| ChatGPT (web) | 7 | 18 | 48 | 0 |
| Gemini Pro (web) | — refused — | | | |
| **Web-AI union** | **14** | **29** | **53** | 0 |

On the Core 30 the CLI found **more than twice** any single web AI and **more than all three combined**. On the looser coverage metric the field is close — the engine's edge is **precision and completeness**. **0 false positives** across every tool **on Juice Shop** (a deliberately vulnerable app, so this measures precision only on known-vulnerable code).

**→ [Full per-challenge scorecard](https://risewithvj.github.io/AI-Security-Audit-Skills/benchmark/juice-shop-web-ai.html)** · **[Executive one-pager (PDF)](https://risewithvj.github.io/AI-Security-Audit-Skills/benchmark/executive-scorecard.pdf)**

---

## Features

| | |
|---|---|
| 🔬 **Proof-gated** | A finding needs file + line + attacker + impact, independently verified, or it never ships. |
| 🧰 **Scanners built in** | Semgrep (34 offline rules too), Gitleaks, Trivy, OSV — folded into the AI hunt, not dumped as noise. |
| 🧱 **Any stack** | Web, API, WordPress, Apps Script, mobile, AI/LLM + MCP, BaaS, e-commerce, cloud/IaC. |
| 🇮🇳 **DPDP built in** | India DPDP Act 2023 + Rules 2025 as a first-class audit, auto-folded in when PII is found. |
| 🧾 **VAPT reports** | DOCX + PDF: executive summary, methodology, CVSS 4.0, OWASP 2025 / API / LLM mapping, fixes. |
| 🔒 **Read-only** | Recommendations only. Your code is never modified, run, or sent anywhere. |

---

## How it works

```mermaid
flowchart LR
  A[Zip / repo] --> B[Recon & map]
  B --> C[Scanners<br/>Semgrep · Gitleaks · Trivy · OSV]
  C --> D[AI hunt<br/>per attack class]
  D --> E{Evidence gate<br/>file + line + proof}
  E -- confirmed --> F[Verify<br/>refutation votes]
  E -- unproven --> G[Needs validation]
  F --> H[VAPT report<br/>DOCX + PDF]
```

Read-only and source-only: the engine reads code and runs the bundled scanners; it never runs, serves, or contacts your app.

---

## Sample report

<div align="center">
<img src="examples/assets/report-cover.png" alt="Sample report cover: Source Code Security Audit Report for OWASP Juice Shop, 28 confirmed findings, v1.5.1" width="47%" />
<img src="examples/assets/report-findings.png" alt="Sample report findings page with severities, CWE and OWASP mapping" width="47%" />

**[Security report (PDF)](examples/sample-security-audit-report.pdf)** · **[DPDP report (PDF)](examples/sample-dpdp-audit-report.pdf)** · [DOCX versions](examples/)
</div>

Each confirmed finding includes location, plain-English summary, business impact, root cause, the **source trace with file and line**, the smallest safe fix with code, what the fix could break, a regression test, CWE, OWASP/API/LLM mapping, CVSS 4.0, and verifier votes.

---

## FAQ

<details><summary><b>Is my code safe?</b></summary>Yes — read-only and recommendations only; nothing is modified, and the web prompt runs inside the AI you already use. Strip <code>.env</code> and real secrets before zipping, as a habit.</details>
<details><summary><b>Free vs paid AI?</b></summary>Free/smaller AIs get <b>Lite</b> (top risks, one page). Paid tiers run the full <b>Pro</b> audit, with <b>God</b> and the <b>Deep 4-pass</b> for the deepest review.</details>
<details><summary><b>Why zero false positives?</b></summary>Juice Shop is deliberately vulnerable, so "0 FP" there measures precision only on known-vulnerable code — not real-world noise. Every finding still needs file-and-line proof.</details>
<details><summary><b>Does it fix my code?</b></summary>No. It describes the smallest safe fix for each finding; your project is never changed.</details>
<details><summary><b>What is DPDP?</b></summary>India's Digital Personal Data Protection Act 2023 (+ Rules 2025). The DPDP pass checks notice, consent, safeguards, breach readiness, retention/erasure, rights, children's data and transfers against your code.</details>

---

## Roadmap

- [x] **v1.6** — redesigned landing page + analytics, new README, HD images, GitHub polish
- [x] **v1.5** — tiered web prompts, lean auto-profile CLI, mechanical Core 30 benchmark, web-AI scorecard
- [x] **v1.4** — original content + originality gate, no-install web version, honest benchmark scoring
- [ ] Optional live staging verification (OWASP ZAP) behind an explicit authorization gate
- [ ] Fix-branch helper: one finding per commit with regression tests, then auto re-audit
- [ ] SARIF export for GitHub code scanning

---

## Contributing & security

Issues and PRs welcome — templates included (bug, false positive, feature, new stack). See **[CONTRIBUTING.md](CONTRIBUTING.md)**. Report vulnerabilities per **[SECURITY.md](SECURITY.md)**. Audit only code you own or are authorized to review.

---

<div align="center">

### 👨‍💻 Author

**Vijaya Kumar L** · *Rise With VJ* — Lead, Application Engineering

[![GitHub](https://img.shields.io/badge/GitHub-risewithvj-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/risewithvj)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-vijayakumarl-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/vijayakumarl/)

If this saved you a week of security review, **⭐ star the repo** so other builders find it.

`claude-code` `agent-skills` `security-audit` `vapt` `appsec` `owasp` `sast` `dpdp` `ai-security` `devsecops`

<sub>© 2026 Vijaya Kumar L · risewithvj · MIT License</sub>

</div>
