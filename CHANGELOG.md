<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Changelog

## 1.4.0 (2026-11-11)

Originality pass, a no-install web version, honest benchmark scoring, and broader coverage.

- **Original by Rise With VJ.** Every adapted checklist, rule and phase was rewritten from scratch with new structure, our own tables, and Indian HR/payroll/KYC/DPDP examples. A new `tools/originality_check.py` fails on any shared 8-word prose sequence with the projects this work drew inspiration from, and reports **0**. Per-file "Adapted from" headers, `CREDITS.md` and `third_party/LICENSES/` are removed; the README and LICENSE credit only Rise With VJ with a single community-inspiration line.
- **Web version (no install).** A GitHub Pages landing page (`docs/index.html`) with per-AI copy-prompt buttons, one self-contained runbook (`docs/web/v1/runbook.md`) that treats the uploaded code as data, a compact paste-only prompt, and a single standard-library engine (`docs/web/v1/aisa_web.py`) that any AI with Python can run on a project zip: safe unzip (zip-slip and size caps), stack detection, regex/AST rules mirroring the bundled Semgrep set, a PII inventory, snippet re-read validation, and an HTML report (PDF when a library is available). Run the same audit through ChatGPT, Gemini, Claude.ai or Codex.
- **Honest benchmark scoring.** `aisa.py benchmark` now does exact `finding_id`/`challenge_id` mapping, matches short attack-class acronyms (XSS, RCE, SSRF, XXE, JWT), and reconciles "extra" findings against the labels before computing the false-positive rate. On OWASP Juice Shop this reconciles the two prior "extra" findings to their real challenges, giving a measured **0% false-positive rate** at **52/60 (87%)** source-visible challenges matched.
- **`--exclude` path globs** for `init` and `scan`, honoured process-wide by stack detection, the exposed-file sweep, and Semgrep.
- **Broader coverage** for classes a source-only audit tends to miss, all general (never benchmark-specific): stored XSS through an incomplete or bypassable sanitiser, unsigned/weakly-signed JWTs accepted by end-of-life libraries, reachable deprecated/legacy endpoints that skip current authorization, IaC and deployment-config files (and the keys inside them) committed to the tree, and forgeable coupon/voucher/referral tokens.
- **CI** no longer lets the SkillSpector job pass silently: it runs `--no-llm` JSON, writes a readable step summary, and fails only on HIGH/CRITICAL findings outside a reviewed, by-design allowlist. Every job gains a 20-minute timeout and the workflow cancels superseded runs per ref. A new job runs the web engine on the test fixture and asserts it finds the planted issues.
- **Sample report** replaced with the OWASP Juice Shop audit (DOCX + PDF) and a fresh preview image.

## 1.3.0 (2026-11-10)

Hardening from the Kora and company2 WordPress/Apps Script runs.

- **Semgrep health check**: `doctor` now runs a tiny real Semgrep scan (plants an obvious pattern in a temp file and confirms a results file is written with the hit) instead of trusting `--version`; a Semgrep that reports a version but cannot produce output is no longer "ok". `scan` retries in `--json` mode and converts JSON→SARIF when the SARIF output is missing or 0 bytes, and falls back from the broken `semgrep` wrapper (exit 127 / Python 3.14 `pysemgrep` exec error) to `pysemgrep`. The report Tools table and `doctor` say how Semgrep actually ran (via pysemgrep, JSON→SARIF, bundled rules only), so a degraded run is never shown as clean.
- **Exposed-file detector always sweeps the whole document root** (root files, `wp-content/uploads`, `wpvividbackups`, `updraft`), regardless of the code `--scope` - because real backups live outside the scanned source. Backups are matched by extension (`.zip .tar .tar.gz .tgz .tar.bz2 .tar.xz .rar .7z .wpress .sql .sql.gz .sql.zip .dump .mdb .bak`) and by known backup OUTPUT folder names (exact component, not any path containing "backup"), so the WPvivid backup plugin's own source no longer floods false positives. Every hit carries its size and a `large` flag for files over 1 MB; the cap is raised to 5,000 and warns (not silently truncates) when hit.
- **`init --wp` speed**: stack detection no longer reads file contents for vendored or public-plugin paths (Elementor, Slider Revolution, W3 Total Cache, ...), only for the project's own custom code - targeting well under 60s on a 10k-file install.
- **Four new Apps Script rules**: server functions reachable via `google.script.run` without an auth guard (every non-underscore global is web-callable); `getActiveUser` vs `getEffectiveUser` auth misuse; `setSharing(DriveApp.Access.ANYONE*)` / `ANYONE_WITH_LINK` public sharing; `UrlFetchApp` to a URL from settings/properties with no host allow-list. With fixture positives and safe negatives.
- **Severity guidance**: a trivial integrity write that nothing security-relevant consumes (counters, cosmetic fields) scores `VI:N`, not `VI:L`.

## 1.2.0 (2026-11-10)

Faster, quieter, more WordPress-aware - from the v1.1 test runs.

- **Offline-aware Semgrep**: a one-time reachability check to semgrep.dev; offline, Semgrep runs the bundled rules only with no registry packs and no retry, so a large scope no longer burns minutes on failed downloads and ends with no output. `AISA_FORCE_OFFLINE` forces it.
- **Scope budget**: scanning a scope above ~20,000 files / 300 MB prints a warning and suggests a narrower `--scope`.
- **Broader vendor detection**: a shared `is_vendor_path()` also treats `vendor_prefixed`, `vendored`, `third_party`, `build/out`, the default WordPress themes (`twentytwenty*`) and well-known public plugins (Elementor, WPForms, Yoast, Slider Revolution, W3 Total Cache, WooCommerce, CF7, Akismet, WPvivid, UpdraftPlus, ...) as dependencies - suppressing `india_pii` from them and marking matching leads `likely_vendor` (excluded from the secrets-to-rotate table).
- **Leftover/backup detector** (part of `scan`): flags web-accessible archives (`*.zip/*.tar*/*.7z`), SQL dumps, `.env*`, editor leftovers (`*.php-<date>/*.bak/*.old/*~`), `debug.log`/`error_log`, phpinfo and WPvivid/updraft backup dirs as `exposed_file` leads with **path and size only, never contents** - the highest-signal WordPress finding scanners miss.
- **`aisa.py benchmark --run <run> --labels <file>`**: maps confirmed findings to a label list (id, class, file) and prints matched / missed / extra, so detection quality is measurable. Ships a starter labels file for the test fixture.
- **`aisa.py init --wp`**: one-command WordPress profile - auto-scopes to `wp-content/{themes,plugins,mu-plugins}`, `wp-config.php` and `docker-compose.yml`; records public plugins (excluded from hunting, still version-checked); runs `wpvulns`; selects the WordPress checklist.

## 1.1.0 (2026-11-10)

PHP/WordPress and Google Apps Script support, plus scanner scoping - from the WordPress and DPDP test runs.

- **Scanners honour `--scope`**: Semgrep runs over the scope paths; Gitleaks and Trivy run per scope path and merge; OSV-Scanner still runs at the project root for lockfiles. Per-tool timeout (default 600s) with a progress line every 60s, and each tool's version is recorded even on timeout or failure.
- **Heavy/irrelevant folders skipped**: the walker ignores WordPress core (`wp-admin`, `wp-includes`), `wpvividbackups`, `updraft(plus)` and `cache`, and parses `docker-compose` volumes to skip host folders bind-mounted to a MySQL/Postgres/Mongo data directory - so a **project-root target with `--scope`** no longer crawls gigabytes of DB files and `docker-compose.yml` can be cited in findings. Semgrep also excludes `*.min.js`/`*.bundle.js` and caps files at 1 MB.
- **Bundled offline PHP/WordPress Semgrep rules** (12): `$wpdb` queries without `prepare`, request-data XSS/`unserialize`/`include`/`eval`/`exec`/`extract`/SSRF, `move_uploaded_file`, `register_rest_route` with `__return_true`, `wp_ajax_nopriv_` handlers, and base64/gzinflate `eval` backdoors - with a PHP fixture and CI checks (positives fire, safe negatives do not).
- **New `checklists/wordpress.md`** (auto-selected for `wordpress`): web-accessible backups/logs/leftover source, wp-config hardening, custom theme/plugin sinks, XML-RPC, user enumeration, component versions and compose/phpMyAdmin exposure.
- **`aisa.py wpvulns`**: lists plugin/theme slugs and versions; queries the WPScan API when `WPSCAN_API_TOKEN` is set (sending only slug and version), otherwise lists them as "not checked: no WordPress vulnerability feed".
- **New `checklists/apps-script.md`** (auto-selected for `apps_script`) with six bundled `.gs` Semgrep rules: web app `ANYONE_ANONYMOUS`/`executeAs`, request trust, HtmlService XSS, `setXFrameOptionsMode(ALLOWALL)`, `getActiveUser` auth, hardcoded secrets, `UrlFetchApp` SSRF.
- **DPDP `pii`**: detects Supabase, Google Sheets/Drive, SMTP/nodemailer and Resend as third-party recipients; erasure markers now require a real delete/erase/anonymise on a personal-data entity and exclude cache TTL/invalidation.
- **`stack`**: `india_pii` is flagged only from the project's own code, not vendored or framework-core paths.

## 1.0.1 (2026-11-10)

Fixes from the first real-world audit runs.

- Scanner leads: `normalize` strips only a leading `./` (not leading dots), normalises backslashes and de-duplicates case-insensitively on Windows, so a dotfile secret like `.env.local` reported by two scanners merges into one lead instead of two.
- Bundled Semgrep rule `aisa.js.jwt-fallback-secret` no longer flags an empty-string fallback (`?? ""` / `|| ''`), which fails closed and is not a hardcoded secret.
- PDF export: on Windows without LibreOffice, `report` now falls back to Microsoft Word via PowerShell COM (`ExportAsFixedFormat`); LibreOffice detection only attempts binaries that exist.
- Scanner discovery: `which()` also searches the Python user Scripts folder, winget Links/Packages, scoop shims, `~/.local/bin`, Homebrew and `/usr/local/bin`; `install.ps1` adds the Python user Scripts folder to the user PATH when missing.
- OSV-Scanner runs from inside the target and, when no lockfile is present, reports `skipped (no lockfile)` instead of `ok`; the report says to commit a lockfile.
- Installers remind the user to restart Claude Code so the skills appear.
- Phase 0 now audits the project in place (read-only) and never copies it; if a copy is unavoidable it must include `.git` for Gitleaks history.
- Severity calibration: aggregate, non-personal cross-tenant reads are usually Low/Medium; when exploitation needs an unexposed random id, use `AT:P` and rate at the lower end of the band.

## 1.0.0 (2026-11-10)

First public release.

- `/ai-security-audit`: six-phase, evidence-gated source-code security audit (VAPT) with isolated hunter, verifier and critic roles, three-vote verification, and machine validation that re-reads every cited line.
- `/ai-dpdp-audit`: dedicated India DPDP Act 2023 and DPDP Rules 2025 audit with a PII data map and twelve obligation groups.
- `aisa.py` engine: doctor, init, scan, normalize, pii, ledger, validate, report, status. Windows, macOS and Linux.
- Scanners: Semgrep, Gitleaks, Trivy and OSV-Scanner when installed, plus 16 bundled offline Semgrep rules.
- VAPT-style DOCX and PDF reports with OWASP Top 10:2025, API Top 10:2023 and LLM Top 10 2025 mapping, CVSS 4.0 scoring and priority order.
- Phase-by-phase prompts and a one-line `START.md` entry point.

## Planned

- 1.1: optional live staging verification (OWASP ZAP and Shannon) behind an explicit authorization gate.
- Fix-branch helper: one finding per commit with regression tests, followed by an automatic re-audit.
- SARIF export for GitHub code scanning.
