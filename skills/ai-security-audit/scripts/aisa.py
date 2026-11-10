#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# AI-Security-Audit-Skills
# Author   : Vijaya Kumar L  (Rise With VJ)
# GitHub   : https://github.com/risewithvj
# LinkedIn : https://www.linkedin.com/in/vijayakumarl/
# License  : MIT
# -----------------------------------------------------------------------------
"""aisa: command-line engine for the ai-security-audit and ai-dpdp-audit skills.

Commands
  doctor      check Python packages and scanners, print install hints
  init        create a run folder, record scope, detect the stack
  scan        run installed scanners read-only into <run>/raw
  normalize   merge scanner output into <run>/leads.json
  pii         build a PII inventory for the DPDP audit (<run>/pii-inventory.json)
  wpvulns     list WordPress plugin/theme versions; check WPScan when WPSCAN_API_TOKEN is set
  ledger      validate <run>/coverage-ledger.json
  validate    validate <run>/findings.json against the schema and the source
  report      build the DOCX (and PDF when possible) report from validated records
  benchmark   score confirmed findings against a labels file (matched/missed/extra)
  status      show where a run stopped
"""

from __future__ import annotations

import argparse
import time
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from aisa_lib import __version__  # noqa: E402
from aisa_lib.common import (  # noqa: E402
    die, load_config, now_iso, read_json, reports_root, resolve_run, wp_scope, write_json,
)

SKILL_DIR = HERE.parent
SCHEMA = SKILL_DIR / "schema" / "findings.schema.json"
BANNER = f"AI-Security-Audit-Skills v{__version__}  |  by Vijaya Kumar L (Rise With VJ)  |  github.com/risewithvj"


def _ok(flag: bool) -> str:
    return "OK " if flag else "-- "


def cmd_doctor(args) -> int:
    from aisa_lib import scanners
    print(BANNER)
    print(f"Python {sys.version.split()[0]} {'OK' if sys.version_info >= (3, 9) else 'too old: need 3.9+'}")
    pkgs = {}
    for mod, pip in (("docx", "python-docx"), ("jsonschema", "jsonschema"), ("cvss", "cvss")):
        try:
            __import__(mod)
            pkgs[pip] = True
        except ImportError:
            pkgs[pip] = False
    need = {"python-docx": "required for the report", "jsonschema": "recommended: full schema validation", "cvss": "recommended: checks CVSS 4.0 scores"}
    for p, ok in pkgs.items():
        print(f"  {_ok(ok)}{p:<12} {need[p]}")
    d = scanners.doctor()
    print(f"\nScanners ({d['os']}):")
    missing = []
    for tool, r in d["tools"].items():
        print(f"  {_ok(r['installed'])}{tool:<12} {r['version'] or 'not installed':<28} {r['purpose']}")
        if tool == "semgrep" and r.get("installed"):
            chk = r.get("selfcheck", {})
            print(f"     {'OK ' if chk.get('ran') else '!! '}health: {chk.get('note', '')}")
        if not r["installed"]:
            missing.append((tool, r["install"]))
    if not all(pkgs.values()):
        miss = " ".join(p for p, ok in pkgs.items() if not ok)
        print(f"\nInstall Python packages:  python -m pip install {miss}")
    if missing:
        print("\nOptional scanners (the audit still runs without them; the report lists what did not run):")
        for tool, hint in missing:
            print(f"  {tool:<12} {hint}")
    if args.json:
        print(json.dumps({"python_packages": pkgs, **d}, indent=2))
    return 0 if pkgs["python-docx"] else 1


def _git_ref(target: Path) -> str | None:
    if not (target / ".git").exists():
        return None
    try:
        sha = subprocess.run(["git", "-C", str(target), "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=20).stdout.strip()
        dirty = subprocess.run(["git", "-C", str(target), "status", "--porcelain"], capture_output=True, text=True, timeout=30).stdout.strip()
        return f"{sha}{' (uncommitted changes)' if dirty else ''}" if sha else None
    except (OSError, subprocess.SubprocessError):
        return None


# Risk-based verification policy (B1): High/Critical candidates get three independent
# votes, Medium/Low get one, and a lone vote that disagrees with the hunter is re-run
# with three. Phase 4 reads this from run-metadata.
VOTE_POLICY = {"critical": 3, "high": 3, "medium": 1, "low": 1, "info": 1,
               "revote_on_disagreement": 3}

# Signals that make an app worth a full (standard) pass even when it is small.
_RISK_FEATURES = ("payments", "india_pii", "auth", "jwt", "uploads", "llm", "mcp", "crypto")
_AUTO_FILE_LIMIT = 150


def _resolve_profile(selected: str, st: dict, is_wp: bool = False):
    """Auto profile (B2): quick for small, low-risk apps; standard otherwise.
    deep is never auto-selected - it is only used when asked for explicitly."""
    if selected and selected != "auto":
        return selected, f"explicit --profile {selected}"
    files = st.get("files_scanned", 0)
    risky = sorted(set(st.get("features", {})) & set(_RISK_FEATURES))
    if files < _AUTO_FILE_LIMIT and not risky and not is_wp:
        return "quick", (f"auto -> quick: {files} source files (< {_AUTO_FILE_LIMIT}) and "
                         f"no payments/PII/auth signals")
    why = []
    if files >= _AUTO_FILE_LIMIT:
        why.append(f"{files} source files (>= {_AUTO_FILE_LIMIT})")
    if risky:
        why.append("risk signals: " + ", ".join(risky))
    if is_wp:
        why.append("WordPress")
    return "standard", "auto -> standard: " + ("; ".join(why) or "default")


def cmd_init(args) -> int:
    from aisa_lib import stack
    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        die(f"target folder does not exist: {target}")
    cfg = load_config()
    repo = args.name or target.name
    base = reports_root() / repo
    try:
        target_in_base = base.resolve().is_relative_to(target)  # type: ignore[attr-defined]
    except AttributeError:
        target_in_base = str(base.resolve()).startswith(str(target))
    if target_in_base and not args.allow_inside:
        die(f"run folder would be inside the target ({base}). Set AISA_REPORTS_DIR elsewhere or pass --allow-inside")
    base.mkdir(parents=True, exist_ok=True)
    prior = sorted(base.glob("run-*"), key=lambda p: int(p.name.split("-")[-1]) if p.name.split("-")[-1].isdigit() else 0)
    nxt = (int(prior[-1].name.split("-")[-1]) + 1) if prior and prior[-1].name.split("-")[-1].isdigit() else 1
    run = base / f"run-{nxt}"
    (run / "raw").mkdir(parents=True)
    scope = [s.strip() for s in (args.scope or "").split(",") if s.strip()] or None
    exclude = [s.strip() for s in (getattr(args, "exclude", None) or "").split(",") if s.strip()]
    from aisa_lib import common as _c
    _c.set_global_exclude(exclude)
    wp_public: list[str] = []
    if getattr(args, "wp", False):
        wp = wp_scope(target)
        if wp["scope"]:
            scope = wp["scope"]
            wp_public = wp["public_plugins"]
        else:
            print("  --wp: no wp-content folder found under the target; using the given scope")
    # Detect the stack up front so an "auto" profile can size the run from real signals.
    st = stack.detect(target, scope)
    profile, profile_reason = _resolve_profile(args.profile, st, bool(getattr(args, "wp", False)))
    budget = getattr(args, "budget", None) or "normal"
    meta = {
        "run_id": f"{repo}-run-{nxt}",
        "tool": "AI-Security-Audit-Skills",
        "tool_version": __version__,
        "framework": args.framework,
        "repo": repo,
        "target": str(target),
        "source_ref": _git_ref(target),
        "scope": scope,
        "exclude": exclude,
        "wp_public_plugins": wp_public,
        "profile": profile,
        "profile_requested": args.profile,
        "profile_reason": profile_reason,
        "budget": budget,
        "votes": VOTE_POLICY["high"],
        "vote_policy": VOTE_POLICY,
        "phase_costs": [],
        "created_at": now_iso(),
        "run_status": "in_progress",
        "phase": "0-scope",
        "prior_runs": [str(p) for p in prior],
        "report": {
            "client": args.client or cfg.get("client", ""),
            "app": args.app or cfg.get("app", "") or repo,
            "prepared_by": args.prepared_by or cfg.get("prepared_by", "Vijaya Kumar L"),
            "reviewed_by": args.reviewed_by or cfg.get("reviewed_by", ""),
            "logo": args.logo or cfg.get("logo", ""),
            "org_short": cfg.get("org_short", ""),
            "target_label": args.target_label or "",
        },
        "scanners": {},
        "not_checked": [],
        "execution_policy": "read-only, source-only: no target code executed, no live systems contacted",
    }
    write_json(run / "run-metadata.json", meta)
    write_json(run / "stack.json", st)
    write_json(run / "coverage-ledger.json", [])
    reused = _reuse_prior_map(args.framework, target, run, prior)
    if getattr(args, "wp", False):
        from aisa_lib import wpvulns
        wpv = wpvulns.scan(target, run)
        print(f"  --wp: scoped to custom WordPress code; wpvulns.json has {len(wpv['components'])} components; "
              f"{len(wp_public)} public plugin(s) excluded from hunting (still version-checked)")
    print(BANNER)
    print(f"Run folder : {run}")
    print(f"Target     : {target}  (ref {meta['source_ref'] or 'no git'})")
    print(f"Profile    : {profile}   Budget: {budget}   Framework: {args.framework}")
    print(f"  reason   : {profile_reason}")
    print(f"Languages  : {', '.join(list(st['languages'])[:8]) or '-'}")
    print(f"Detected   : {', '.join(sorted(st['features'])) or '-'}")
    print(f"Checklists : {len(st['suggested_checklists'])} suggested (see stack.json)")
    if reused:
        print(f"Reused     : {reused} from a prior security run (DPDP skips re-mapping)")
    if prior:
        print(f"Prior runs : {len(prior)} (latest {prior[-1]}) - read its findings.json and coverage-ledger.json in Phase 0")
    print(f"\nNext: python {Path(__file__).name} scan --run \"{run}\"")
    return 0


def _reuse_prior_map(framework: str, target: Path, run: Path, prior: list) -> str:
    """B4: a DPDP run reuses the architecture map and PII inventory from the newest
    prior security run on the same target instead of mapping again. Returns a short
    description of what was reused, or ''."""
    if framework != "dpdp":
        return ""
    reused = []
    for p in reversed(prior):
        pmeta = read_json(Path(p) / "run-metadata.json", {}) or {}
        if pmeta.get("framework") == "security" and str(pmeta.get("target")) == str(target):
            for name in ("architecture.md", "pii-inventory.json"):
                src = Path(p) / name
                if src.exists() and not (run / name).exists():
                    (run / name).write_bytes(src.read_bytes())
                    reused.append(name)
            if reused:
                meta_path = run / "run-metadata.json"
                m = read_json(meta_path, {}) or {}
                m["reused_from"] = str(p)
                m["reused_artifacts"] = reused
                write_json(meta_path, m)
                return ", ".join(reused)
    return ""


def _set_phase(run: Path, phase: str, **extra) -> None:
    meta = read_json(run / "run-metadata.json", {})
    meta["phase"] = phase
    meta.update(extra)
    write_json(run / "run-metadata.json", meta)


def cmd_scan(args) -> int:
    from aisa_lib import exposed, scanners
    run = resolve_run(args.run)
    meta = read_json(run / "run-metadata.json")
    st = read_json(run / "stack.json", {})
    target = Path(meta["target"])
    only = [t.strip() for t in args.only.split(",")] if args.only else None
    cfgs = args.semgrep_config or st.get("semgrep_configs") or ["p/default"]
    scope = meta.get("scope")
    # Excludes come from init; --exclude on scan adds to them for this pass.
    exclude = list(meta.get("exclude") or [])
    exclude += [s.strip() for s in (getattr(args, "exclude", None) or "").split(",") if s.strip()]
    from aisa_lib import common as _c
    _c.set_global_exclude(exclude)
    where = f"{target} (scope: {', '.join(scope)})" if scope else str(target)
    print(f"Scanning {where} (read-only). Per-tool timeout {args.timeout}s; progress every 60s.")
    res = scanners.run_all(target, run / "raw", cfgs, timeout=args.timeout, only=only, scope=scope)
    # Fast leftover/backup pass (paths and sizes only, never contents). This
    # always sweeps the whole document root, not just --scope, since backups live
    # outside the code scope (docroot root, uploads, wpvividbackups, updraft).
    exposed_hits = exposed.find_exposed(target, scope)
    write_json(run / "raw" / "exposed.json", exposed_hits)
    if exposed_hits:
        big = sum(1 for h in exposed_hits if h.get("large"))
        extra = f", {big} over 1 MB" if big else ""
        print(f"  exposed-files {len(exposed_hits)} leftover/backup/log/env file(s) in web-served paths{extra} (see exposed_file leads)")
    meta = read_json(run / "run-metadata.json")
    meta.setdefault("scanners", {}).update(res)
    meta["phase"] = "2-scanners"
    write_json(run / "run-metadata.json", meta)
    for tool, r in res.items():
        print(f"  {tool:<12} {r['status']:<14} {r.get('version') or ''}")
        if r["status"] in ("failed", "timeout") and r.get("stderr_tail"):
            print("    " + r["stderr_tail"].strip().splitlines()[-1][:200])
    print(f"\nNext: python {Path(__file__).name} normalize --run \"{run}\"")
    return 0


def cmd_normalize(args) -> int:
    from aisa_lib import normalize
    run = resolve_run(args.run)
    meta = read_json(run / "run-metadata.json")
    out = normalize.normalize(Path(meta["target"]), run / "raw")
    existing = read_json(run / "leads.json")
    if existing:  # keep triage decisions already made
        prev = {x["fingerprint"]: x for x in existing.get("leads", [])}
        for ld in out["leads"]:
            if ld["fingerprint"] in prev:
                ld["triage"] = prev[ld["fingerprint"]].get("triage")
                ld["triage_reason"] = prev[ld["fingerprint"]].get("triage_reason")
    # Preserve WordPress component rows (from `init --wp` / `wpvulns`) across re-normalize.
    wpv = read_json(run / "wpvulns.json", {})
    if wpv and wpv.get("dependencies"):
        have = {d.get("package") for d in out.get("dependencies", [])}
        out.setdefault("dependencies", []).extend(d for d in wpv["dependencies"] if d.get("package") not in have)
        out["counts"]["dependency_vulns"] = len(out["dependencies"])
    write_json(run / "leads.json", out)
    c = out["counts"]
    print(f"leads.json: {c['leads']} leads (code {c['code']}, secrets {c['secrets']}, misconfig {c['misconfig']}, exposed-files {c.get('exposed_files', 0)}), {c['dependency_vulns']} dependency advisories")
    test_like = sum(1 for x in out["leads"] if x["likely_test_or_example"])
    if test_like:
        print(f"  {test_like} leads are in test/example/doc paths (flagged likely_test_or_example)")
    return 0


def cmd_pii(args) -> int:
    from aisa_lib import pii
    run = resolve_run(args.run)
    meta = read_json(run / "run-metadata.json")
    inv = pii.inventory(Path(meta["target"]), meta.get("scope"))
    write_json(run / "pii-inventory.json", inv)
    s = inv["summary"]
    print(f"pii-inventory.json: {s['fields']} PII field references across {s['data_types']} data types; "
          f"{s['value_files']} files with PII-like values; {s['log_sinks']} possible PII-in-log lines; "
          f"{s['third_parties']} third-party data recipients")
    return 0


def cmd_wpvulns(args) -> int:
    from aisa_lib import wpvulns
    run = resolve_run(args.run)
    meta = read_json(run / "run-metadata.json")
    out = wpvulns.scan(Path(meta["target"]), run)
    print(f"wpvulns.json: {len(out['components'])} WordPress components found. {out['note']}")
    for c in out["components"][:60]:
        print(f"  {c['type']:<7} {c['slug']:<32} {c.get('version') or 'unknown'}")
    return 0


def cmd_ledger(args) -> int:
    from aisa_lib.validate import validate_ledger
    run = resolve_run(args.run)
    r = validate_ledger(run)
    print(f"coverage-ledger.json: {r.get('units', 0)} units  {r.get('summary')}")
    for e in r["errors"][:100]:
        print(f"  ERROR {e}")
    print("OK" if r["ok"] else f"{len(r['errors'])} error(s). Fix before continuing.")
    return 0 if r["ok"] else 1


def cmd_validate(args) -> int:
    from aisa_lib.validate import validate_findings
    run = resolve_run(args.run)
    r = validate_findings(run, SCHEMA)
    write_json(run / "validation.json", r)
    c = r.get("counts", {})
    print(f"findings.json: {c.get('confirmed', 0)} confirmed, {c.get('needs_validation', 0)} needs_validation, {c.get('rejected', 0)} rejected")
    for w in r["warnings"]:
        print(f"  WARN  {w}")
    for e in r["errors"][:200]:
        print(f"  ERROR {e}")
    if r["ok"]:
        _set_phase(run, "4-verified")
        print("OK: every record passed. Every cited line was re-read from the source.")
        return 0
    print(f"{len(r['errors'])} error(s). Fix the records (never the check) and run validate again.")
    return 1


def cmd_report(args) -> int:
    from aisa_lib import report_docx
    from aisa_lib.validate import validate_findings
    run = resolve_run(args.run)
    if not args.skip_validate:
        r = validate_findings(run, SCHEMA)
        if not r["ok"]:
            print("findings.json does not validate; the report is built only from validated records.")
            for e in r["errors"][:30]:
                print(f"  ERROR {e}")
            return 1
    meta = read_json(run / "run-metadata.json")
    fw = read_json(run / "findings.json", {}).get("framework") or meta.get("framework", "security")
    name = "DPDP-Compliance-Audit-Report" if fw == "dpdp" else "AI-Security-Audit-Report"
    out = report_docx.build(run, run / f"{name}.docx", fw)
    print(f"DOCX: {out}")
    pdf = report_docx.to_pdf(out) if not args.no_pdf else None
    if pdf:
        print(f"PDF : {pdf}")
    elif not args.no_pdf:
        msg = "PDF not created (install LibreOffice, or 'pip install docx2pdf' with Microsoft Word). The DOCX is complete."
        print(msg)
        if args.pdf:
            return 1
    summ = report_docx.write_summary(run, run / "summary.md")
    print(f"Summary: {summ}")
    _set_phase(run, "5-report", run_status=meta.get("run_status") if meta.get("run_status") == "incomplete" else "complete", completed_at=now_iso())
    return 0


def cmd_benchmark(args) -> int:
    from aisa_lib import benchmark
    run = resolve_run(args.run)
    res = benchmark.run(run, args.labels)
    write_json(run / "benchmark.json", res)
    c = res["counts"]
    rec = c.get("reconciled_extra", 0)
    fpr = c.get("false_positive_rate", 0.0)
    print(f"benchmark: {c['matched']}/{c['labels']} labels matched  |  {c['missed']} missed  |  "
          f"{c['extra']} extra (genuine)  |  {rec} reconciled dup  |  FP rate {fpr:.1%}")
    for m in res["matched"]:
        print(f"  MATCH  {m['label'].get('id')}  <- {m['finding']}")
    for m in res["missed"]:
        print(f"  MISS   {m.get('id')}  ({m.get('class')}, {m.get('file')})")
    for e in res.get("reconciled_extra", []):
        print(f"  DUP    {e['id']}  {e['class']}  (reconciled -> {e.get('reconciled_to')})")
    for e in res["extra"]:
        print(f"  EXTRA  {e['id']}  {e['class']}")
    return 0


def cmd_status(args) -> int:
    run = resolve_run(args.run)
    meta = read_json(run / "run-metadata.json")
    print(BANNER)
    print(f"Run    : {run}")
    print(f"Target : {meta.get('target')}   Profile: {meta.get('profile')}   Framework: {meta.get('framework')}")
    print(f"Phase  : {meta.get('phase')}   Status: {meta.get('run_status')}")
    checks = [
        ("stack.json", "Phase 0 init"), ("leads.json", "Phase 2 normalize"), ("architecture.md", "Phase 1 map"),
        ("candidates.json", "Phase 3 hunt"), ("findings.json", "Phase 4 records"), ("validation.json", "Phase 4 validate"),
    ]
    for f, label in checks:
        print(f"  {_ok((run / f).exists())}{label:<20} {f}")
    ledger = read_json(run / "coverage-ledger.json", []) or []
    if ledger:
        summ: dict[str, int] = {}
        for u in ledger:
            summ[u.get("status")] = summ.get(u.get("status"), 0) + 1
        print(f"  ledger: {len(ledger)} units {summ}")
    reports = list(run.glob("*.docx"))
    print(f"  {_ok(bool(reports))}{'Phase 5 report':<20} {', '.join(p.name for p in reports) or '-'}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="aisa", description=BANNER)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("doctor", help="check dependencies and scanners")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_doctor)

    p = sub.add_parser("init", help="create a run folder and detect the stack")
    p.add_argument("--target", default=".")
    p.add_argument("--profile", choices=["auto", "quick", "standard", "deep"], default="auto",
                   help="auto (default) sizes the run from the stack; quick/standard/deep force it")
    p.add_argument("--budget", choices=["small", "normal", "large"], default="normal",
                   help="effort cap: small = fewest hunters/waves, large = widest fan-out")
    p.add_argument("--framework", choices=["security", "dpdp"], default="security")
    p.add_argument("--scope", help="comma-separated paths relative to target")
    p.add_argument("--exclude", help="comma-separated path globs to skip everywhere, e.g. 'data/static/codefixes/**,**/seed/**'")
    p.add_argument("--wp", action="store_true", help="WordPress profile: auto-scope to custom theme/plugin code + wp-config + compose, run wpvulns, select the WordPress checklist")
    p.add_argument("--name", help="report folder name (default: target folder name)")
    p.add_argument("--client"); p.add_argument("--app"); p.add_argument("--prepared-by"); p.add_argument("--reviewed-by")
    p.add_argument("--logo", help="path to a PNG/JPG logo for the report header")
    p.add_argument("--target-label", help="how the target is shown on the cover, e.g. a URL or repo name")
    p.add_argument("--allow-inside", action="store_true", help=argparse.SUPPRESS)
    p.set_defaults(fn=cmd_init)

    for name, fn, hlp in (("scan", cmd_scan, "run scanners"), ("normalize", cmd_normalize, "merge scanner output"),
                          ("pii", cmd_pii, "build the PII inventory"), ("wpvulns", cmd_wpvulns, "list WordPress plugin/theme versions (optional WPScan)"),
                          ("ledger", cmd_ledger, "validate the coverage ledger"),
                          ("validate", cmd_validate, "validate findings.json"), ("report", cmd_report, "build the report"),
                          ("benchmark", cmd_benchmark, "score confirmed findings against a labels file"),
                          ("status", cmd_status, "show run progress")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("--run", help="run folder (default: newest run)")
        if name == "benchmark":
            p.add_argument("--labels", required=True, help="JSON labels file: {labels:[{id,class,file}]}")
        if name == "scan":
            p.add_argument("--only", help="comma-separated subset: semgrep,gitleaks,trivy,osv-scanner")
            p.add_argument("--semgrep-config", action="append", help="override Semgrep rule packs")
            p.add_argument("--timeout", type=int, default=600, help="per-scanner timeout in seconds (default 600)")
            p.add_argument("--exclude", help="comma-separated path globs to skip (added to init's excludes)")
        if name == "report":
            p.add_argument("--pdf", action="store_true", help="fail if the PDF cannot be created")
            p.add_argument("--no-pdf", action="store_true")
            p.add_argument("--skip-validate", action="store_true", help=argparse.SUPPRESS)
        p.set_defaults(fn=fn)

    args = ap.parse_args(argv)
    from aisa_lib import common as _cost
    _cost.io_reset()
    t0 = time.monotonic()
    rc = args.fn(args)
    _record_cost(args, round(time.monotonic() - t0, 2), _cost.io_snapshot())
    return rc


def _record_cost(args, seconds: float, io: dict) -> None:
    """B6: print a cost line for the phase and persist it on the run when resolvable."""
    phase = getattr(args, "cmd", "?")
    print(f"cost: {phase}  {seconds}s  {io['files_read']} files read  "
          f"~{io['est_tokens']} engine I/O (chars/4). "
          f"AI token use isn't measured by the engine. Check /cost in Claude Code after a run.")
    if phase in ("doctor",):
        return
    try:
        run = resolve_run(getattr(args, "run", None))
    except SystemExit:
        return
    meta_path = run / "run-metadata.json"
    if not meta_path.exists():
        return
    m = read_json(meta_path, {}) or {}
    m.setdefault("phase_costs", []).append({"phase": phase, "seconds": seconds, **io})
    write_json(meta_path, m)


if __name__ == "__main__":
    sys.exit(main())
