# -----------------------------------------------------------------------------
# AI-Security-Audit-Skills
# Author   : Vijaya Kumar L  (Rise With VJ)
# GitHub   : https://github.com/risewithvj
# LinkedIn : https://www.linkedin.com/in/vijayakumarl/
# License  : MIT
# -----------------------------------------------------------------------------
"""Run the external scanners read-only and record exactly what ran."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from .common import IS_WINDOWS, IGNORE_DIRS, compose_db_dirs, which

# Scope budget: above this, warn and suggest a narrower --scope (a huge scope is
# slow and, offline, can exhaust Semgrep before it writes output).
BUDGET_FILES = 20_000
BUDGET_BYTES = 300 * 1024 * 1024

_ONLINE: bool | None = None


def is_online() -> bool:
    """Checked once: can we reach the Semgrep registry? Offline, we skip the
    registry packs entirely instead of waiting out download timeouts."""
    global _ONLINE
    if _ONLINE is None:
        if os.environ.get("AISA_FORCE_OFFLINE"):
            _ONLINE = False
        else:
            try:
                with socket.create_connection(("semgrep.dev", 443), timeout=3):
                    _ONLINE = True
            except OSError:
                _ONLINE = False
    return _ONLINE


def scope_budget(targets: list[str]) -> dict:
    nfiles = nbytes = 0
    exceeded = False
    for t in targets:
        p = Path(t)
        if p.is_file():
            nfiles += 1
            try:
                nbytes += p.stat().st_size
            except OSError:
                pass
            continue
        for dp, dns, fns in os.walk(p):
            dns[:] = [d for d in dns if d not in IGNORE_DIRS and not d.startswith(".")]
            for fn in fns:
                nfiles += 1
                try:
                    nbytes += (Path(dp) / fn).stat().st_size
                except OSError:
                    pass
            if nfiles > BUDGET_FILES * 2 or nbytes > BUDGET_BYTES * 2:
                exceeded = True
                break
        if exceeded:
            break
    exceeded = exceeded or nfiles > BUDGET_FILES or nbytes > BUDGET_BYTES
    return {"files": nfiles, "bytes": nbytes, "exceeded": exceeded}

INSTALL_HINTS = {
    "semgrep": {
        "windows": "pip install semgrep   (or: python -m pip install semgrep)",
        "mac": "brew install semgrep   (or: pip install semgrep)",
        "linux": "pip install semgrep",
    },
    "gitleaks": {
        "windows": "winget install Gitleaks.Gitleaks   (or: scoop install gitleaks)",
        "mac": "brew install gitleaks",
        "linux": "download from https://github.com/gitleaks/gitleaks/releases",
    },
    "trivy": {
        "windows": "winget install AquaSecurity.Trivy   (or: scoop install trivy)",
        "mac": "brew install trivy",
        "linux": "see https://trivy.dev/latest/getting-started/installation/",
    },
    "osv-scanner": {
        "windows": "scoop install osv-scanner   (or download from https://github.com/google/osv-scanner/releases)",
        "mac": "brew install osv-scanner",
        "linux": "download from https://github.com/google/osv-scanner/releases",
    },
}

BUNDLED_RULES = Path(__file__).resolve().parents[2] / "semgrep-rules"
QUIET_ENV = {"SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off", "TRIVY_NO_PROGRESS": "true"}


def _env() -> dict:
    env = dict(os.environ)
    env.update(QUIET_ENV)
    return env


PURPOSE = {
    "semgrep": "code patterns (SAST)",
    "gitleaks": "secrets in files and Git history",
    "trivy": "dependency CVEs, IaC/Dockerfile misconfiguration, secrets",
    "osv-scanner": "known vulnerabilities in lockfiles",
}


def _version_line(exe: str, args: list[str]) -> str:
    try:
        out = subprocess.run([exe, *args], capture_output=True, text=True, timeout=25, env=_env(), stdin=subprocess.DEVNULL)
        text = (out.stdout or out.stderr).strip().splitlines()
        return text[0].strip() if text else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _is_broken_semgrep(line: str) -> bool:
    """The `semgrep` wrapper on some boxes (e.g. Python 3.14) execs the bare name
    `pysemgrep` and dies, so even `--version` prints an error, not a version."""
    low = line.lower()
    return any(s in low for s in ("pysemgrep", "no such file", "traceback", "errno"))


def version_of(tool: str) -> str | None:
    exe = which(tool)
    if not exe:
        return None
    args = {"semgrep": ["--version"], "gitleaks": ["version"], "trivy": ["--version"], "osv-scanner": ["--version"]}[tool]
    line = _version_line(exe, args)
    if tool == "semgrep" and _is_broken_semgrep(line):
        ps = which("pysemgrep")
        if ps:
            alt = _version_line(ps, ["--version"])
            if alt and alt != "unknown" and not _is_broken_semgrep(alt):
                return f"{alt} (via pysemgrep)"
    return line


def _run(cmd: list[str], timeout: int, ok_codes: tuple[int, ...], cwd: Path | None = None, label: str = "") -> dict:
    """Run a scanner with a hard per-tool deadline, printing a progress line every
    60s so a slow scan is visible rather than looking hung."""
    start = time.time()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                stdin=subprocess.DEVNULL, env=_env(), cwd=str(cwd) if cwd else None)
    except OSError as exc:
        return {"status": "failed", "seconds": 0.0, "stderr_tail": str(exc)}
    out = err = ""
    while True:
        remaining = timeout - (time.time() - start)
        if remaining <= 0:
            proc.kill()
            try:
                _o, _e = proc.communicate(timeout=10)
                err = (_e or "")
            except (subprocess.SubprocessError, OSError):
                pass
            return {"status": "timeout", "seconds": round(time.time() - start, 1),
                    "stderr_tail": (f"killed after {timeout}s\n" + err)[-1500:]}
        try:
            out, err = proc.communicate(timeout=min(60, remaining))
            status = "ok" if proc.returncode in ok_codes else "failed"
            return {"status": status, "exit_code": proc.returncode, "seconds": round(time.time() - start, 1),
                    "stderr_tail": (err or "")[-1500:]}
        except subprocess.TimeoutExpired:
            print(f"    ... {label or cmd[0]} still running ({int(time.time() - start)}s)", flush=True)


def _scan_targets(target: Path, scope: list[str] | None) -> list[str]:
    """The paths each scanner runs over: the scope paths when given (so a project-root
    target with --scope does not drag in core/DB folders), otherwise the whole target."""
    if scope:
        paths = [str((target / s)) for s in scope if (target / s).exists()]
        if paths:
            return paths
    return [str(target)]


def _worst(statuses: list[str]) -> str:
    for s in ("timeout", "failed", "skipped"):
        if s in statuses:
            return s
    return "ok" if statuses else "failed"


# --- Semgrep: robust invocation -------------------------------------------
# Semgrep is the one scanner that routinely fails in ways that still look like a
# success: the `semgrep` wrapper can exec a missing `pysemgrep` (exit 127), and
# `--sarif --output` can write a 0-byte file (exit 2) while `--json` works. So we
# (1) fall back from `semgrep` to `pysemgrep`, (2) fall back from SARIF to JSON
# and convert, and (3) never report "ok" unless a non-empty results file exists.

def _semgrep_exes() -> list[tuple[str, str]]:
    """Ordered (impl, exe) candidates to actually run Semgrep with."""
    out: list[tuple[str, str]] = []
    s = which("semgrep")
    if s:
        out.append(("semgrep", s))
    ps = which("pysemgrep")
    if ps and ps != s:
        out.append(("pysemgrep", ps))
    return out


def _sarif_ok(p: Path) -> bool:
    try:
        return p.exists() and p.stat().st_size > 0
    except OSError:
        return False


_SEV_LEVEL = {"ERROR": "error", "WARNING": "warning", "INFO": "note"}


def _sarif_from_semgrep_json(data: dict) -> dict:
    """Convert `semgrep --json` output into the minimal SARIF shape normalize
    reads (runs[].tool.driver.rules[] with CWE tags, runs[].results[])."""
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for r in data.get("results", []) or []:
        rid = r.get("check_id", "")
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        cwes = meta.get("cwe") or []
        if isinstance(cwes, str):
            cwes = [cwes]
        if rid not in rules:
            rules[rid] = {"id": rid, "properties": {"tags": [str(c) for c in cwes]}}
        results.append({
            "ruleId": rid,
            "level": _SEV_LEVEL.get(str(extra.get("severity", "WARNING")).upper(), "warning"),
            "message": {"text": extra.get("message", "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": r.get("path", "")},
                "region": {"startLine": (r.get("start", {}) or {}).get("line", 0)},
            }}],
        })
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "semgrep", "rules": list(rules.values())}},
        "results": results,
    }]}


def _semgrep_base(out_sarif: Path) -> list[str]:
    args = ["scan", "--sarif", "--output", str(out_sarif), "--metrics=off",
            "--disable-version-check", "--timeout", "30", "--quiet", "--max-target-bytes", "1000000"]
    for d in sorted(IGNORE_DIRS):
        args += ["--exclude", d]
    for pat in ("*.min.js", "*.bundle.js", "*.min.css"):
        args += ["--exclude", pat]
    from . import common as _c
    for pat in _c._GLOBAL_EXCLUDE:            # user --exclude globs reach Semgrep too
        args += ["--exclude", pat]
    return args


def _run_semgrep(exe: str, impl: str, out_sarif: Path, raw: Path, config_args: list[str],
                 targets: list[str], timeout: int, label: str) -> dict:
    """One Semgrep config set: try SARIF, and if the SARIF file is missing or
    empty, retry the same config in --json mode and convert it to SARIF so
    normalize always has input. Records impl and sarif_mode on the result."""
    if out_sarif.exists():
        out_sarif.unlink()
    base = _semgrep_base(out_sarif)
    res = _run([exe, *base, *config_args, *targets], timeout, (0, 1), label=label)
    res["impl"] = impl
    if _sarif_ok(out_sarif):
        res["sarif_mode"] = "sarif"
        return res
    # SARIF empty/missing: retry in JSON mode and convert.
    out_json = raw / "semgrep.json"
    if out_json.exists():
        out_json.unlink()
    jbase = [a if a != "--sarif" else "--json" for a in base]
    jbase = [str(out_json) if a == str(out_sarif) else a for a in jbase]
    jres = _run([exe, *jbase, *config_args, *targets], timeout, (0, 1), label=label + " (json)")
    jres["impl"] = impl
    if out_json.exists() and out_json.stat().st_size > 0:
        try:
            out_sarif.write_text(json.dumps(_sarif_from_semgrep_json(json.loads(out_json.read_text(encoding="utf-8")))), encoding="utf-8")
            jres["sarif_mode"] = "json-converted"
            return jres
        except (OSError, ValueError):
            pass
    jres["sarif_mode"] = "none"
    return jres


def semgrep_selfcheck() -> dict:
    """Run a tiny real Semgrep scan (not just --version): plant one obvious
    pattern in a temp file and confirm Semgrep actually writes a results file
    with the hit. Used by `doctor` so a Semgrep that cannot produce output is
    never reported healthy. Tries pysemgrep and JSON mode like a real scan."""
    exes = _semgrep_exes()
    if not exes:
        return {"ran": False, "exe": None, "mode": "none", "results": 0, "note": "Semgrep not found."}
    probe_dir = Path(tempfile.mkdtemp(prefix="aisa-semgrep-check-"))
    probe = probe_dir / "probe.py"
    probe.write_text("def f(x):\n    eval(x)\n", encoding="utf-8")
    cfg = ["-e", "eval(...)", "-l", "python"]
    common = ["scan", *cfg, "--metrics=off", "--disable-version-check", "--quiet"]
    try:
        for impl, exe in exes:
            sarif = probe_dir / "out.sarif"
            if sarif.exists():
                sarif.unlink()
            _run([exe, *common, "--sarif", "--output", str(sarif), str(probe_dir)], 90, (0, 1), label="semgrep self-check")
            if _sarif_ok(sarif):
                try:
                    n = sum(len(run.get("results", [])) for run in json.loads(sarif.read_text(encoding="utf-8")).get("runs", []))
                except (OSError, ValueError):
                    n = 0
                if n > 0:
                    return {"ran": True, "exe": impl, "mode": "sarif", "results": n,
                            "note": f"{impl} ran a tiny scan and wrote SARIF ({n} result)."}
            js = probe_dir / "out.json"
            if js.exists():
                js.unlink()
            _run([exe, *common, "--json", "--output", str(js), str(probe_dir)], 90, (0, 1), label="semgrep self-check (json)")
            if js.exists() and js.stat().st_size > 0:
                try:
                    n = len(json.loads(js.read_text(encoding="utf-8")).get("results", []))
                except (OSError, ValueError):
                    n = 0
                if n > 0:
                    return {"ran": True, "exe": impl, "mode": "json-converted", "results": n,
                            "note": f"{impl} SARIF output was empty; JSON mode works ({n} result). Scans convert JSON->SARIF."}
        tried = "SARIF and JSON" + (", and pysemgrep" if len(exes) > 1 else "")
        return {"ran": False, "exe": exes[0][0], "mode": "none", "results": 0,
                "note": f"Semgrep is installed but produced no results file (tried {tried}). SAST will not run."}
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)


def run_all(target: Path, raw: Path, semgrep_configs: list[str], timeout: int = 600,
            only: list[str] | None = None, scope: list[str] | None = None) -> dict:
    raw.mkdir(parents=True, exist_ok=True)
    results: dict[str, dict] = {}
    tools = only or ["semgrep", "gitleaks", "trivy", "osv-scanner"]
    targets = _scan_targets(target, scope)
    skip_dirs = ["node_modules", ".git"] + sorted(IGNORE_DIRS) + [str(d) for d in compose_db_dirs(target)]
    budget = scope_budget(targets)
    if budget["exceeded"]:
        print(f"  ! scope is large (~{budget['files']}+ files, ~{budget['bytes'] // (1024 * 1024)}+ MB). "
              f"Scanning may be slow; narrow it with --scope (e.g. just custom code).", flush=True)
    for tool in tools:
        exe = which(tool)
        if not exe:
            results[tool] = {"status": "not_installed", "purpose": PURPOSE[tool]}
            continue
        ver = version_of(tool)  # recorded even if the scan later times out or fails
        if tool == "semgrep":
            out = raw / "semgrep.sarif"
            local = ["--config", str(BUNDLED_RULES)] if BUNDLED_RULES.is_dir() else []
            # Config sets to try in order. Offline: bundled only. Online: registry
            # packs + bundled, then bundled-only if the packs could not be fetched.
            if not is_online():
                config_sets = [(local, ["bundled aisa rules only (offline: registry packs skipped)"],
                                "No network to semgrep.dev: ran the bundled offline rules only. Re-run with internet for registry pack coverage.")]
            else:
                remote = [x for cfg in semgrep_configs for x in ("--config", cfg)]
                config_sets = [
                    (remote + local, semgrep_configs + (["bundled aisa rules"] if local else []), None),
                    (local, ["bundled aisa rules only (registry packs unavailable)"],
                     "Semgrep registry packs could not be used; ran the bundled offline rules. Re-run with internet for full coverage."),
                ]
            res = {"status": "failed", "seconds": 0.0, "impl": None, "sarif_mode": "none"}
            # Try each implementation (semgrep, then pysemgrep); within each, the
            # config sets. Stop as soon as a non-empty results file is produced.
            for impl, s_exe in (_semgrep_exes() or [("semgrep", exe)]):
                for cfg_args, rules_desc, cfg_note in config_sets:
                    if not cfg_args:
                        continue
                    res = _run_semgrep(s_exe, impl, out, raw, cfg_args, targets, timeout, f"semgrep ({impl})")
                    res["rules"] = rules_desc
                    if cfg_note:
                        res["note"] = ((res.get("note") + " ") if res.get("note") else "") + cfg_note
                    if _sarif_ok(out):
                        break
                if _sarif_ok(out):
                    break
            if not _sarif_ok(out):
                tried = "SARIF and JSON"
                if len(_semgrep_exes()) > 1:
                    tried += ", and pysemgrep"
                res["status"] = "failed"
                res["stderr_tail"] = (res.get("stderr_tail") or "") + f"\nSemgrep produced no results file (tried {tried})."
            elif res["status"] not in ("ok",):
                # SARIF exists but the run's exit code was non-ok: treat as ok since
                # we have results, but keep the note trail.
                res["status"] = "ok"
        elif tool == "gitleaks":
            out = raw / "gitleaks.json"
            merged: list = []
            secs = 0.0
            statuses, tails = [], []
            for i, tp in enumerate(targets):
                part = raw / f"gitleaks.{i}.json"
                cmd = [exe, "detect", "--source", tp, "--redact", "--report-format", "json", "--report-path", str(part), "--no-banner", "--exit-code", "0", "--no-git"]
                r = _run(cmd, timeout, (0, 1), label="gitleaks")
                secs += r.get("seconds", 0.0)
                statuses.append(r["status"]); tails.append(r.get("stderr_tail", ""))
                if part.exists():
                    try:
                        merged += json.loads(part.read_text(encoding="utf-8")) or []
                    except (OSError, ValueError):
                        pass
                    part.unlink()
            out.write_text(json.dumps(merged), encoding="utf-8")
            res = {"status": _worst(statuses), "seconds": round(secs, 1), "stderr_tail": ("\n".join(t for t in tails if t))[-1500:], "scanned_paths": len(targets)}
        elif tool == "trivy":
            out = raw / "trivy.json"
            merged_results: list = []
            secs = 0.0
            statuses, tails = [], []
            skip_args = [a for d in skip_dirs for a in ("--skip-dirs", d)]
            for i, tp in enumerate(targets):
                part = raw / f"trivy.{i}.json"
                cmd = [exe, "fs", "--scanners", "vuln,misconfig,secret", "--format", "json", "--output", str(part), "--quiet", *skip_args, tp]
                r = _run(cmd, timeout, (0,), label="trivy")
                secs += r.get("seconds", 0.0)
                statuses.append(r["status"]); tails.append(r.get("stderr_tail", ""))
                if part.exists():
                    try:
                        merged_results += (json.loads(part.read_text(encoding="utf-8")) or {}).get("Results", []) or []
                    except (OSError, ValueError):
                        pass
                    part.unlink()
            out.write_text(json.dumps({"Results": merged_results}), encoding="utf-8")
            res = {"status": _worst(statuses), "seconds": round(secs, 1), "stderr_tail": ("\n".join(t for t in tails if t))[-1500:], "scanned_paths": len(targets)}
        else:
            # OSV-Scanner looks for lockfiles, which live at the project root, so it
            # always runs from the target root regardless of --scope.
            out = raw / "osv.json"
            cmd = [exe, "scan", "source", "-r", "--format", "json", "--output", str(out), "."]
            res = _run(cmd, timeout, (0, 1), cwd=target, label="osv-scanner")
            tail = res.get("stderr_tail", "").lower()
            if res["status"] == "failed" and "unknown command" in tail:
                res = _run([exe, "--format", "json", "--output", str(out), "-r", "."], timeout, (0, 1), cwd=target, label="osv-scanner")
                tail = res.get("stderr_tail", "").lower()
            if "no package sources found" in tail:
                out.write_text('{"results": []}', encoding="utf-8")
                res.update({"status": "skipped", "note": "no lockfile found"})
        res.update({"version": ver, "purpose": PURPOSE[tool], "output": out.name if out.exists() else None})
        try:
            has_output = out.exists() and out.stat().st_size > 0
        except OSError:
            has_output = False
        if res["status"] == "ok" and not has_output:
            res["status"] = "failed"
            res["stderr_tail"] = (res.get("stderr_tail") or "") + "\nno output file written (or it was empty)"
        results[tool] = res
    return results


def doctor() -> dict:
    os_key = "windows" if IS_WINDOWS else ("mac" if Path("/System/Library").exists() else "linux")
    rows = {}
    for tool in INSTALL_HINTS:
        ver = version_of(tool)
        row = {"installed": ver is not None, "version": ver, "purpose": PURPOSE[tool], "install": INSTALL_HINTS[tool][os_key]}
        if tool == "semgrep" and ver is not None:
            # Don't trust --version: actually run a tiny scan. A Semgrep that
            # reports a version but cannot write a results file is NOT healthy.
            chk = semgrep_selfcheck()
            row["selfcheck"] = chk
            row["healthy"] = bool(chk.get("ran"))
        rows[tool] = row
    return {"os": os_key, "tools": rows}
