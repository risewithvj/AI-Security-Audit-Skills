# -----------------------------------------------------------------------------
# AI-Security-Audit-Skills
# Author   : Vijaya Kumar L  (Rise With VJ)
# GitHub   : https://github.com/risewithvj
# LinkedIn : https://www.linkedin.com/in/vijayakumarl/
# License  : MIT
# -----------------------------------------------------------------------------
"""Merge scanner output into one de-duplicated, redacted leads.json."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import unquote

from .common import IS_WINDOWS, is_vendor_path, read_json, redact_text, rel

TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|specs|fixtures?|mocks?|examples?|samples?|docs?|stories)(/|$)|\.(test|spec|stories)\.", re.I)
CWE_RX = re.compile(r"CWE-(\d+)")


def _fp(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _norm_path(target: Path, uri: str) -> str:
    if uri.startswith("file:"):
        uri = unquote(uri[5:]).lstrip("/") if re.match(r"^file:/+[A-Za-z]:", uri) else unquote(uri[7:] if uri.startswith("file://") else uri[5:])
    if re.match(r"^/[A-Za-z]:[\\/]", uri):  # /C:/... from a Windows file URI
        uri = uri[1:]
    if uri.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", uri):
        return rel(target, Path(uri))
    # Relative path: normalise backslashes to forward slashes and strip only a
    # leading "./" prefix. A bare ".lstrip('./')" also ate leading dots, so a
    # dotfile like ".env.local" became "env.local" and the same secret reported
    # by two scanners failed to de-duplicate.
    p = uri.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return Path(p).as_posix()


def _merge_key(file: str) -> str:
    """Path form used only for de-duplication. Windows filesystems are
    case-insensitive, so compare paths without regard to case there."""
    return file.lower() if IS_WINDOWS else file


def _semgrep(target: Path, raw: Path) -> list[dict]:
    data = read_json(raw / "semgrep.sarif", {}) or {}
    leads = []
    for run in data.get("runs", []):
        rules = {}
        for r in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules[r.get("id")] = r
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            rule = rules.get(rid, {})
            tags = " ".join(rule.get("properties", {}).get("tags", []))
            cwes = sorted({f"CWE-{c}" for c in CWE_RX.findall(tags)})
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            path = _norm_path(target, loc.get("artifactLocation", {}).get("uri", ""))
            line = loc.get("region", {}).get("startLine", 0)
            msg = res.get("message", {}).get("text", "")
            sev = {"error": "high", "warning": "medium", "note": "low"}.get(res.get("level", "warning"), "medium")
            leads.append({
                "tool": "semgrep", "rule_id": rid, "kind": "code", "file": path, "line": line,
                "cwe": cwes, "severity_hint": sev, "message": redact_text(msg)[:500],
            })
    return leads


def _gitleaks(target: Path, raw: Path) -> list[dict]:
    data = read_json(raw / "gitleaks.json", []) or []
    leads = []
    for item in data:
        path = _norm_path(target, item.get("File", ""))
        leads.append({
            "tool": "gitleaks", "rule_id": item.get("RuleID", ""), "kind": "secret", "file": path,
            "line": item.get("StartLine", 0), "cwe": ["CWE-798"], "severity_hint": "high",
            "message": f"{item.get('Description', 'Secret')} (redacted)",
            "commit": (item.get("Commit") or "")[:12] or None,
            "history_only": bool(item.get("Commit")) and not (target / path).exists(),
        })
    return leads


def _trivy(target: Path, raw: Path) -> tuple[list[dict], list[dict]]:
    data = read_json(raw / "trivy.json", {}) or {}
    leads, deps = [], []
    for res in data.get("Results", []) or []:
        path = _norm_path(target, res.get("Target", ""))
        for v in res.get("Vulnerabilities", []) or []:
            deps.append({
                "tool": "trivy", "package": v.get("PkgName"), "version": v.get("InstalledVersion"),
                "ecosystem": res.get("Type"), "manifest": path, "ids": sorted({v.get("VulnerabilityID")} | set(v.get("VendorIDs") or [])),
                "fixed_version": v.get("FixedVersion") or "", "severity": (v.get("Severity") or "UNKNOWN").title(),
                "title": (v.get("Title") or "")[:200],
            })
        for m in res.get("Misconfigurations", []) or []:
            if m.get("Status") == "PASS":
                continue
            line = (m.get("CauseMetadata") or {}).get("StartLine") or 0
            leads.append({
                "tool": "trivy", "rule_id": m.get("ID", ""), "kind": "misconfig", "file": path, "line": line,
                "cwe": [], "severity_hint": (m.get("Severity") or "MEDIUM").lower(),
                "message": redact_text(f"{m.get('Title', '')}: {m.get('Message', '')}")[:500],
            })
        for s in res.get("Secrets", []) or []:
            leads.append({
                "tool": "trivy", "rule_id": s.get("RuleID", ""), "kind": "secret", "file": path,
                "line": s.get("StartLine", 0), "cwe": ["CWE-798"], "severity_hint": (s.get("Severity") or "HIGH").lower(),
                "message": f"{s.get('Title', 'Secret')} (redacted)",
            })
    return leads, deps


def _osv(target: Path, raw: Path) -> list[dict]:
    data = read_json(raw / "osv.json", {}) or {}
    deps = []
    for res in data.get("results", []) or []:
        manifest = _norm_path(target, res.get("source", {}).get("path", ""))
        for pkg in res.get("packages", []) or []:
            info = pkg.get("package", {})
            groups = pkg.get("groups") or [{"ids": [v.get("id")]} for v in pkg.get("vulnerabilities", [])]
            vulns = {v.get("id"): v for v in pkg.get("vulnerabilities", []) or []}
            for g in groups:
                ids = sorted(set(g.get("ids") or []) | set(g.get("aliases") or []))
                fixed = ""
                title = ""
                for vid in g.get("ids") or []:
                    v = vulns.get(vid, {})
                    title = title or (v.get("summary") or "")
                    for aff in v.get("affected", []) or []:
                        for rng in aff.get("ranges", []) or []:
                            for ev in rng.get("events", []) or []:
                                if ev.get("fixed"):
                                    fixed = ev["fixed"]
                sev = g.get("max_severity") or ""
                deps.append({
                    "tool": "osv-scanner", "package": info.get("name"), "version": info.get("version"),
                    "ecosystem": info.get("ecosystem"), "manifest": manifest, "ids": ids, "fixed_version": fixed,
                    "severity": _osv_band(sev), "title": title[:200],
                })
    return deps


def _osv_band(score: str) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "Unknown"
    return "Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 4 else "Low" if s > 0 else "Unknown"


def _human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def _exposed(target: Path, raw: Path) -> list[dict]:
    data = read_json(raw / "exposed.json", []) or []
    leads = []
    for item in data:
        size = item.get("bytes", 0)
        leads.append({
            "tool": "exposed-files", "rule_id": item.get("reason", "exposed"), "kind": "exposed_file",
            "file": item.get("file", ""), "line": 0, "cwe": ["CWE-530", "CWE-538"],
            "severity_hint": item.get("severity_hint", "medium"),
            "message": f"Web-accessible {item.get('reason', 'file')} ({_human_bytes(size)}) - remove from the web root or block it; contents not read",
        })
    return leads


def normalize(target: Path, raw: Path) -> dict:
    leads: list[dict] = []
    leads += _semgrep(target, raw)
    leads += _gitleaks(target, raw)
    t_leads, t_deps = _trivy(target, raw)
    leads += t_leads
    leads += _exposed(target, raw)
    deps = t_deps + _osv(target, raw)

    merged: dict[str, dict] = {}
    for ld in leads:
        family = ld["cwe"][0] if ld["cwe"] else ld["kind"]
        key = _fp(_merge_key(ld["file"]), str(ld["line"]), family)
        if key in merged:
            m = merged[key]
            if ld["tool"] not in m["tools"]:
                m["tools"].append(ld["tool"])
            m["rule_ids"].append(f"{ld['tool']}:{ld['rule_id']}")
            continue
        merged[key] = {
            "fingerprint": key, "tools": [ld["tool"]], "rule_ids": [f"{ld['tool']}:{ld['rule_id']}"],
            "kind": ld["kind"], "file": ld["file"], "line": ld["line"], "cwe": ld["cwe"],
            "severity_hint": ld["severity_hint"], "message": ld["message"],
            "likely_test_or_example": bool(TEST_PATH.search(ld["file"])),
            "likely_vendor": is_vendor_path(ld["file"]),
            "history_only": ld.get("history_only", False), "commit": ld.get("commit"),
            "triage": None, "triage_reason": None,
        }
    out_leads = sorted(merged.values(), key=lambda x: (x["file"], x["line"]))
    for i, ld in enumerate(out_leads, 1):
        ld["id"] = f"L-{i:04d}"

    dep_map: dict[str, dict] = {}
    for d in deps:
        key = _fp(str(d["package"]), str(d["version"]), ",".join(d["ids"][:1]))
        if key in dep_map:
            e = dep_map[key]
            e["ids"] = sorted(set(e["ids"]) | set(d["ids"]))
            e["tools"] = sorted(set(e["tools"]) | {d["tool"]})
            e["fixed_version"] = e["fixed_version"] or d["fixed_version"]
            continue
        d = dict(d)
        d["tools"] = [d.pop("tool")]
        d["reachability"] = "not_assessed"
        dep_map[key] = d
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    out_deps = sorted(dep_map.values(), key=lambda x: (order.get(x["severity"], 9), str(x["package"])))

    return {
        "leads": out_leads,
        "dependencies": out_deps,
        "counts": {
            "leads": len(out_leads),
            "secrets": sum(1 for x in out_leads if x["kind"] == "secret"),
            "code": sum(1 for x in out_leads if x["kind"] == "code"),
            "misconfig": sum(1 for x in out_leads if x["kind"] == "misconfig"),
            "exposed_files": sum(1 for x in out_leads if x["kind"] == "exposed_file"),
            "dependency_vulns": len(out_deps),
        },
    }
