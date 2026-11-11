# -----------------------------------------------------------------------------
# AI-Security-Audit-Skills
# Author   : Vijaya Kumar L  (Rise With VJ)
# GitHub   : https://github.com/risewithvj
# LinkedIn : https://www.linkedin.com/in/vijayakumarl/
# License  : MIT
# -----------------------------------------------------------------------------
"""WordPress plugin/theme version inventory, with an optional WPScan lookup.

OSV and Trivy do not carry WordPress plugin/theme advisories, so this reads each
component's slug and version from the source and, only when WPSCAN_API_TOKEN is
set, queries the WPScan API (sending just the slug and version - never any site
data). Without a token the components are listed as 'not checked'.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from pathlib import Path

from .common import IGNORE_DIRS, read_text

STABLE_TAG = re.compile(r"^\s*Stable tag:\s*([0-9][0-9A-Za-z.\-]*)", re.I | re.M)
HDR_VERSION = re.compile(r"^\s*(?:\*\s*)?Version:\s*([0-9][0-9A-Za-z.\-]*)", re.I | re.M)


def _version_of(folder: Path, kind: str) -> str | None:
    if kind == "theme":
        m = HDR_VERSION.search(read_text(folder / "style.css"))
        return m.group(1).strip() if m else None
    rt = folder / "readme.txt"
    if rt.exists():
        m = STABLE_TAG.search(read_text(rt))
        if m and m.group(1).lower() != "trunk":
            return m.group(1).strip()
    for php in list(folder.glob("*.php"))[:8]:
        m = HDR_VERSION.search(read_text(php)[:4000])
        if m:
            return m.group(1).strip()
    return None


def _wp_content_dirs(target: Path) -> list[Path]:
    found = []
    for base in [target / "wp-content", target / "wordpress" / "wp-content"]:
        if base.is_dir():
            found.append(base)
    if not found:
        for wc in target.rglob("wp-content"):
            if not any(part in IGNORE_DIRS for part in wc.parts):
                found.append(wc)
                break
    return found


def collect_components(target: Path) -> list[dict]:
    comps: list[dict] = []
    seen = set()
    for wc in _wp_content_dirs(target):
        for kind, sub in (("plugin", "plugins"), ("theme", "themes")):
            d = wc / sub
            if not d.is_dir():
                continue
            for item in sorted(d.iterdir()):
                if not item.is_dir() or item.name in seen:
                    continue
                seen.add(item.name)
                comps.append({"slug": item.name, "type": kind, "version": _version_of(item, kind)})
    return comps


def _wpscan(slug: str, kind: str, token: str) -> dict | None:
    url = f"https://wpscan.com/api/v3/{'plugins' if kind == 'plugin' else 'themes'}/{slug}"
    req = urllib.request.Request(url, headers={"Authorization": f"Token token={token}", "User-Agent": "aisa"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None


def _vuln_rows(comp: dict, data: dict) -> list[dict]:
    node = (data or {}).get(comp["slug"], {})
    out = []
    for v in node.get("vulnerabilities", []) or []:
        fixed = (v.get("fixed_in") or "")
        out.append({"id": (v.get("references", {}).get("cve", [None]) or [None])[0] or v.get("title", "")[:60],
                    "title": v.get("title", "")[:160], "fixed_in": fixed})
    return out


def scan(target: Path, run: Path) -> dict:
    comps = collect_components(target)
    token = os.environ.get("WPSCAN_API_TOKEN", "").strip()
    checked = bool(token)
    deps: list[dict] = []
    for c in comps:
        row = {"package": f"{c['slug']} ({c['type']})", "version": c.get("version") or "unknown",
               "ecosystem": f"wordpress-{c['type']}", "tools": ["wpscan"] if checked else [],
               "reachability": "not_assessed"}
        if checked and c.get("version"):
            data = _wpscan(c["slug"], c["type"], token)
            vulns = _vuln_rows(c, data) if data else []
            unresolved = [v for v in vulns if not v["fixed_in"] or _older(c["version"], v["fixed_in"])]
            row["ids"] = [v["id"] for v in unresolved] or (["no known vulnerabilities (WPScan)"] if data is not None else ["WPScan lookup failed"])
            row["fixed_version"] = next((v["fixed_in"] for v in unresolved if v["fixed_in"]), "")
            row["severity"] = "High" if unresolved else "Low"
            row["title"] = "; ".join(v["title"] for v in unresolved[:3])
        else:
            row["ids"] = ["not checked: no WordPress vulnerability feed (set WPSCAN_API_TOKEN)"]
            row["fixed_version"] = ""
            row["severity"] = "Unknown"
            row["title"] = ""
        deps.append(row)
    out = {"components": comps, "checked": checked,
           "note": "WPScan lookup ran" if checked else "no WPSCAN_API_TOKEN: versions listed but not checked against a vulnerability feed",
           "dependencies": deps}
    (run / "wpvulns.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    # Merge into leads.json so the report's dependency table shows them.
    leads_path = run / "leads.json"
    try:
        leads = json.loads(leads_path.read_text(encoding="utf-8")) if leads_path.exists() else {"leads": [], "dependencies": [], "counts": {}}
        have = {d.get("package") for d in leads.get("dependencies", [])}
        leads.setdefault("dependencies", []).extend(d for d in deps if d["package"] not in have)
        leads.setdefault("counts", {})["dependency_vulns"] = len(leads["dependencies"])
        leads_path.write_text(json.dumps(leads, indent=2), encoding="utf-8")
    except (OSError, ValueError):
        pass
    return out


def _older(cur: str, fixed: str) -> bool:
    def parts(v):
        return [int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v)[:4]]
    try:
        return parts(cur) < parts(fixed)
    except (ValueError, TypeError):
        return True
