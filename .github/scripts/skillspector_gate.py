#!/usr/bin/env python3
# AI-Security-Audit-Skills | Vijaya Kumar L (Rise With VJ) | github.com/risewithvj | MIT
"""Gate SkillSpector output for CI.

A security-audit skill necessarily ships attack-pattern examples, example
payloads, and an engine that shells out to scanners, so SkillSpector's static
patterns light up on our own content. Those findings are reviewed once and
recorded, by fingerprint, in .github/skillspector-allowlist.json.

This gate FAILS the job only when a HIGH or CRITICAL finding appears that is NOT
already in the allowlist — i.e. a genuinely new high-risk pattern we introduced.
Informational / LOW / MEDIUM notes and coverage/parse limits never fail the job.

Usage:
    python skillspector_gate.py --scan report1.json [report2.json ...]
    python skillspector_gate.py --scan ... --update   # rewrite the allowlist
"""
from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ALLOWLIST = HERE.parent / "skillspector-allowlist.json"
BLOCKING = {"HIGH", "CRITICAL"}


def load_issues(paths):
    out = []
    for p in paths:
        try:
            data = json.loads(Path(p).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"::warning::could not read SkillSpector report {p}: {e}")
            continue
        skill = (data.get("skill") or {}).get("name") or Path(p).stem
        for i in data.get("issues", []):
            loc = i.get("location") or {}
            out.append({
                "skill": skill,
                "fingerprint": i.get("match_fingerprint"),
                "id": i.get("id"),
                "severity": str(i.get("severity", "")).upper(),
                "category": i.get("category"),
                "file": loc.get("file"),
                "line": loc.get("start_line"),
            })
    return out


def read_allowlist():
    if not ALLOWLIST.exists():
        return set()
    data = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    return {e["fingerprint"] for e in data.get("allowed", []) if e.get("fingerprint")}


def write_allowlist(issues):
    allowed = []
    seen = set()
    for i in sorted(issues, key=lambda x: (x["severity"], str(x["id"]), str(x["file"]))):
        if i["severity"] not in BLOCKING or not i["fingerprint"] or i["fingerprint"] in seen:
            continue
        seen.add(i["fingerprint"])
        allowed.append({
            "fingerprint": i["fingerprint"], "id": i["id"], "severity": i["severity"],
            "category": i["category"], "file": i["file"],
        })
    doc = {
        "_comment": (
            "Reviewed, by-design SkillSpector findings for this security-audit skill. "
            "Each entry is an attack-pattern example, example payload, or scanner-"
            "subprocess call that is expected in security-education content. CI fails "
            "only on HIGH/CRITICAL findings whose fingerprint is NOT listed here. "
            "Regenerate with: python .github/scripts/skillspector_gate.py --scan <reports> --update"
        ),
        "allowed": allowed,
    }
    ALLOWLIST.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(allowed)} allowlisted fingerprints to {ALLOWLIST}")


def summary(issues, new):
    import collections
    lines = ["## SkillSpector scan of our own skills", ""]
    by_sev = collections.Counter(i["severity"] for i in issues)
    lines.append(f"Total findings: **{len(issues)}** "
                 f"(CRITICAL {by_sev.get('CRITICAL',0)}, HIGH {by_sev.get('HIGH',0)}, "
                 f"MEDIUM {by_sev.get('MEDIUM',0)}, LOW {by_sev.get('LOW',0)}).")
    lines.append("")
    reviewed = sum(1 for i in issues if i["severity"] in BLOCKING) - len(new)
    lines.append(f"- {reviewed} HIGH/CRITICAL are reviewed, by-design findings (allowlisted).")
    if new:
        lines.append(f"- :x: **{len(new)} new HIGH/CRITICAL** not in the allowlist:")
        lines.append("")
        lines.append("| Severity | ID | Category | File | Line |")
        lines.append("|---|---|---|---|---|")
        for i in new:
            lines.append(f"| {i['severity']} | {i['id']} | {i['category']} | "
                         f"`{i['file']}` | {i['line']} |")
    else:
        lines.append("- :white_check_mark: No new HIGH/CRITICAL findings. Gate passes.")
    out = os.environ.get("GITHUB_STEP_SUMMARY")
    text = "\n".join(lines) + "\n"
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(text)
    print(text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", nargs="+", required=True)
    ap.add_argument("--update", action="store_true")
    args = ap.parse_args()
    issues = load_issues(args.scan)
    if args.update:
        write_allowlist(issues)
        return 0
    allow = read_allowlist()
    new = [i for i in issues if i["severity"] in BLOCKING and i["fingerprint"] not in allow]
    summary(issues, new)
    if new:
        print(f"::error::{len(new)} new HIGH/CRITICAL SkillSpector finding(s) not in allowlist")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
