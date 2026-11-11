# -----------------------------------------------------------------------------
# AI-Security-Audit-Skills
# Author   : Vijaya Kumar L  (Rise With VJ)
# GitHub   : https://github.com/risewithvj
# LinkedIn : https://www.linkedin.com/in/vijayakumarl/
# License  : MIT
# -----------------------------------------------------------------------------
"""Benchmark the confirmed findings against a known label list.

A labels file is {"name": "...", "labels": [{"id","class","file", ...}, ...]}.
A label can be matched three ways, strongest first:

  1. Exact id mapping. If the label carries a ``finding_id`` (or ``challenge_id``)
     and a confirmed finding has that same ``id`` (or lists it under ``challenge_id`` /
     ``maps_to``), that is an unambiguous match - no file or class check needed.
  2. File + class keyword. A confirmed finding cites the label's ``file`` and shares a
     class keyword (>= 4 letters) with the label's ``class``/``title``.
  3. File + acronym. Short attack-class acronyms (XSS, RCE, SSRF, XXE, JWT, CSRF, IDOR,
     SQLI, SSTI, LFI, RFI, XXE) are too short for the keyword rule, so they are matched
     as standalone tokens, case-insensitively.

Before the false-positive rate is computed, every "extra" confirmed finding is
reconciled against the labels: an extra that actually lands on a labelled file and
shares the label's class/acronym is a *duplicate detection of a known issue*, not a
false positive. Only the genuinely unmatched extras feed the false-positive rate.
Prints matched / missed / extra / false-positive rate so detection quality is
measurable across runs.
"""

from __future__ import annotations

import re
from pathlib import Path

from .common import read_json

# Attack-class acronyms that are shorter than the 4-letter keyword floor but are
# still decisive when they line up on the same file.
ACRONYMS = {"xss", "rce", "ssrf", "xxe", "jwt", "csrf", "idor", "sqli", "ssti",
            "lfi", "rfi", "xss", "ssti", "rce", "dos", "xpath", "nosql"}


def _finding_files(f: dict) -> set[str]:
    files = set()
    for key in ("trace", "affected_locations"):
        for t in f.get(key) or []:
            if t.get("file"):
                files.add(t["file"])
    return files


def _finding_ids(f: dict) -> set[str]:
    """Every id this finding can be addressed by, for exact label mapping."""
    ids = set()
    for key in ("id", "challenge_id", "maps_to", "label_id"):
        v = f.get(key)
        if isinstance(v, str):
            ids.add(v)
        elif isinstance(v, list):
            ids.update(x for x in v if isinstance(x, str))
    return ids


def _label_class_tokens(label: dict):
    raw = (label.get("class") or "") + " " + (label.get("title") or "")
    words = [w for w in re.split(r"[^a-z]+", raw.lower()) if len(w) >= 4]
    acrs = [w for w in re.split(r"[^a-z]+", raw.lower()) if w in ACRONYMS]
    return words, acrs


def _class_hits(label: dict, f: dict) -> bool:
    words, acrs = _label_class_tokens(label)
    hay = ((f.get("class") or "") + " " + (f.get("title") or "")).lower()
    hay_tokens = set(re.split(r"[^a-z]+", hay))
    if words and any(w in hay for w in words):
        return True
    if acrs and any(a in hay_tokens for a in acrs):
        return True
    return not words and not acrs  # no class given -> file alone decides


def _exact_id(label: dict, confirmed: list[dict]) -> str | None:
    want = {label.get("finding_id"), label.get("challenge_id"), label.get("id")}
    want = {w for w in want if isinstance(w, str)}
    if not want:
        return None
    for f in confirmed:
        if want & _finding_ids(f):
            return f["id"]
    return None


def _match(label: dict, confirmed: list[dict]) -> str | None:
    # Exact id/challenge mapping wins outright; otherwise fall back to the
    # file + class/acronym coverage test. A single root-cause finding may cover
    # more than one labelled challenge, so matching does not consume a finding.
    fid = _exact_id(label, confirmed)
    if fid:
        return fid
    lf = label.get("file")
    for f in confirmed:
        if lf and lf in _finding_files(f) and _class_hits(label, f):
            return f["id"]
    return None


def _reconciles(label: dict, f: dict) -> bool:
    """True if an unmatched extra finding actually corresponds to this label."""
    if _finding_ids(f) & {label.get("finding_id"), label.get("challenge_id"), label.get("id")}:
        return True
    lf = label.get("file")
    return bool(lf and lf in _finding_files(f) and _class_hits(label, f))


def run(run_dir: Path, labels_path: str) -> dict:
    fx = read_json(run_dir / "findings.json", {}) or {}
    confirmed = [f for f in fx.get("findings", []) if f.get("verdict") == "confirmed"]
    doc = read_json(Path(labels_path).expanduser(), {}) or {}
    labels = doc.get("labels", doc if isinstance(doc, list) else [])
    matched, missed, used = [], [], set()
    for lb in labels:
        fid = _match(lb, confirmed)
        if fid:
            matched.append({"label": lb, "finding": fid})
            used.add(fid)
        else:
            missed.append(lb)

    # Reconcile the leftover confirmed findings against the labels. One that lands on a
    # labelled file with a matching class is a duplicate detection, not a false positive.
    reconciled, genuine_extra = [], []
    for f in confirmed:
        if f["id"] in used:
            continue
        hit = next((lb for lb in labels if _reconciles(lb, f)), None)
        rec = {"id": f["id"], "class": f.get("class", ""), "files": sorted(_finding_files(f))}
        if hit:
            rec["reconciled_to"] = hit.get("id")
            reconciled.append(rec)
        else:
            genuine_extra.append(rec)

    fp_rate = round(len(genuine_extra) / len(confirmed), 3) if confirmed else 0.0
    return {"labels_file": str(labels_path), "name": doc.get("name", ""),
            "matched": matched, "missed": missed,
            "extra": genuine_extra, "reconciled_extra": reconciled,
            "counts": {"labels": len(labels), "confirmed": len(confirmed),
                       "matched": len(matched), "missed": len(missed),
                       "extra": len(genuine_extra), "reconciled_extra": len(reconciled),
                       "false_positive_rate": fp_rate}}
