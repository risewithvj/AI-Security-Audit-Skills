# -----------------------------------------------------------------------------
# AI-Security-Audit-Skills
# Author   : Vijaya Kumar L  (Rise With VJ)
# GitHub   : https://github.com/risewithvj
# LinkedIn : https://www.linkedin.com/in/vijayakumarl/
# License  : MIT
# -----------------------------------------------------------------------------
"""Machine checks that keep the report honest.

The most important one: every cited file:line is re-read from the target and
must contain the quoted snippet. A finding that cites code that is not there
cannot pass.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .common import find_secrets, read_json, read_text, redact_text

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
HEDGES = re.compile(r"\b(might|could potentially|possibly|may be vulnerable|consider|perhaps|it seems|appears to be vulnerable)\b", re.I)
CVSS4_BASE = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
CVSS4_VALUES = {
    "AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA",
    "VC": "HLN", "VI": "HLN", "VA": "HLN", "SC": "HLN", "SI": "HLN", "SA": "HLN",
}
SNIPPET_WINDOW = 3


def band(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Info"


def check_cvss_vector(vector: str) -> list[str]:
    errs = []
    if not vector.startswith("CVSS:4.0/"):
        return ["CVSS vector must start with 'CVSS:4.0/'"]
    parts = vector[len("CVSS:4.0/"):].split("/")
    seen = {}
    for p in parts:
        if ":" not in p:
            errs.append(f"bad CVSS metric '{p}'")
            continue
        k, v = p.split(":", 1)
        seen[k] = v
    for i, k in enumerate(CVSS4_BASE):
        if k not in seen:
            errs.append(f"CVSS vector missing base metric {k}")
        elif len(seen[k]) != 1 or seen[k] not in CVSS4_VALUES[k]:
            errs.append(f"CVSS metric {k} has invalid value '{seen[k]}'")
    base_order = [p.split(":")[0] for p in parts if p.split(":")[0] in CVSS4_BASE]
    if base_order != [k for k in CVSS4_BASE if k in base_order]:
        errs.append("CVSS base metrics are out of order")
    return errs


def cvss_compute(vector: str) -> float | None:
    """Return the CVSS 4.0 base score if the optional 'cvss' package is installed."""
    try:
        from cvss import CVSS4  # type: ignore
    except ImportError:
        return None
    try:
        return float(CVSS4(vector).base_score)
    except Exception:  # noqa: BLE001 - library raises several types
        return None


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def check_snippet(target: Path, step: dict, where: str) -> list[str]:
    errs = []
    f = step.get("file", "")
    if not f or Path(f).is_absolute() or ".." in Path(f).parts:
        return [f"{where}: file must be a path relative to the target, got '{f}'"]
    p = (target / f)
    if not p.is_file():
        return [f"{where}: cited file does not exist in target: {f}"]
    lines = read_text(p).splitlines()
    line = int(step.get("line", 0))
    if line < 1 or line > len(lines):
        return [f"{where}: line {line} is outside {f} (1..{len(lines)})"]
    snip = _norm(step.get("snippet", ""))
    if not snip:
        return [f"{where}: empty snippet"]
    lo, hi = max(0, line - 1 - SNIPPET_WINDOW), min(len(lines), line + SNIPPET_WINDOW)
    # Compare against both the raw and the redacted line, so a masked secret
    # in the snippet still matches the real code.
    window = [_norm(x) for x in lines[lo:hi]] + [_norm(redact_text(x)) for x in lines[lo:hi]]
    joined = " ".join(_norm(x) for x in lines[lo:hi])
    if not any(snip in w for w in window) and snip not in joined:
        errs.append(f"{where}: snippet not found at {f}:{line} (+/-{SNIPPET_WINDOW} lines). Snippet: '{snip[:90]}'")
    return errs


def _strings(obj: Any, path: str = ""):
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _strings(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _strings(v, f"{path}[{i}]")


def _schema_errors(doc: dict, schema_path: Path) -> list[str] | None:
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return None
    schema = read_json(schema_path)
    validator = jsonschema.Draft202012Validator(schema)
    out = []
    for e in sorted(validator.iter_errors(doc), key=lambda e: list(e.path)):
        loc = "/".join(str(x) for x in e.path) or "(root)"
        msg = e.message
        if isinstance(e.instance, (dict, list)) or len(msg) > 200:
            rule = "/".join(str(x) for x in list(e.schema_path)[-3:])
            msg = f"'{e.validator}' rule failed at schema {rule}" + (" (severity/cvss are only allowed on confirmed findings)" if e.validator == "not" else "")
        out.append(f"schema: {loc}: {msg}")
    return out


REQ = {
    "confirmed": ["plain", "description", "trace", "result", "cwe", "severity", "cvss", "confidence",
                  "business_impact", "root_cause", "recommendation", "regression_test"],
    "needs_validation": ["description", "trace", "missing_fact", "why_verification", "safe_check"],
    "rejected": ["reason"],
}
PREFIX = {"confirmed": "F-", "needs_validation": "V-", "rejected": "R-"}


def validate_findings(run: Path, schema_path: Path) -> dict:
    meta = read_json(run / "run-metadata.json", {})
    target = Path(meta.get("target", ""))
    doc = read_json(run / "findings.json")
    errors: list[str] = []
    warnings: list[str] = []
    if doc is None:
        return {"ok": False, "errors": ["findings.json not found in run folder"], "warnings": [], "counts": {}}

    schema_errs = _schema_errors(doc, schema_path)
    if schema_errs is None:
        warnings.append("jsonschema not installed; used built-in checks only (pip install jsonschema for full schema validation)")
    else:
        errors += schema_errs

    ledger = read_json(run / "coverage-ledger.json", []) or []
    ledger_ids = {u.get("coverage_id") for u in ledger if isinstance(u, dict)}

    framework = doc.get("framework", "security")
    ids = set()
    counts = {"confirmed": 0, "needs_validation": 0, "rejected": 0}
    sev_counts = {s: 0 for s in SEVERITIES}
    for i, f in enumerate(doc.get("findings", [])):
        fid = f.get("id", f"#{i}")
        v = f.get("verdict")
        if fid in ids:
            errors.append(f"{fid}: duplicate id")
        ids.add(fid)
        if v not in REQ:
            errors.append(f"{fid}: unknown verdict '{v}'")
            continue
        counts[v] += 1
        if not str(fid).startswith(PREFIX[v]):
            errors.append(f"{fid}: id must start with {PREFIX[v]} for verdict {v}")
        required = list(REQ[v])
        if v == "confirmed" and framework == "dpdp":
            required = [k for k in required if k != "cvss"]
            if not (f.get("dpdp") or {}).get("obligation"):
                errors.append(f"{fid}: DPDP findings need dpdp.obligation")
        for key in required:
            if f.get(key) in (None, "", [], {}):
                errors.append(f"{fid}: missing required field '{key}' for {v}")
        if v != "confirmed" and ("severity" in f or "cvss" in f):
            errors.append(f"{fid}: only confirmed findings may carry severity or CVSS")

        if v == "confirmed":
            sev = f.get("severity")
            if sev in sev_counts:
                sev_counts[sev] += 1
            cv = f.get("cvss") or {}
            vec, score = cv.get("vector", ""), cv.get("score")
            if vec:
                for e in check_cvss_vector(vec):
                    errors.append(f"{fid}: {e}")
            if isinstance(score, (int, float)):
                b = band(float(score))
                if sev and b != sev:
                    gap = SEVERITIES.index(b) - SEVERITIES.index(sev) if sev in SEVERITIES else 9
                    if gap != 1:
                        errors.append(f"{fid}: severity '{sev}' is not allowed for CVSS {score} (band '{b}'); it may be at most one band above, never below")
                    elif not f.get("severity_rationale"):
                        errors.append(f"{fid}: severity '{sev}' is one band above CVSS band '{b}'; add severity_rationale (for example the data sensitivity and scale)")
                computed = cvss_compute(vec) if vec else None
                if computed is not None and abs(computed - float(score)) > 0.05:
                    errors.append(f"{fid}: CVSS score {score} does not match vector (computed {computed})")
            rec = f.get("recommendation") or {}
            if not rec.get("production_risk"):
                errors.append(f"{fid}: recommendation.production_risk is required (what could break)")
            for field in ("title", "description", "result"):
                m = HEDGES.search(f.get(field, "") or "")
                if m:
                    errors.append(f"{fid}: hedge word '{m.group(0)}' in confirmed {field}; prove it or mark needs_validation")
            plain = f.get("plain") or {}
            for k in ("what_this_is", "problem", "fix", "if_we_skip"):
                if not plain.get(k):
                    errors.append(f"{fid}: plain.{k} is required")
            if f.get("confidence") not in ("High", "Medium"):
                errors.append(f"{fid}: confirmed confidence must be High or Medium")

        if v in ("confirmed", "needs_validation"):
            steps = (f.get("trace") or []) + (f.get("affected_locations") or [])
            if target.is_dir():
                for j, step in enumerate(steps):
                    errors += check_snippet(target, step, f"{fid} trace[{j}]")
            else:
                errors.append(f"target folder not found: {target}; cannot verify snippets")
                break
            for u in f.get("ledger_units", []) or []:
                if ledger_ids and u not in ledger_ids:
                    warnings.append(f"{fid}: ledger unit '{u}' not in coverage-ledger.json")

        for path, s in _strings(f):
            for name, val in find_secrets(s):
                errors.append(f"{fid}.{path}: contains an unredacted {name} ({val[:4]}...). Mask it")

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "counts": {**counts, "by_severity": sev_counts},
    }


LEDGER_STATUSES = {"planned", "in_progress", "covered", "candidate", "blocked", "deferred", "not_applicable", "out_of_scope"}


def validate_ledger(run: Path) -> dict:
    data = read_json(run / "coverage-ledger.json")
    errors: list[str] = []
    if data is None:
        return {"ok": False, "errors": ["coverage-ledger.json not found"], "summary": {}}
    if not isinstance(data, list):
        return {"ok": False, "errors": ["coverage-ledger.json must be a JSON array"], "summary": {}}
    seen = set()
    summary: dict[str, int] = {}
    for i, u in enumerate(data):
        if not isinstance(u, dict):
            errors.append(f"unit #{i} is not an object")
            continue
        cid = u.get("coverage_id")
        if not cid:
            errors.append(f"unit #{i}: missing coverage_id")
        elif cid in seen:
            errors.append(f"duplicate coverage_id: {cid}")
        seen.add(cid)
        st = u.get("status")
        summary[st] = summary.get(st, 0) + 1
        if st not in LEDGER_STATUSES:
            errors.append(f"{cid}: invalid status '{st}'")
            continue
        for k in ("surface", "boundary", "attack_class"):
            if not u.get(k):
                errors.append(f"{cid}: missing '{k}'")
        rp = u.get("reviewed_paths") or []
        if st in ("covered", "candidate", "blocked") and not rp:
            errors.append(f"{cid}: status {st} requires reviewed_paths")
        if st == "candidate" and not u.get("result_ids"):
            errors.append(f"{cid}: status candidate requires result_ids")
        if st in ("blocked", "deferred", "not_applicable", "out_of_scope") and not u.get("notes"):
            errors.append(f"{cid}: status {st} requires a reason in notes")
        if st == "planned" and (rp or u.get("result_ids")):
            errors.append(f"{cid}: planned unit must not have evidence yet")
    return {"ok": not errors, "errors": errors, "summary": summary, "units": len(data)}
