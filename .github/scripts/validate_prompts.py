#!/usr/bin/env python3
# AI-Security-Audit-Skills | Vijaya Kumar L (Rise With VJ) | github.com/risewithvj | MIT
"""Validate docs/web/v1/prompts.json for the no-install web prompt system.

Checks:
  1. Every declared TYPE has a prompt in all three MODES (lite/pro/god).
  2. Every file referenced under `linked_files` exists inside docs/.
  3. Every prompt's text points at the runbook and names its MODE/TYPE.
Exit 1 on any failure.
"""
from __future__ import annotations
import json, sys
from pathlib import Path

DOCS = Path(__file__).resolve().parents[1].parent / "docs"
PJ = DOCS / "web" / "v1" / "prompts.json"


def main() -> int:
    doc = json.loads(PJ.read_text(encoding="utf-8"))
    modes = doc["modes"]
    types = doc["types"]
    prompts = doc["prompts"]
    errs = []

    have = {(p["type"], p["mode"]) for p in prompts}
    for t in types:
        for m in modes:
            if (t, m) not in have:
                errs.append(f"missing prompt for TYPE={t} MODE={m}")

    for rel in doc.get("linked_files", []):
        if not (DOCS / rel).exists():
            errs.append(f"linked file missing from docs/: {rel}")

    run = doc["runbook"]
    for p in prompts:
        txt = p.get("text", "")
        if run not in txt:
            errs.append(f"prompt {p.get('id')} does not link the runbook")
        if f"MODE={p['mode']}" not in txt or f"TYPE={p['type']}" not in txt:
            errs.append(f"prompt {p.get('id')} text does not match its MODE/TYPE")
        if not p.get("title") or not p.get("use_when"):
            errs.append(f"prompt {p.get('id')} missing title/use_when")

    if errs:
        print("prompts.json INVALID:")
        for e in errs:
            print("  -", e)
        return 1
    print(f"prompts.json OK: {len(types)} types x {len(modes)} modes, "
          f"{len(prompts)} prompts, all linked files present.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
