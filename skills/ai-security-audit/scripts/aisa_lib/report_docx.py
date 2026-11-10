# -----------------------------------------------------------------------------
# AI-Security-Audit-Skills
# Author   : Vijaya Kumar L  (Rise With VJ)
# GitHub   : https://github.com/risewithvj
# LinkedIn : https://www.linkedin.com/in/vijayakumarl/
# License  : MIT
# -----------------------------------------------------------------------------
"""Build the VAPT-style DOCX report from validated records only.

Theme: Calibri, blue section headings, blue-header tables with light grey
label columns, colour-coded severity cells and distribution cards, a running
header with an optional logo, and a confidential footer.
"""

from __future__ import annotations

import datetime as _dt
import os
import subprocess
from pathlib import Path

from . import __url__, __version__
from .common import IS_WINDOWS, read_json, which

try:
    from docx import Document
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_TAB_ALIGNMENT
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Pt, RGBColor, Twips
except ImportError:  # pragma: no cover - checked by doctor
    Document = None

FONT = "Calibri"
BLUE = "1155CC"
HEAD_FILL = "3C78D8"
LABEL_FILL = "F3F3F3"
BORDER = "BFBFBF"
GREY = "444444"
CONTENT_DXA = 9360
SEV_STYLE = {
    "Critical": ("CC0000", "F4CCCC"),
    "High": ("B45F06", "FCE5CD"),
    "Medium": ("BF9000", "FFF2CC"),
    "Low": ("38761D", "D9EAD3"),
    "Info": (GREY, "F3F3F3"),
    "Unverified": (GREY, "EFEFEF"),
}
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
BANNER = {
    "Critical": "CRITICAL SEVERITY - IMMEDIATE REMEDIATION REQUIRED",
    "High": "HIGH SEVERITY - PRIORITY REMEDIATION REQUIRED",
    "Medium": "MEDIUM SEVERITY - REMEDIATION RECOMMENDED",
    "Low": "LOW SEVERITY - HARDENING RECOMMENDED",
    "Info": "INFORMATIONAL FINDINGS ONLY",
    "None": "NO CONFIRMED VULNERABILITIES IN THE CHECKED SCOPE",
}
OWASP_WEB = [
    ("A01:2025", "Broken Access Control"), ("A02:2025", "Security Misconfiguration"),
    ("A03:2025", "Software Supply Chain Failures"), ("A04:2025", "Cryptographic Failures"),
    ("A05:2025", "Injection"), ("A06:2025", "Insecure Design"), ("A07:2025", "Authentication Failures"),
    ("A08:2025", "Software or Data Integrity Failures"), ("A09:2025", "Security Logging and Alerting Failures"),
    ("A10:2025", "Mishandling of Exceptional Conditions"),
]
OWASP_API = [
    ("API1:2023", "Broken Object Level Authorization"), ("API2:2023", "Broken Authentication"),
    ("API3:2023", "Broken Object Property Level Authorization"), ("API4:2023", "Unrestricted Resource Consumption"),
    ("API5:2023", "Broken Function Level Authorization"), ("API6:2023", "Unrestricted Access to Sensitive Business Flows"),
    ("API7:2023", "Server Side Request Forgery"), ("API8:2023", "Security Misconfiguration"),
    ("API9:2023", "Improper Inventory Management"), ("API10:2023", "Unsafe Consumption of APIs"),
]
OWASP_LLM = [
    ("LLM01:2025", "Prompt Injection"), ("LLM02:2025", "Sensitive Information Disclosure"), ("LLM03:2025", "Supply Chain"),
    ("LLM04:2025", "Data and Model Poisoning"), ("LLM05:2025", "Improper Output Handling"), ("LLM06:2025", "Excessive Agency"),
    ("LLM07:2025", "System Prompt Leakage"), ("LLM08:2025", "Vector and Embedding Weaknesses"),
    ("LLM09:2025", "Misinformation"), ("LLM10:2025", "Unbounded Consumption"),
]


# --- low-level helpers -------------------------------------------------------

def _rpr(run, size=10, bold=False, italic=False, color="000000", font=FONT):
    run.font.name = font
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.insert(0, rfonts)
    for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rfonts.set(qn(a), font)
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    run.font.color.rgb = RGBColor.from_string(color)
    return run


def _para(container, text="", size=10.5, bold=False, italic=False, color="000000", align=None, after=6, before=0, font=FONT, line=1.1):
    p = container.add_paragraph()
    pf = p.paragraph_format
    pf.space_after = Pt(after)
    pf.space_before = Pt(before)
    pf.line_spacing = line
    if align:
        p.alignment = align
    if text:
        _rpr(p.add_run(text), size, bold, italic, color, font)
    return p


def _shade(cell, fill):
    tcpr = cell._element.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tcpr.append(shd)


def _cell_fmt(cell, width, fill=None, valign="center"):
    tcpr = cell._element.get_or_add_tcPr()
    tcw = OxmlElement("w:tcW")
    tcw.set(qn("w:w"), str(width))
    tcw.set(qn("w:type"), "dxa")
    tcpr.append(tcw)
    borders = OxmlElement("w:tcBorders")
    for side in ("top", "left", "bottom", "right"):
        b = OxmlElement(f"w:{side}")
        b.set(qn("w:val"), "single")
        b.set(qn("w:sz"), "4")
        b.set(qn("w:color"), BORDER)
        borders.append(b)
    tcpr.append(borders)
    if fill:
        _shade(cell, fill)
    mar = OxmlElement("w:tcMar")
    for side, w in (("top", 90), ("left", 120), ("bottom", 90), ("right", 120)):
        m = OxmlElement(f"w:{side}")
        m.set(qn("w:w"), str(w))
        m.set(qn("w:type"), "dxa")
        mar.append(m)
    tcpr.append(mar)
    va = OxmlElement("w:vAlign")
    va.set(qn("w:val"), valign)
    tcpr.append(va)


def _table(doc, widths):
    t = doc.add_table(rows=0, cols=len(widths))
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    tblpr = t._element.tblPr
    tblw = OxmlElement("w:tblW")
    tblw.set(qn("w:w"), str(sum(widths)))
    tblw.set(qn("w:type"), "dxa")
    tblpr.append(tblw)
    layout = OxmlElement("w:tblLayout")
    layout.set(qn("w:type"), "fixed")
    tblpr.append(layout)
    grid = t._element.find(qn("w:tblGrid"))
    for gc, w in zip(grid.findall(qn("w:gridCol")), widths):
        gc.set(qn("w:w"), str(w))
    t._aisa_widths = widths
    return t


def _write_cell(cell, text, size=10, bold=False, color="000000", italic=False, align=None, font=FONT):
    cell.paragraphs[0].text = ""
    lines = str(text).split("\n") if text is not None else [""]
    for i, line in enumerate(lines):
        p = cell.paragraphs[0] if i == 0 else cell.add_paragraph()
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = 1.1
        if align:
            p.alignment = align
        _rpr(p.add_run(line), size, bold, italic, color, font)


def _no_split(row):
    trpr = row._tr.get_or_add_trPr()
    cs = OxmlElement("w:cantSplit")
    cs.set(qn("w:val"), "true")
    trpr.append(cs)


def _row(table, values, fills=None, bold=False, colors=None, header=False, aligns=None, mono_cols=(), bold_cols=()):
    row = table.add_row()
    _no_split(row)
    cells = row.cells
    widths = table._aisa_widths
    for i, (c, v) in enumerate(zip(cells, values)):
        fill = HEAD_FILL if header else (fills[i] if fills else None)
        _cell_fmt(c, widths[i], fill)
        color = "FFFFFF" if header else (colors[i] if colors and colors[i] else "000000")
        align = WD_ALIGN_PARAGRAPH.CENTER if header else (aligns[i] if aligns else None)
        _write_cell(c, v, 10, bold or header or i in bold_cols, color, align=align,
                    font="Consolas" if i in mono_cols else FONT)
    if header:
        trpr = table.rows[-1]._tr.get_or_add_trPr()
        th = OxmlElement("w:tblHeader")
        th.set(qn("w:val"), "true")
        trpr.append(th)
    return cells


def _kv_table(doc, rows, label_w=2200):
    t = _table(doc, [label_w, CONTENT_DXA - label_w])
    for label, value, *opt in rows:
        row = t.add_row()
        _no_split(row)
        cells = row.cells
        _cell_fmt(cells[0], label_w, LABEL_FILL)
        _write_cell(cells[0], label, 10, True)
        _cell_fmt(cells[1], CONTENT_DXA - label_w)
        style = opt[0] if opt else {}
        _write_cell(cells[1], value, style.get("size", 10), style.get("bold", False), style.get("color", "000000"),
                    font=style.get("font", FONT))
    _para(doc, "", after=4)
    return t


def _heading(doc, text, level=1):
    size = {1: 16, 2: 13, 3: 11.5}[level]
    p = _para(doc, "", after=6 if level > 1 else 8, before=12 if level == 1 else 8)
    _rpr(p.add_run(text), size, True, False, BLUE)
    p.paragraph_format.keep_with_next = True
    return p


def _bullets(doc, items, size=10.5):
    for it in items:
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Twips(360)
        p.paragraph_format.first_line_indent = Twips(-220)
        p.paragraph_format.space_after = Pt(3)
        _rpr(p.add_run("\u25cf  "), 8, False, False, BLUE)
        _rpr(p.add_run(it), size)


def _page_break(doc):
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


def _field(run, instr):
    for tag, text in (("begin", None), ("instr", instr), ("separate", None), ("end", None)):
        if tag == "instr":
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = text
        else:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), tag)
        run._r.append(el)


def _bottom_border(paragraph, color=BORDER, top=False):
    ppr = paragraph._p.get_or_add_pPr()
    pbdr = OxmlElement("w:pBdr")
    b = OxmlElement("w:top" if top else "w:bottom")
    b.set(qn("w:val"), "single")
    b.set(qn("w:sz"), "6")
    b.set(qn("w:space"), "4")
    b.set(qn("w:color"), color)
    pbdr.append(b)
    ppr.append(pbdr)


# --- content helpers ---------------------------------------------------------

def _overall(findings):
    conf = [f for f in findings if f.get("verdict") == "confirmed"]
    if not conf:
        return "None"
    return min((f.get("severity", "Info") for f in conf), key=lambda s: SEV_ORDER.get(s, 9))


def _loc(f):
    if f.get("location"):
        return f["location"]
    tr = f.get("trace") or []
    return ", ".join(f"{s['file']}:{s['line']}" for s in tr[:3]) or "-"


def _trace_text(f):
    out = []
    for i, s in enumerate((f.get("trace") or []) + (f.get("affected_locations") or []), 1):
        note = f"  ({s['note']})" if s.get("note") else ""
        out.append(f"{i}. {s['file']}:{s['line']}{note}\n    {s['snippet']}")
    return "\n".join(out) or "-"


def _first_sentence(text, limit=220):
    text = (text or "").strip().replace("\n", " ")
    for sep in (". ", "; "):
        if sep in text[:limit]:
            return text[: text.index(sep, 0) + 1]
    return text[:limit]


def build(run: Path, out_path: Path, framework: str | None = None) -> Path:
    if Document is None:
        raise RuntimeError("python-docx is not installed. Run: pip install python-docx")
    meta = read_json(run / "run-metadata.json", {})
    doc_data = read_json(run / "findings.json", {"findings": []})
    leads = read_json(run / "leads.json", {"leads": [], "dependencies": [], "counts": {}})
    ledger = read_json(run / "coverage-ledger.json", []) or []
    stack = read_json(run / "stack.json", {})
    framework = framework or doc_data.get("framework", "security")
    is_dpdp = framework == "dpdp"
    findings = doc_data.get("findings", [])
    conf = sorted([f for f in findings if f.get("verdict") == "confirmed"], key=lambda f: (SEV_ORDER.get(f.get("severity"), 9), f["id"]))
    nv = [f for f in findings if f.get("verdict") == "needs_validation"]
    rej = [f for f in findings if f.get("verdict") == "rejected"]
    overall = doc_data.get("overall_risk") or _overall(findings)
    rep = meta.get("report", {})
    app = rep.get("app") or Path(meta.get("target", "application")).name
    client = rep.get("client") or ""
    prepared = rep.get("prepared_by") or "Vijaya Kumar L"
    reviewed = rep.get("reviewed_by") or "-"
    date = rep.get("date") or _dt.date.today().strftime("%B %d, %Y").replace(" 0", " ")
    title = "DPDP ACT 2023 COMPLIANCE AUDIT REPORT" if is_dpdp else "SOURCE CODE SECURITY AUDIT REPORT"
    short = "DPDP COMPLIANCE AUDIT REPORT" if is_dpdp else "SECURITY AUDIT REPORT"

    doc = Document()
    sec = doc.sections[0]
    sec.page_width, sec.page_height = Twips(12240), Twips(15840)
    sec.left_margin = sec.right_margin = Twips(1440)
    sec.top_margin = sec.bottom_margin = Twips(1300)
    sec.header_distance = sec.footer_distance = Twips(560)
    st = doc.styles["Normal"]
    st.font.name = FONT
    st.font.size = Pt(10.5)
    st.element.rPr.rFonts.set(qn("w:eastAsia"), FONT)

    # header and footer
    hp = sec.header.paragraphs[0]
    logo = rep.get("logo")
    if logo and Path(logo).expanduser().is_file():
        from docx.shared import Inches
        hp.add_run().add_picture(str(Path(logo).expanduser()), height=Inches(0.32))
    else:
        _rpr(hp.add_run(rep.get("org_short") or client or "AI Security Audit"), 11, True, False, BLUE)
    _bottom_border(hp)
    fp = sec.footer.paragraphs[0]
    fp.style = doc.styles["Normal"]
    fp.paragraph_format.tab_stops.add_tab_stop(Twips(CONTENT_DXA), WD_TAB_ALIGNMENT.RIGHT)
    _bottom_border(fp, top=True)
    _rpr(fp.add_run(f"{short} by {prepared}"), 8, False, False, "7F7F7F")
    _rpr(fp.add_run("\tConfidential \u2013 Internal Use  |  Page "), 8, False, False, "7F7F7F")
    _field(_rpr(fp.add_run(), 8, False, False, "7F7F7F"), "PAGE")

    # cover
    _para(doc, "", after=40)
    _para(doc, title, 18, True, color=BLUE, align=WD_ALIGN_PARAGRAPH.CENTER, after=10)
    sev_color = SEV_STYLE.get(overall, (GREY, ""))[0] if overall != "None" else "38761D"
    _para(doc, BANNER.get(overall, BANNER["None"]), 12, True, color=sev_color, align=WD_ALIGN_PARAGRAPH.CENTER, after=40)
    _para(doc, "Target Application:", 11, align=WD_ALIGN_PARAGRAPH.CENTER, after=6)
    _para(doc, app, 16, True, color=BLUE, align=WD_ALIGN_PARAGRAPH.CENTER, after=6)
    if client:
        _para(doc, client, 11, italic=True, align=WD_ALIGN_PARAGRAPH.CENTER, after=36)
    else:
        _para(doc, "", after=30)
    tot = f"{len(conf)} Confirmed  |  {len(nv)} Require{'s' if len(nv) == 1 else ''} Verification"
    testing = ("Source-code privacy and data-protection review (white-box), PII inventory, consent, rights, retention and safeguards"
               if is_dpdp else "Source-code security audit (white-box): AI-assisted manual review, SAST, secrets, dependency and IaC analysis")
    _kv_table(doc, [
        ("Report Date", date),
        ("Testing Type", testing),
        ("Target", rep.get("target_label") or meta.get("repo") or app),
        ("Risk Rating", overall.upper() if overall != "None" else "NONE CONFIRMED", {"bold": True, "color": sev_color}),
        ("Total Findings", tot, {"bold": True}),
        ("Classification", "CONFIDENTIAL - Authorized Personnel Only", {"bold": True, "color": "CC0000"}),
        ("Prepared by", prepared),
        ("Reviewed by", reviewed),
    ], label_w=2400)
    _page_break(doc)

    n = 0

    def H(text, level=1):
        nonlocal n
        if level == 1:
            n += 1
            _heading(doc, f"{n}. {text}", 1)
        else:
            _heading(doc, text, level)

    # 1. executive summary
    H("Executive Summary")
    summary = doc_data.get("executive_summary") or _auto_summary(app, conf, nv, overall, is_dpdp)
    for para in summary.split("\n\n"):
        _para(doc, para.strip(), 10.5, after=8)
    _heading(doc, f"{n}.1 {'Gap' if is_dpdp else 'Vulnerability'} Summary", 2)
    t = _table(doc, [700, 3700, 1300, 1660, 800, 1200])
    _row(t, ["#", "Finding" if is_dpdp else "Vulnerability", "Severity", "Obligation" if is_dpdp else "Category", "CVSS", "Status"], header=True)
    for f in conf:
        c, fill = SEV_STYLE.get(f["severity"], (GREY, None))
        cat = (f.get("dpdp") or {}).get("obligation") if is_dpdp else f.get("class", "")
        _row(t, [f["id"], f["title"], f["severity"].upper(), cat or "", str((f.get("cvss") or {}).get("score", "-")), "Open"],
             fills=[None, None, fill, None, None, None], colors=[None, None, c, None, None, None],
             aligns=[WD_ALIGN_PARAGRAPH.CENTER, None, WD_ALIGN_PARAGRAPH.CENTER, None, WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.CENTER], bold_cols=(2,))
    for f in nv:
        c, fill = SEV_STYLE["Unverified"]
        cat = (f.get("dpdp") or {}).get("obligation") if is_dpdp else f.get("class", "")
        _row(t, [f["id"], f["title"], "UNVERIFIED", cat or "", "TBD", "Needs Verification"],
             fills=[None, None, fill, None, None, None], colors=[None, None, c, None, None, None],
             aligns=[WD_ALIGN_PARAGRAPH.CENTER, None, WD_ALIGN_PARAGRAPH.CENTER, None, WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.CENTER], bold_cols=(2,))
    if not conf and not nv:
        _row(t, ["-", "No confirmed findings in the checked scope", "-", "-", "-", "-"])
    _para(doc, "", after=4)

    _heading(doc, f"{n}.2 Severity Distribution", 2)
    counts = {s: sum(1 for f in conf if f.get("severity") == s) for s in SEV_ORDER}
    cards = [("CRITICAL", "Critical", counts["Critical"]), ("HIGH", "High", counts["High"]),
             ("MEDIUM", "Medium", counts["Medium"]), ("LOW / UNVERIFIED", "Low", counts["Low"] + counts["Info"] + len(nv))]
    t = _table(doc, [2340] * 4)
    r1 = t.add_row().cells
    r2 = t.add_row().cells
    for i, (label, key, cnt) in enumerate(cards):
        c, fill = SEV_STYLE[key]
        for cell, txt, size in ((r1[i], label, 10), (r2[i], str(cnt), 20)):
            _cell_fmt(cell, 2340, fill)
            _write_cell(cell, txt, size, True, c, align=WD_ALIGN_PARAGRAPH.CENTER)
    _para(doc, "", after=4)

    # 2. scope and methodology
    H("Assessment Scope & Methodology")
    _heading(doc, f"{n}.1 Scope", 2)
    scope = meta.get("scope") or ["Whole repository"]
    langs = ", ".join(list((stack.get("languages") or {}).keys())[:8]) or "-"
    feats = ", ".join(sorted({x for v in (stack.get("features") or {}).values() for x in v})[:14]) or "-"
    _bullets(doc, [
        f"Target: {rep.get('target_label') or meta.get('repo') or app} (source code, commit {meta.get('source_ref') or 'not recorded'})",
        f"In-scope paths: {', '.join(scope)}",
        f"Languages: {langs}",
        f"Frameworks and services detected: {feats}",
        f"Profile: {meta.get('profile', 'standard')} ({meta.get('votes', 3)} independent verification vote(s) per candidate)",
        f"Audit period: {rep.get('period') or date}",
    ])
    if is_dpdp:
        _para(doc, "Timeline: the DPDP Rules 2025 were notified in November 2025. Most operational duties (Rules 3 and 5 to 16: notice, security safeguards, breach intimation, retention and erasure, children's data, rights and cross-border transfer) apply 18 months after notification, around May 2027; consent manager registration applies after one year.", 10, italic=True, after=6)
    _heading(doc, f"{n}.2 Methodology", 2)
    if is_dpdp:
        _para(doc, "The review mapped how personal data enters, is stored, used, shared, retained and erased in the source code, and compared it with obligations under the Digital Personal Data Protection Act, 2023 and the DPDP Rules, 2025:", after=4)
        _bullets(doc, ["Phase 0: scope and safety gate", "Phase 1: data map and PII inventory (machine-assisted)",
                       "Phase 2: obligation-by-obligation review: notice, consent, purpose, minimisation, accuracy, security safeguards, breach readiness, retention and erasure, Data Principal rights, children's data, processors and cross-border transfer",
                       "Phase 3: independent verification of every gap from source", "Phase 4: report with recommendations only"])
    else:
        _para(doc, "The audit followed a six-phase, evidence-gated workflow aligned with the OWASP Testing Guide, OWASP Top 10:2025, OWASP API Security Top 10:2023 and, where relevant, the OWASP Top 10 for LLM Applications 2025:", after=4)
        _bullets(doc, [
            "Phase 0 - Scope and safety gate: read-only, source-only, no target code executed, no live systems contacted",
            "Phase 1 - Recon: architecture, principals, trust boundaries, entry points, sensitive-data inventory, coverage ledger",
            "Phase 2 - Automated scanning: SAST, secrets (files and Git history), dependency CVEs, IaC and container misconfiguration",
            "Phase 3 - AI-assisted manual hunting by attack class, with coverage critics and variant analysis",
            "Phase 4 - Independent verification: each candidate re-checked by verifiers that did not find it; every cited file and line machine-checked",
            "Phase 5 - Reporting from validated records only, with recommendations (no code changed)",
        ])
    scans = meta.get("scanners") or {}
    if scans:
        _heading(doc, f"{n}.3 Tools", 2)
        t = _table(doc, [1700, 2400, 3460, 1800])
        _row(t, ["Tool", "Version", "Purpose", "Status"], header=True)
        for tool, r in scans.items():
            status = {"ok": "Ran", "not_installed": "Not installed", "timeout": "Timed out", "failed": "Failed", "skipped": "Skipped (no lockfile)"}.get(r.get("status"), r.get("status", "-"))
            # Surface how Semgrep actually ran: the pysemgrep fallback and a
            # JSON->SARIF conversion mean a degraded run is never shown as clean.
            if tool == "semgrep":
                extra = []
                if r.get("impl") and r["impl"] != "semgrep":
                    extra.append(f"via {r['impl']}")
                if r.get("sarif_mode") == "json-converted":
                    extra.append("JSON->SARIF")
                if r.get("status") == "ok" and r.get("rules") and any("bundled" in x and "only" in x for x in r["rules"]):
                    extra.append("bundled rules only")
                if extra:
                    status = f"{status} ({', '.join(extra)})"
            col = "38761D" if r.get("status") == "ok" else "B45F06"
            _row(t, [tool, r.get("version") or "-", r.get("purpose", ""), status], colors=[None, None, None, col])
        _para(doc, "", after=4)

    # cost and speed (B6): engine phases only; tokens are estimates (chars / 4)
    costs = meta.get("phase_costs") or []
    if costs:
        _heading(doc, f"{n}.4 Cost and speed", 2)
        _para(doc, "Engine phases only. 'Engine I/O (chars/4)' counts the characters the tool itself "
                   "read, divided by 4 - it is not LLM billing. AI token use isn't measured by the "
                   "engine; check /cost in Claude Code after a run.",
              9.5, italic=True, after=4)
        t = _table(doc, [2600, 1700, 2100, 2960])
        _row(t, ["Phase", "Time (s)", "Files read", "Engine I/O (chars/4)"], header=True)
        tot_s = tot_f = tot_t = 0
        for c in costs:
            _row(t, [str(c.get("phase", "")), str(c.get("seconds", "")),
                     str(c.get("files_read", "")), f"~{c.get('est_tokens', '')}"])
            tot_s += c.get("seconds", 0) or 0
            tot_f += c.get("files_read", 0) or 0
            tot_t += c.get("est_tokens", 0) or 0
        _row(t, ["Total (engine)", f"{round(tot_s, 2)}", str(tot_f), f"~{tot_t}"], bold=True)
        _para(doc, "", after=4)

    # 3. detailed findings
    H("Detailed Findings")
    if is_dpdp:
        _para(doc, "Each gap below passed the evidence gate: the personal data involved, the obligation it breaks, a source trace with file and line, what is missing, and the concrete result. Personal data values are never shown; only fields, files and lines.", 10.5, italic=True, after=8)
    else:
        _para(doc, "Each finding below passed the evidence gate: a named attacker, the input they control, the rule that should stop them, a source trace with file and line, the missing check, and the concrete result. Live secrets are masked. Exploit payloads are intentionally not included; the engineering team should reproduce each issue in a safe environment as part of remediation.", 10.5, italic=True, after=8)
    if not conf:
        _para(doc, "No gap passed the evidence gate in the checked scope." if is_dpdp else "No vulnerability passed the evidence gate in the checked scope. See the coverage section for what was and was not checked.", after=8)
    for f in conf:
        c, _fill = SEV_STYLE.get(f["severity"], (GREY, None))
        p = _para(doc, "", after=4, before=10)
        p.paragraph_format.keep_with_next = True
        _rpr(p.add_run(f"{f['id']}  {f['title']}  "), 12, True, False, BLUE)
        _rpr(p.add_run(f"[{f['severity'].upper()}]"), 12, True, False, c)
        pl = f.get("plain") or {}
        rec = f.get("recommendation") or {}
        cv = f.get("cvss") or {}
        rec_text = rec.get("summary", "")
        if rec.get("files_to_change"):
            rec_text += "\nFiles to change: " + ", ".join(rec["files_to_change"])
        rows = [
            ("Location", _loc(f)),
            ("In plain words", f"What this is: {pl.get('what_this_is', '')}\nProblem: {pl.get('problem', '')}\nIf we skip it: {pl.get('if_we_skip', '')}"),
            ("Description", f.get("description", "")),
            ("Business Impact", f.get("business_impact", "")),
            ("Root Cause", f.get("root_cause", "")),
            ("Evidence (source trace)", _trace_text(f), {"font": "Consolas", "size": 8.5}),
            ("Recommendation", rec_text),
        ]
        if rec.get("code_example"):
            rows.append(("Fix example", rec["code_example"], {"font": "Consolas", "size": 8.5}))
        rows += [
            ("Production risk of the fix", rec.get("production_risk", "")),
            ("Regression test", f.get("regression_test", "")),
            ("Classification", "  |  ".join(x for x in [
                ", ".join(f.get("cwe") or []), ", ".join(f.get("owasp") or []),
                f"CVSS {cv.get('score')} ({cv.get('vector')})" if cv else "", f"Confidence: {f.get('confidence', '-')}",
                _votes(f)] if x)),
        ]
        if f.get("severity_rationale"):
            rows.append(("Severity rationale", f"{f['severity_rationale']} (CVSS 4.0 band: {_band(cv.get('score'))})"))
        if is_dpdp and f.get("dpdp"):
            d = f["dpdp"]
            rows.insert(1, ("DPDP obligation", "; ".join(x for x in [d.get("obligation", ""), ", ".join(d.get("act_sections") or []), ", ".join(d.get("rules") or []), ("Data: " + ", ".join(d.get("data_types") or [])) if d.get("data_types") else ""] if x)))
        if f.get("regulation"):
            rows.append(("Regulatory exposure", "; ".join(f["regulation"])))
        _kv_table(doc, rows)

    # 4. needs verification
    H("Findings Requiring Manual Verification")
    _para(doc, "The items below are specific, source-grounded concerns that depend on one fact the repository does not show (for example a cloud, hosting, identity-provider or production setting). They are listed separately and must not be treated as confirmed vulnerabilities until verified.", 10.5, after=8)
    if not nv:
        _para(doc, "None.", after=8)
    for f in nv:
        p = _para(doc, "", after=4, before=10)
        p.paragraph_format.keep_with_next = True
        _rpr(p.add_run(f"{f['id']}  {f['title']}  "), 12, True, False, BLUE)
        _rpr(p.add_run("[UNVERIFIED]"), 12, True, False, GREY)
        _kv_table(doc, [
            ("Location", _loc(f)),
            ("Description", f.get("description", "")),
            ("Missing fact", f.get("missing_fact", "")),
            ("Why it needs verification", f.get("why_verification", "")),
            ("Potential impact if confirmed", f.get("potential_impact", "") or f.get("result", "")),
            ("Safe check to settle it", f.get("safe_check", "")),
            ("Evidence (source trace)", _trace_text(f), {"font": "Consolas", "size": 8.5}),
        ])

    # 5. dependency and secret hygiene
    deps = leads.get("dependencies") or []
    secret_leads = [x for x in leads.get("leads", []) if x.get("kind") == "secret" and x.get("triage") != "noise" and not x.get("likely_test_or_example") and not x.get("likely_vendor")]
    if not is_dpdp:
        H("Dependency & Secret Hygiene")
        _para(doc, "Known-vulnerable packages found in manifests and lockfiles. Unless a finding above shows the vulnerable code is reachable, these are listed as present but not shown reachable. Upgrading is still recommended.", after=6)
        if deps:
            t = _table(doc, [2100, 1200, 2460, 1500, 1000, 1100])
            _row(t, ["Package", "Version", "Advisory", "Fixed in", "Severity", "Reachable"], header=True)
            for d in deps[:60]:
                c, fill = SEV_STYLE.get(d.get("severity"), (GREY, None))
                reach = {"not_assessed": "Not shown", "reachable": "Yes", "not_reachable": "No"}.get(d.get("reachability"), "Not shown")
                _row(t, [str(d.get("package")), str(d.get("version")), ", ".join(d.get("ids", [])[:3]), d.get("fixed_version") or "-",
                         d.get("severity", "-"), reach], fills=[None, None, None, None, fill, None], colors=[None, None, None, None, c, None], bold_cols=(4,))
            if len(deps) > 60:
                _para(doc, f"{len(deps) - 60} more advisories are listed in leads.json.", 9, italic=True)
        else:
            ran = [k for k, s in scans.items() if k in ("trivy", "osv-scanner") and s.get("status") == "ok"]
            osv_skipped = scans.get("osv-scanner", {}).get("status") == "skipped"
            notes = [f"{k}: {s['note']}" for k, s in scans.items() if k in ("trivy", "osv-scanner") and s.get("note") and s.get("status") != "skipped"]
            parts = []
            if ran:
                parts.append(f"No known-vulnerable dependencies were reported by {', '.join(ran)}.")
            if osv_skipped:
                parts.append("OSV-Scanner was skipped because no lockfile was found. Commit a lockfile "
                             "(package-lock.json, yarn.lock, pnpm-lock.yaml, poetry.lock, requirements.txt, go.sum, Gemfile.lock, etc.) "
                             "and re-run for full dependency-vulnerability coverage.")
            if notes:
                parts.append("Notes: " + "; ".join(notes))
            if not parts:
                parts.append("Dependency scanning did not run (see Tools), so dependency risk was not checked.")
            _para(doc, " ".join(parts), after=6)
        _heading(doc, "Secrets to rotate", 2)
        if secret_leads:
            t = _table(doc, [3600, 900, 3060, 1800])
            _row(t, ["Location", "Line", "Type (value masked)", "Where"], header=True)
            for s in secret_leads[:40]:
                _row(t, [s["file"], str(s["line"]), s["message"], "Git history only" if s.get("history_only") else "Current files"])
            _para(doc, "Rotate every credential listed, even if it was removed later: Git history keeps old values.", 9.5, italic=True)
        else:
            _para(doc, "No unresolved secret leads outside tests and examples.", after=6)

    # 6. coverage
    H("Coverage & What Was Not Checked")
    lsum: dict[str, int] = {}
    for u in ledger:
        lsum[u.get("status", "?")] = lsum.get(u.get("status", "?"), 0) + 1
    lc = leads.get("counts") or {}
    tri = {"trace": 0, "noise": 0, "dependency": 0}
    for x in leads.get("leads", []):
        if x.get("triage") in tri:
            tri[x["triage"]] += 1
    _bullets(doc, [
        f"Coverage units: {len(ledger)} total ({', '.join(f'{k}: {v}' for k, v in sorted(lsum.items())) or 'none'})",
        f"Scanner leads raised: {lc.get('leads', 0)} (traced by hunters: {tri['trace']}, dismissed with a reason: {tri['noise']}, dependency items: {tri['dependency']})",
        f"Candidates verified: {len(conf) + len(nv) + len(rej)} ({len(conf)} confirmed, {len(nv)} need verification, {len(rej)} rejected as false positives)",
    ])
    _heading(doc, "Not checked", 2)
    not_checked = list(meta.get("not_checked") or [])
    for tool, r in scans.items():
        if r.get("status") != "ok":
            not_checked.append(f"{tool} ({r.get('purpose', '')}) did not run: {r.get('status')}")
    for u in ledger:
        if u.get("status") in ("deferred", "out_of_scope", "blocked"):
            not_checked.append(f"{u.get('surface')} / {u.get('attack_class')}: {u.get('status')} ({u.get('notes', '')})")
    not_checked.append("Runtime behaviour, live infrastructure, cloud console and hosting dashboard settings (source-only audit; see items requiring verification)")
    _bullets(doc, not_checked[:40])
    if is_dpdp:
        _heading(doc, "Not verifiable from source code", 2)
        _para(doc, "These obligations depend on documents, contracts or operations outside the code. They were neither marked as gaps nor as met:", after=4)
        _bullets(doc, [
            "Published privacy notice and its language versions outside the application",
            "Contracts with Data Processors, including Rule 6 security clauses",
            "Appointment and contact of a DPO or grievance officer (where not shown in the app)",
            "Breach intimation procedure to the Data Protection Board and Data Principals (Rule 7)",
            "Actual production retention, backups and log retention where not defined in code or IaC",
            "Significant Data Fiduciary duties: DPIA, independent audit, algorithmic due diligence (if notified)",
            "What third-party recipients do with the data they receive",
        ])

    # 7. standards mapping
    if is_dpdp:
        H("DPDP Obligation Mapping")
        _dpdp_table(doc, conf, nv)
    else:
        H("OWASP Mapping")
        _owasp_table(doc, "OWASP Top 10:2025", OWASP_WEB, conf, nv, always=True)
        if any(o.startswith("API") for f in conf + nv for o in f.get("owasp") or []):
            _owasp_table(doc, "OWASP API Security Top 10:2023", OWASP_API, conf, nv)
        if any(o.startswith("LLM") for f in conf + nv for o in f.get("owasp") or []):
            _owasp_table(doc, "OWASP Top 10 for LLM Applications 2025", OWASP_LLM, conf, nv)

    # 8. priority order
    H("Priority Remediation Order")
    _para(doc, "Order reflects severity and how findings enable each other. Items requiring verification are placed where they would rank if confirmed.", after=6)
    order = [f for f in conf if f["severity"] in ("Critical", "High")] + nv + [f for f in conf if f["severity"] not in ("Critical", "High")]
    t = _table(doc, [600, 900, 1300, 6560])
    _row(t, ["#", "Finding", "Severity", "Action"], header=True)
    for i, f in enumerate(order, 1):
        sev = f.get("severity", "Unverified") if f["verdict"] == "confirmed" else "Unverified"
        c, fill = SEV_STYLE.get(sev, (GREY, None))
        action = _first_sentence((f.get("recommendation") or {}).get("summary") or f.get("safe_check", ""))
        _row(t, [str(i), f["id"], sev.upper(), action], fills=[None, None, fill, None], colors=[None, None, c, None],
             aligns=[WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.CENTER, None], bold_cols=(2,))
    if not order:
        _row(t, ["-", "-", "-", "No actions required from this audit."])
    _para(doc, "", after=4)

    # 9. compliance
    regs: dict[str, list[str]] = {}
    for f in conf + nv:
        for r in f.get("regulation") or []:
            regs.setdefault(r, []).append(f["id"])
    if regs:
        H("Compliance & Regulatory Exposure")
        t = _table(doc, [5200, 2400, 1760])
        _row(t, ["Regulation and requirement", "Related findings", "Status"], header=True)
        for r, ids in regs.items():
            _row(t, [r, ", ".join(ids), "At risk"], colors=[None, None, "CC0000"])
        _para(doc, "This section describes what the confirmed findings put at risk. It is not legal advice.", 9.5, italic=True)

    # 10. disclosure
    H("Disclosure")
    _para(doc, f"This report was prepared from an authorized, read-only review of the application's source code. No target code was executed and no live system, API, database or cloud account was contacted. No exploit code, live credential values or step-by-step exploitation sequences are included, in line with responsible disclosure practice. This document is confidential and intended solely for the teams responsible for remediation.", after=8)
    if is_dpdp:
        _para(doc, "This is an engineering review of source code against the DPDP Act 2023 and DPDP Rules 2025. It is not legal advice and does not certify compliance. Confirm interpretations with qualified legal counsel.", after=8)
    _para(doc, "Findings reflect the source at the commit stated in the scope section. A clean result means no issue passed the evidence gate in the checked scope; it is not a guarantee that no vulnerability exists.", after=8)
    _para(doc, f"Generated with AI-Security-Audit-Skills v{__version__} ({__url__}), created by Vijaya Kumar L (Rise With VJ).", 9, italic=True, color="7F7F7F", after=10)
    _para(doc, f"Report Date: {date}", 10.5, align=WD_ALIGN_PARAGRAPH.CENTER, before=12)

    core = doc.core_properties
    core.title = f"{title} - {app}"
    core.author = prepared
    core.subject = "Security audit" if not is_dpdp else "DPDP compliance audit"
    core.keywords = "AI-Security-Audit-Skills, risewithvj"
    core.comments = f"Generated with AI-Security-Audit-Skills v{__version__} by Rise With VJ ({__url__})"
    core.last_modified_by = prepared
    core.created = core.modified = _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)
    core.revision = 1
    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out_path))
    return out_path


def _band(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "-"
    return "Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 4 else "Low" if s > 0 else "Info"


def _votes(f):
    v = f.get("votes") or {}
    if not v:
        return ""
    s = f"Votes: {v.get('confirmed', 0)} confirmed / {v.get('needs_validation', 0)} verify / {v.get('rejected', 0)} reject"
    return s + (f" (dissent: {v['dissent']})" if v.get("dissent") else "")


def _owasp_table(doc, title, cats, conf, nv, always=False):
    _heading(doc, title, 2)
    t = _table(doc, [3600, 1900, 1960, 1900])
    _row(t, ["Category", "Confirmed", "Needs verification", "Status"], header=True)
    for cid, name in cats:
        c_ids = [f["id"] for f in conf if any(o.startswith(cid) for o in f.get("owasp") or [])]
        v_ids = [f["id"] for f in nv if any(o.startswith(cid) for o in f.get("owasp") or [])]
        if not always and not c_ids and not v_ids:
            continue
        status, col = ("FAILED", "CC0000") if c_ids else (("UNVERIFIED", GREY) if v_ids else ("No finding in checked scope", "38761D"))
        _row(t, [f"{cid} {name}", ", ".join(c_ids) or "-", ", ".join(v_ids) or "-", status], colors=[None, None, None, col], bold_cols=(3,) if c_ids else ())
    _para(doc, "", after=4)


def _dpdp_table(doc, conf, nv):
    t = _table(doc, [3000, 2300, 1400, 1360, 1300])
    _row(t, ["Obligation", "Act / Rules reference", "Confirmed", "Verify", "Status"], header=True)
    obls: dict[str, dict] = {}
    for f in conf + nv:
        d = f.get("dpdp") or {}
        o = d.get("obligation") or "Other"
        e = obls.setdefault(o, {"refs": set(), "c": [], "v": []})
        e["refs"].update(d.get("act_sections") or [])
        e["refs"].update(d.get("rules") or [])
        (e["c"] if f["verdict"] == "confirmed" else e["v"]).append(f["id"])
    for o, e in sorted(obls.items()):
        status, col = ("GAP", "CC0000") if e["c"] else ("UNVERIFIED", GREY)
        _row(t, [o, ", ".join(sorted(e["refs"])) or "-", ", ".join(e["c"]) or "-", ", ".join(e["v"]) or "-", status], colors=[None, None, None, None, col])
    if not obls:
        _row(t, ["No gaps passed the evidence gate", "-", "-", "-", "-"])
    _para(doc, "", after=4)


def _auto_summary(app, conf, nv, overall, is_dpdp):
    what = ("a review of how the source code collects, stores, uses, shares, retains and erases personal data, "
            "against the DPDP Act 2023 and the DPDP Rules 2025") if is_dpdp else "a read-only, source-code security audit"
    noun = ("gap", "gaps") if is_dpdp else ("vulnerability", "vulnerabilities")
    s = f"This report presents the results of {what} of {app}. "
    if conf:
        top = conf[0]
        s += (f"The assessment confirmed {len(conf)} {noun[0] if len(conf) == 1 else noun[1]}, with an overall risk rating of "
              f"{overall.upper()}. The most serious is {top['id']}: {top['title']}.")
    else:
        s += "No finding passed the evidence gate in the checked scope."
    if nv:
        s += (f" {len(nv)} further item{'s' if len(nv) != 1 else ''} depend{'' if len(nv) != 1 else 's'} on a setting "
              f"the repository does not show and require{'' if len(nv) != 1 else 's'} manual verification.")
    s += ("\n\nEvery confirmed finding was traced from an entry point to the affected code with file and line evidence, "
          "checked by independent verifiers, and machine-validated against the source before inclusion. Recommendations "
          "describe the smallest safe fix; no code was changed during the audit.")
    return s


def _libreoffice_exe() -> str | None:
    """Return a real LibreOffice binary, or None. Only paths that exist count,
    so a missing LibreOffice is reported accurately rather than attempted."""
    for name in ("soffice", "libreoffice"):
        found = which(name)
        if found:
            return found
    extra = []
    if IS_WINDOWS:
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
            extra.append(Path(base) / "LibreOffice" / "program" / "soffice.exe")
    else:
        extra += [Path("/Applications/LibreOffice.app/Contents/MacOS/soffice"), Path("/usr/bin/soffice"), Path("/usr/local/bin/soffice")]
    for p in extra:
        if p.exists():
            return str(p)
    return None


def _word_com_pdf(docx_path: Path, pdf: Path) -> bool:
    """Windows fallback: drive Microsoft Word through PowerShell COM to export a
    PDF (wdExportFormatPDF = 17). Quit() is wrapped in finally so Word always
    closes; a benign RPC error on Quit after a successful export is ignored."""
    if not IS_WINDOWS:
        return False
    dp = str(docx_path).replace("'", "''")
    pp = str(pdf).replace("'", "''")
    ps = (
        "$ErrorActionPreference='Stop'; "
        "$w = New-Object -ComObject Word.Application; $w.Visible=$false; "
        f"try {{ $d = $w.Documents.Open('{dp}', $false, $true); "
        f"$d.ExportAsFixedFormat('{pp}', 17); $d.Close($false) }} "
        "finally { try { $w.Quit() } catch {} }"
    )
    for shell in ("pwsh", "powershell"):
        exe = which(shell)
        if not exe:
            continue
        try:
            subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", ps],
                           capture_output=True, timeout=180, check=False)
            if pdf.exists():
                return True
        except (OSError, subprocess.SubprocessError):
            continue
    return False


def to_pdf(docx_path: Path) -> Path | None:
    out_dir = docx_path.parent
    pdf = docx_path.with_suffix(".pdf")
    exe = _libreoffice_exe()
    if exe:
        try:
            subprocess.run([exe, "--headless", "--convert-to", "pdf", "--outdir", str(out_dir), str(docx_path)],
                           capture_output=True, timeout=180, check=False)
            if pdf.exists():
                return pdf
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        from docx2pdf import convert  # type: ignore  # uses Microsoft Word on Windows/macOS
        convert(str(docx_path), str(pdf))
        if pdf.exists():
            return pdf
    except Exception:  # noqa: BLE001
        pass
    # Last resort on Windows: Microsoft Word via PowerShell COM.
    if _word_com_pdf(docx_path, pdf):
        return pdf
    return None


def write_summary(run: Path, out: Path) -> Path:
    doc_data = read_json(run / "findings.json", {"findings": []})
    meta = read_json(run / "run-metadata.json", {})
    fs = doc_data.get("findings", [])
    conf = sorted([f for f in fs if f.get("verdict") == "confirmed"], key=lambda f: (SEV_ORDER.get(f.get("severity"), 9), f["id"]))
    nv = [f for f in fs if f.get("verdict") == "needs_validation"]
    overall = doc_data.get("overall_risk") or _overall(fs)
    lines = [f"Overall risk: {overall}", "Confirmed: " + (", ".join(f"{s} {sum(1 for f in conf if f['severity'] == s)}" for s in SEV_ORDER if any(f['severity'] == s for f in conf)) or "none"),
             f"Needs verification: {len(nv)}", "", "Top fixes:"]
    for f in conf[:3]:
        lines.append(f"- {f['id']} [{f['severity']}] {f['title']}: {_first_sentence((f.get('recommendation') or {}).get('summary', ''))}")
    nc = [f"{k} not run ({v.get('status')})" for k, v in (meta.get("scanners") or {}).items() if v.get("status") != "ok"]
    lines += ["", "Not checked: " + ("; ".join((meta.get("not_checked") or []) + nc) or "see report")]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out
