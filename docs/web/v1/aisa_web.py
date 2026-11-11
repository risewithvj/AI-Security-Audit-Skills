# AI-Security-Audit-Skills | Vijaya Kumar L (Rise With VJ) | github.com/risewithvj | MIT
"""Self-contained, standard-library-only security-audit engine.

An AI (ChatGPT / Claude.ai code mode) runs this on an uploaded project zip or a
directory. It never makes network calls and never executes the target code: the
uploaded code is DATA. It mirrors the bundled Semgrep rules (aisa-core.yaml) and
the DPDP PII inventory, writes a self-contained HTML report (plus JSON, and a PDF
only if reportlab/python-docx happen to be importable).

Usage:
    python aisa_web.py <project.zip | project_dir> [--out <dir>]
"""

from __future__ import annotations

import ast
import html
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

# --- safe-unzip limits -------------------------------------------------------
MAX_TOTAL_UNCOMPRESSED = 300 * 1024 * 1024   # 300 MB across the whole archive
MAX_FILE_UNCOMPRESSED = 50 * 1024 * 1024     # 50 MB per entry
MAX_ENTRIES = 20000
MAX_READ_BYTES = 2 * 1024 * 1024             # only scan the first 2 MB of a file

IGNORE_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".next", "out",
               "__pycache__", ".venv", "venv", "env", ".cache", "coverage",
               "bower_components", ".idea", ".vscode", "target", "bin", "obj"}

CODE_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".php", ".rb",
            ".java", ".go", ".cs", ".vue", ".svelte", ".astro", ".sql", ".prisma",
            ".graphql", ".gql", ".html"}

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ---------------------------------------------------------------------------
# 1. SAFE UNZIP
# ---------------------------------------------------------------------------
def safe_unzip(zip_path: Path, dest: Path) -> None:
    """Extract a zip rejecting zip-slip, symlinks, oversize and bomb archives."""
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    total = 0
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ValueError(f"archive has too many entries ({len(infos)} > {MAX_ENTRIES})")
        for info in infos:
            name = info.filename
            if info.is_dir():
                continue
            # skip symlinks (unix mode high bits 0xA000 == S_IFLNK)
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue
            if info.file_size > MAX_FILE_UNCOMPRESSED:
                continue
            total += info.file_size
            if total > MAX_TOTAL_UNCOMPRESSED:
                raise ValueError("archive exceeds total uncompressed size cap")
            target = (dest / name).resolve()
            # zip-slip guard: resolved path must stay inside dest
            if os.path.commonpath([str(dest), str(target)]) != str(dest):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                out.write(src.read())


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def walk_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fn in filenames:
            yield Path(dirpath) / fn


def read_text(p: Path) -> str:
    try:
        with open(p, "rb") as fh:
            data = fh.read(MAX_READ_BYTES)
        return data.decode("utf-8", "replace")
    except OSError:
        return ""


def rel(root: Path, p: Path) -> str:
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        return p.as_posix()


def mask_secret(s: str) -> str:
    """Show first 4 chars + length only, so real values never leak."""
    s = s.strip()
    if len(s) <= 4:
        return "*" * len(s) + f" (len {len(s)})"
    return s[:4] + "*" * min(len(s) - 4, 8) + f" (len {len(s)})"


def snippet(line: str, limit: int = 200) -> str:
    return line.strip()[:limit]


# ---------------------------------------------------------------------------
# 2. STACK DETECT
# ---------------------------------------------------------------------------
EXT_LANG = {
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".py": "Python", ".php": "PHP",
    ".rb": "Ruby", ".java": "Java", ".go": "Go", ".cs": "C#", ".vue": "Vue",
    ".svelte": "Svelte", ".astro": "Astro", ".sql": "SQL",
}
NODE_DEPS = {
    "next": "Next.js", "react": "React", "vue": "Vue", "express": "Express",
    "@nestjs/core": "NestJS", "fastify": "Fastify", "vite": "Vite",
    "@supabase/supabase-js": "Supabase", "firebase": "Firebase",
    "firebase-admin": "Firebase Admin", "@prisma/client": "Prisma",
    "pg": "node-postgres", "mysql2": "mysql2", "mongoose": "Mongoose",
    "stripe": "Stripe", "razorpay": "Razorpay", "jsonwebtoken": "jsonwebtoken",
    "next-auth": "NextAuth", "openai": "OpenAI SDK", "@anthropic-ai/sdk": "Anthropic SDK",
}
PY_DEPS = {
    "django": "Django", "flask": "Flask", "fastapi": "FastAPI",
    "sqlalchemy": "SQLAlchemy", "psycopg2": "psycopg2", "supabase": "Supabase",
    "stripe": "Stripe", "pyjwt": "PyJWT", "requests": "requests", "httpx": "httpx",
}
FILE_MARKERS = {
    "Dockerfile": "Docker", "docker-compose.yml": "Docker Compose",
    "docker-compose.yaml": "Docker Compose", "compose.yaml": "Docker Compose",
    "vercel.json": "Vercel", "netlify.toml": "Netlify", "wp-config.php": "WordPress",
    "manage.py": "Django", "artisan": "Laravel", "firebase.json": "Firebase",
    "firestore.rules": "Firestore Rules", "next.config.js": "Next.js",
    "vite.config.js": "Vite", "vite.config.ts": "Vite",
}


def detect_stack(root: Path) -> dict:
    langs: dict[str, int] = {}
    frameworks: set[str] = set()
    manifests: list[str] = []
    for p in walk_files(root):
        name = p.name
        lang = EXT_LANG.get(p.suffix.lower())
        if lang:
            langs[lang] = langs.get(lang, 0) + 1
        if name in FILE_MARKERS:
            frameworks.add(FILE_MARKERS[name])
        if p.suffix == ".tf":
            frameworks.add("Terraform")
        if name == "package.json":
            manifests.append(rel(root, p))
            try:
                data = json.loads(read_text(p))
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for d in deps:
                    if d.lower() in NODE_DEPS:
                        frameworks.add(NODE_DEPS[d.lower()])
            except ValueError:
                pass
        elif name in ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py"):
            manifests.append(rel(root, p))
            txt = read_text(p).lower()
            for d, label in PY_DEPS.items():
                if re.search(rf"(^|[\s\"'\[,]){re.escape(d)}([\s=<>~!\[\"',;]|$)", txt, re.M):
                    frameworks.add(label)
        elif name == "composer.json":
            manifests.append(rel(root, p))
            if "laravel/" in read_text(p):
                frameworks.add("Laravel")
            frameworks.add("PHP/Composer")
    return {
        "languages": dict(sorted(langs.items(), key=lambda kv: -kv[1])),
        "frameworks": sorted(frameworks),
        "manifests": sorted(manifests),
    }


# ---------------------------------------------------------------------------
# 3. BUNDLED REGEX / AST RULES  (mirror aisa-core.yaml)
# ---------------------------------------------------------------------------
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"}
PY_EXT = {".py"}

# --- regex rules for JS/TS/PHP ---------------------------------------------
RX_JWT_FALLBACK = re.compile(
    r"""process\.env\.([A-Za-z0-9_]*(?:JWT|SECRET|SESSION|TOKEN|SIGNING|HMAC|AUTH)[A-Za-z0-9_]*)"""
    r"""\s*(?:\|\||\?\?)\s*(['"])(.+?)\2""", re.I)
RX_SQL_CONCAT = re.compile(
    r"""\.(?:query|raw|execute)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|['"][^'"]*['"]\s*\+\s*\w)""", re.I)
RX_SQL_UNSAFE = re.compile(r"\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(", re.I)
RX_CLIENT_SECRET = re.compile(
    r"""(?:process\.env|import\.meta\.env)\.((?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|"""
    r"""NUXT_PUBLIC_|PUBLIC_|GATSBY_)[A-Za-z0-9_]*(?:SERVICE_?ROLE|SECRET|PRIVATE|ADMIN|"""
    r"""DATABASE_URL|DB_URL|PASSWORD|OPENAI|ANTHROPIC|GEMINI|STRIPE_SECRET|"""
    r"""RAZORPAY_KEY_SECRET|SK_)[A-Za-z0-9_]*)""", re.I)
RX_PAYMENT_CLIENT = re.compile(
    r"""(?:unit_amount|amount|price)\s*:\s*(?:req|request)\.(?:body|query|params)\.""", re.I)
RX_IDOR_INLINE = re.compile(
    r"""(?:findById|findByPk)\s*\(\s*(?:req|request)\.params\.([A-Za-z0-9_]*"""
    r"""(?:id|employee|user|account|owner|org|tenant|document|doc|file)[A-Za-z0-9_]*)""", re.I)
RX_LOG_CALL = re.compile(r"\b(?:console\.\w+|logger\.\w+|log\.\w+)\s*\(")
RX_PII_TOKEN = re.compile(
    r"(?i)(aadh?aa?r|\bpan\b|bank_?acc|account_?no|ifsc|salary|net_?pay|\botp\b|"
    r"password|passwd|token|secret)")
RX_ID_NAME = re.compile(
    r"(?i)(id|employee|user|account|owner|org|tenant|document|doc|file)")

RULE_META = {
    "jwt-fallback-secret": ("JWT/session secret falls back to a hardcoded value", "CRITICAL",
        "Anyone who knows the fallback can forge valid tokens.",
        "Read the secret from the environment and fail at startup if it is missing; never ship a literal fallback."),
    "sql-string-concat": ("SQL built by string concatenation / interpolation", "CRITICAL",
        "Request data concatenated into SQL allows SQL injection.",
        "Use parameterized / bound queries ($1, ?) instead of building the SQL string."),
    "client-exposed-server-secret": ("Server secret read through a client-exposed env prefix", "CRITICAL",
        "NEXT_PUBLIC_/VITE_/REACT_APP_ vars are inlined into the browser bundle, leaking the secret to every user.",
        "Drop the public prefix and read the secret only on the server."),
    "payment-amount-from-client": ("Payment amount comes from the request body", "HIGH",
        "A client can set any price/amount and pay less than intended.",
        "Look the price up on the server from a trusted source; never trust req.body for money."),
    "idor-param-to-query": ("Route parameter reaches a DB call without an ownership check", "HIGH",
        "A user can swap the id in the URL to read another tenant's / user's data (IDOR).",
        "Bind the query to req.user (owner/tenant id) and verify ownership before returning data."),
    "pii-in-logs": ("Personal/sensitive data written to a log call", "MEDIUM",
        "Aadhaar/PAN/bank/salary/OTP/token in logs is widely readable and long retained.",
        "Remove or redact personal data before logging; log identifiers, not sensitive values."),
}


def add_finding(findings, rid, file, line, code, secret_raw=None):
    title, sev, why, rec = RULE_META[rid]
    code = snippet(code)
    if secret_raw is not None:
        code = code + "   [secret: " + mask_secret(secret_raw) + "]"
    findings.append({
        "rule": rid, "title": title, "severity": sev,
        "file": file, "line": line, "code": code,
        "why": why, "recommendation": rec,
    })


def scan_js_php(findings, relpath, text):
    lines = text.splitlines()
    # track param destructuring for IDOR:  const { employeeId } = req.params
    declared_params: dict[str, int] = {}
    for i, line in enumerate(lines, 1):
        m = re.search(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:req|request)\.params", line)
        if m:
            for nm in re.split(r"[,\s]+", m.group(1)):
                nm = nm.strip()
                if nm and RX_ID_NAME.search(nm):
                    declared_params[nm] = i

    for i, line in enumerate(lines, 1):
        if line.lstrip().startswith("//") or line.lstrip().startswith("*"):
            continue
        m = RX_JWT_FALLBACK.search(line)
        if m:
            add_finding(findings, "jwt-fallback-secret", relpath, i, line, secret_raw=m.group(3))
        if RX_SQL_CONCAT.search(line) or RX_SQL_UNSAFE.search(line):
            add_finding(findings, "sql-string-concat", relpath, i, line)
        m = RX_CLIENT_SECRET.search(line)
        if m:
            add_finding(findings, "client-exposed-server-secret", relpath, i, line)
        if RX_PAYMENT_CLIENT.search(line):
            add_finding(findings, "payment-amount-from-client", relpath, i, line)
        # IDOR: req.params.<id> inside a db call, or a declared param used in a query array
        if RX_IDOR_INLINE.search(line):
            add_finding(findings, "idor-param-to-query", relpath, i, line)
        elif re.search(r"\.(?:query|execute|raw|findOne|find)\s*\(", line) and "[" in line:
            for nm in declared_params:
                if re.search(r"\b" + re.escape(nm) + r"\b", line):
                    add_finding(findings, "idor-param-to-query", relpath, i, line)
                    break
        # PII in logs
        if RX_LOG_CALL.search(line) and RX_PII_TOKEN.search(line):
            add_finding(findings, "pii-in-logs", relpath, i, line)


# --- AST rules for Python ---------------------------------------------------
def _str_value(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class PyRules(ast.NodeVisitor):
    def __init__(self, findings, relpath, lines):
        self.findings = findings
        self.rel = relpath
        self.lines = lines

    def _line(self, node):
        idx = getattr(node, "lineno", 1) - 1
        return self.lines[idx] if 0 <= idx < len(self.lines) else ""

    def visit_Call(self, node):
        func = node.func
        # os.getenv("X_SECRET", "literal") / os.environ.get(...) -> jwt-fallback-secret
        if isinstance(func, ast.Attribute) and func.attr in ("getenv", "get"):
            if len(node.args) >= 2:
                env = _str_value(node.args[0])
                default = _str_value(node.args[1])
                if env and default and re.search(r"(?i)secret|jwt|token|key|password|session", env):
                    add_finding(self.findings, "jwt-fallback-secret", self.rel,
                                node.lineno, self._line(node), secret_raw=default)
        # cursor.execute(f"...") / "..." % / .format / "..." + x  -> sql-string-concat
        if isinstance(func, ast.Attribute) and func.attr in ("execute", "executemany", "raw"):
            if node.args:
                a = node.args[0]
                risky = (isinstance(a, ast.JoinedStr) or
                         (isinstance(a, ast.BinOp) and isinstance(a.op, (ast.Mod, ast.Add))) or
                         (isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute)
                          and a.func.attr == "format"))
                if risky:
                    add_finding(self.findings, "sql-string-concat", self.rel,
                                node.lineno, self._line(node))
        # logging calls with PII keyword in a string arg
        logname = None
        if isinstance(func, ast.Attribute) and func.attr in (
                "debug", "info", "warning", "warn", "error", "log", "exception"):
            logname = func.attr
        elif isinstance(func, ast.Name) and func.id == "print":
            logname = "print"
        if logname:
            line = self._line(node)
            if RX_PII_TOKEN.search(line):
                add_finding(self.findings, "pii-in-logs", self.rel, node.lineno, line)
        self.generic_visit(node)


def scan_python(findings, relpath, text):
    lines = text.splitlines()
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return
    PyRules(findings, relpath, lines).visit(tree)


# ---------------------------------------------------------------------------
# 4. PII INVENTORY  (mirror pii.py, values never printed)
# ---------------------------------------------------------------------------
FIELD_PATTERNS = {
    "Aadhaar number": r"aadh?aa?r|adhaar|uidai|uid_?(no|number)",
    "PAN": r"\bpan(_?(no|number|card|num))?\b|pancard|pan_card",
    "Bank account / IFSC / UPI": r"bank_?(acc(ount)?|ac)(_?(no|number))?|account_?(no|number)|ifsc|upi_?id|vpa\b",
    "Salary / compensation": r"\bsalary|\bctc\b|gross_?pay|net_?pay|basic_?pay|payslip|pay_?slip|form_?16|tds\b",
    "PF / ESIC / UAN": r"\buan\b|epf|pf_?(no|number|account)|esic|esi_?(no|number)",
    "Health / medical": r"medical|health|diagnos|disease|blood_?group|disabilit|insurance_?claim|prescription",
    "Biometric": r"biometric|fingerprint|face_?(id|template|embedding)|iris",
    "Children / dependants": r"guardian|parent_?(name|consent|email|phone)|dependant|dependent|child(ren)?_?(name|dob|age)|minor",
    "Date of birth / age": r"\bdob\b|date_?of_?birth|birth_?date|birthday|\bage\b",
    "Phone number": r"phone|mobile(_?(no|number))?|msisdn|whatsapp_?(no|number)",
    "Email address": r"\bemail\b|e_?mail_?(id|address)",
    "Physical address": r"\baddress(_?line)?\b|pincode|pin_?code|postal_?code|zip_?code",
    "Credentials": r"password|passwd|pwd\b|otp\b|pin_?hash|secret_?answer",
}
FIELD_RX = {k: re.compile(v, re.I) for k, v in FIELD_PATTERNS.items()}
SENSITIVE = {"Aadhaar number", "PAN", "Bank account / IFSC / UPI", "Salary / compensation",
             "PF / ESIC / UAN", "Health / medical", "Biometric", "Children / dependants",
             "Credentials"}
SCHEMA_FILE = re.compile(r"(model|schema|entity|migration|dto|types?|serializer|form|prisma|graphql|sql|\.proto$)", re.I)
DEF_LINE = re.compile(
    r"(\bcolumn\b|\bColumn\(|models\.\w+Field|Field\(|@Column|@Prop|:\s*(String|string|str|int|number|Date|varchar|text|bigint|Int)\b|"
    r"\bvarchar\b|\btext\b|\bCREATE TABLE\b|\bADD COLUMN\b|t\.(string|text|integer)|\$table->|name=\")", re.I)
LOG_LINE = re.compile(r"(console\.\w+|logger\.\w+|log\.\w+|logging\.\w+|print\(|error_log\(|echo )")
THIRD_PARTY = {
    "Google Analytics / GTM": r"gtag\(|googletagmanager|google-analytics|react-ga",
    "Meta Pixel": r"fbq\(|connect\.facebook\.net",
    "Sentry": r"@sentry/|sentry_sdk|Sentry\.init",
    "Supabase": r"@supabase/supabase-js|supabase\.co|SUPABASE_URL|SUPABASE_SERVICE_ROLE",
    "Firebase": r"firebase/analytics|getAnalytics\(|firebase-admin",
    "OpenAI / Anthropic / Gemini (LLM)": r"api\.openai\.com|new OpenAI\(|anthropic\.messages|new Anthropic\(|GoogleGenerativeAI",
    "SMS / WhatsApp gateways": r"twilio|msg91|exotel|gupshup|textlocal|interakt",
    "Email providers": r"sendgrid|mailgun|ses\.amazonaws|mailchimp|postmark|nodemailer|\bresend\b",
    "Payment gateways": r"stripe|razorpay|payu|cashfree|paytm|phonepe|ccavenue",
}
THIRD_RX = {k: re.compile(v, re.I) for k, v in THIRD_PARTY.items()}


def pii_inventory(root: Path) -> dict:
    fields: dict[str, list] = {}
    logs: list = []
    third: dict[str, list] = {}
    for p in walk_files(root):
        ext = p.suffix.lower()
        if ext not in CODE_EXT and ext not in (".json", ".yaml", ".yml", ".env", ".tf"):
            continue
        r = rel(root, p)
        txt = read_text(p)
        if not txt:
            continue
        schema_like = bool(SCHEMA_FILE.search(r))
        for i, line in enumerate(txt.splitlines(), 1):
            if len(line) > 400:
                continue
            low = line.lower()
            hits = [k for k, rx in FIELD_RX.items() if rx.search(low)]
            if hits:
                if schema_like or DEF_LINE.search(line):
                    for k in hits:
                        lst = fields.setdefault(k, [])
                        if len(lst) < 60:
                            lst.append({"file": r, "line": i})
                if LOG_LINE.search(line) and len(logs) < 200:
                    logs.append({"file": r, "line": i, "data_types": hits})
            for k, rx in THIRD_RX.items():
                if rx.search(line):
                    lst = third.setdefault(k, [])
                    loc = f"{r}:{i}"
                    if len(lst) < 15 and loc not in lst:
                        lst.append(loc)
    return {
        "data_types": {k: {"count": len(v), "references": v, "high_sensitivity": k in SENSITIVE}
                       for k, v in sorted(fields.items())},
        "possible_pii_in_logs": logs,
        "third_party_recipients": third,
        "note": "Heuristic inventory. Values are never shown; every item is a lead for review.",
    }


# ---------------------------------------------------------------------------
# 5. VALIDATE  (false-positive guard: re-read cited file:line)
# ---------------------------------------------------------------------------
def validate(findings, root: Path):
    cache: dict[str, list] = {}
    kept = []
    for f in findings:
        path = root / f["file"]
        if f["file"] not in cache:
            cache[f["file"]] = read_text(path).splitlines()
        lines = cache[f["file"]]
        idx = f["line"] - 1
        if 0 <= idx < len(lines):
            # the snippet (before any appended secret note) must still be on that line
            core = f["code"].split("   [secret:")[0].strip()
            if core and core[:60] in lines[idx].strip():
                kept.append(f)
    return kept


# ---------------------------------------------------------------------------
# 6. OUTPUT
# ---------------------------------------------------------------------------
NOT_CHECKED = [
    "Runtime / DAST behaviour (this is static analysis only)",
    "Business-logic flaws beyond the bundled rules",
    "Authentication flows and session management depth",
    "Dependency CVEs / SCA (no network lookups performed)",
    "Infrastructure, cloud IAM and secrets at rest",
    "Access-control correctness beyond flagged IDOR leads",
]


def write_json(out: Path, report: dict):
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


def _esc(s) -> str:
    return html.escape(str(s))


def write_html(out: Path, report: dict):
    stack = report["stack"]
    findings = sorted(report["findings"], key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["file"]))
    counts = report["summary"]["by_severity"]
    pii = report["pii"]

    sev_color = {"CRITICAL": "#b00020", "HIGH": "#d84315", "MEDIUM": "#ef6c00",
                 "LOW": "#558b2f", "INFO": "#607d8b"}

    rows = ""
    for f in findings:
        c = sev_color.get(f["severity"], "#607d8b")
        rows += f"""<tr>
<td><span class="sev" style="background:{c}">{_esc(f['severity'])}</span></td>
<td><code>{_esc(f['rule'])}</code><br><b>{_esc(f['title'])}</b></td>
<td><code>{_esc(f['file'])}:{_esc(f['line'])}</code><pre>{_esc(f['code'])}</pre></td>
<td>{_esc(f['why'])}<br><i>Fix:</i> {_esc(f['recommendation'])}</td>
</tr>\n"""
    if not rows:
        rows = '<tr><td colspan="4">No findings from the bundled rules.</td></tr>'

    pii_rows = ""
    for k, v in pii["data_types"].items():
        tag = ' <span class="sens">sensitive</span>' if v["high_sensitivity"] else ""
        locs = ", ".join(f"{_esc(r['file'])}:{r['line']}" for r in v["references"][:8])
        pii_rows += f"<tr><td>{_esc(k)}{tag}</td><td>{v['count']}</td><td><code>{locs}</code></td></tr>\n"
    if not pii_rows:
        pii_rows = '<tr><td colspan="3">No PII fields detected.</td></tr>'

    log_rows = ""
    for l in pii["possible_pii_in_logs"][:40]:
        log_rows += f"<li><code>{_esc(l['file'])}:{l['line']}</code> — {_esc(', '.join(l['data_types']))}</li>"
    log_rows = log_rows or "<li>None detected.</li>"

    third_rows = ""
    for k, locs in pii["third_party_recipients"].items():
        third_rows += f"<li><b>{_esc(k)}</b> — <code>{_esc(', '.join(locs[:6]))}</code></li>"
    third_rows = third_rows or "<li>None detected.</li>"

    not_checked = "".join(f"<li>{_esc(x)}</li>" for x in NOT_CHECKED)
    sev_badges = " ".join(
        f'<span class="sev" style="background:{sev_color.get(s,"#607d8b")}">{s}: {counts.get(s,0)}</span>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Security Audit Report</title>
<style>
 body{{font:15px/1.5 -apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#1a1a1a;max-width:1100px;margin:0 auto;padding:24px}}
 h1{{margin:0 0 4px}} h2{{border-bottom:2px solid #eee;padding-bottom:6px;margin-top:34px}}
 .muted{{color:#666;font-size:13px}}
 table{{border-collapse:collapse;width:100%;margin-top:12px}}
 th,td{{border:1px solid #e2e2e2;padding:8px;text-align:left;vertical-align:top}}
 th{{background:#fafafa}}
 code{{background:#f4f4f4;padding:1px 4px;border-radius:3px;font-size:12px}}
 pre{{background:#f7f7f7;padding:6px;border-radius:4px;overflow:auto;font-size:12px;margin:4px 0 0;white-space:pre-wrap}}
 .sev{{color:#fff;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap;display:inline-block}}
 .sens{{background:#b00020;color:#fff;padding:1px 6px;border-radius:8px;font-size:11px}}
 .pill{{background:#eef;border:1px solid #cce;border-radius:12px;padding:2px 10px;font-size:12px;margin:2px;display:inline-block}}
 footer{{margin-top:40px;color:#888;font-size:12px;border-top:1px solid #eee;padding-top:12px}}
</style></head><body>
<h1>AI Security Audit Report</h1>
<div class="muted">Target: <code>{_esc(report['target'])}</code> &middot; Generated {_esc(report['generated'])} &middot;
Files scanned: {report['summary']['files_scanned']}</div>
<p>{sev_badges}</p>

<h2>Stack</h2>
<p><b>Languages:</b> {' '.join(f'<span class="pill">{_esc(k)} ({v})</span>' for k,v in stack['languages'].items()) or '—'}</p>
<p><b>Frameworks / platforms:</b> {' '.join(f'<span class="pill">{_esc(x)}</span>' for x in stack['frameworks']) or '—'}</p>
<p><b>Manifests:</b> {' '.join(f'<code>{_esc(m)}</code>' for m in stack['manifests']) or '—'}</p>

<h2>Findings ({len(findings)})</h2>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Location &amp; code</th><th>Why &amp; fix</th></tr></thead>
<tbody>{rows}</tbody></table>

<h2>PII Inventory</h2>
<p class="muted">Field names and locations only — no personal-data values are ever shown.</p>
<table><thead><tr><th>Data type</th><th>Refs</th><th>Locations</th></tr></thead><tbody>{pii_rows}</tbody></table>
<h3>Possible PII in logs</h3><ul>{log_rows}</ul>
<h3>Third-party recipients</h3><ul>{third_rows}</ul>

<h2>Not checked (out of scope for this static pass)</h2>
<ul>{not_checked}</ul>

<footer>AI-Security-Audit-Skills &middot; Vijaya Kumar L (Rise With VJ) &middot; github.com/risewithvj &middot; MIT.
Static analysis; the target code is treated as data and is never executed. Findings are leads to confirm, not proof of exploitability.</footer>
</body></html>"""
    (out / "report.html").write_text(doc, encoding="utf-8")


def write_pdf(out: Path, report: dict) -> bool:
    """Write report.pdf only if reportlab or python-docx is importable. Never fail."""
    findings = sorted(report["findings"], key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["file"]))
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.pdfgen import canvas as rcanvas
        c = rcanvas.Canvas(str(out / "report.pdf"), pagesize=A4)
        w, h = A4
        y = h - 20 * mm
        c.setFont("Helvetica-Bold", 16)
        c.drawString(20 * mm, y, "AI Security Audit Report")
        y -= 8 * mm
        c.setFont("Helvetica", 9)
        c.drawString(20 * mm, y, f"Target: {report['target']}  Generated: {report['generated']}")
        y -= 10 * mm
        for f in findings:
            if y < 25 * mm:
                c.showPage(); y = h - 20 * mm; c.setFont("Helvetica", 9)
            c.setFont("Helvetica-Bold", 10)
            c.drawString(20 * mm, y, f"[{f['severity']}] {f['rule']}  {f['file']}:{f['line']}")
            y -= 5 * mm
            c.setFont("Helvetica", 8)
            c.drawString(22 * mm, y, (f["title"][:110]))
            y -= 7 * mm
        c.save()
        return True
    except Exception:
        pass
    try:
        import docx  # python-docx
        d = docx.Document()
        d.add_heading("AI Security Audit Report", 0)
        d.add_paragraph(f"Target: {report['target']}  Generated: {report['generated']}")
        for f in findings:
            d.add_heading(f"[{f['severity']}] {f['rule']} — {f['file']}:{f['line']}", level=2)
            d.add_paragraph(f["title"])
            d.add_paragraph(f["code"])
            d.add_paragraph("Fix: " + f["recommendation"])
        d.save(str(out / "report.pdf"))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------
def run_scan(root: Path) -> dict:
    stack = detect_stack(root)
    findings: list = []
    files_scanned = 0
    for p in walk_files(root):
        ext = p.suffix.lower()
        if ext not in CODE_EXT:
            continue
        text = read_text(p)
        if not text:
            continue
        files_scanned += 1
        r = rel(root, p)
        if ext in PY_EXT:
            scan_python(findings, r, text)
        if ext in JS_EXT or ext == ".php" or ext == ".html":
            scan_js_php(findings, r, text)
        if ext == ".sql":
            # raw SQL concat lives in code files; schema SQL is handled by PII inventory
            pass
    findings = validate(findings, root)
    # de-duplicate identical (rule,file,line)
    seen = set(); deduped = []
    for f in findings:
        key = (f["rule"], f["file"], f["line"])
        if key not in seen:
            seen.add(key); deduped.append(f)
    findings = deduped

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    pii = pii_inventory(root)
    return {
        "target": str(root),
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "stack": stack,
        "findings": findings,
        "pii": pii,
        "not_checked": NOT_CHECKED,
        "summary": {
            "files_scanned": files_scanned,
            "total_findings": len(findings),
            "by_severity": by_sev,
            "rules_hit": sorted({f["rule"] for f in findings}),
        },
    }


def main(argv) -> int:
    args = [a for a in argv if not a.startswith("--")]
    out_dir = None
    if "--out" in argv:
        i = argv.index("--out")
        if i + 1 < len(argv):
            out_dir = Path(argv[i + 1])
    if not args:
        print("usage: python aisa_web.py <project.zip | project_dir> [--out <dir>]")
        return 2
    target = Path(args[0])
    if not target.exists():
        print(f"error: {target} not found")
        return 2
    out = (out_dir or Path("aisa-report")).resolve()
    out.mkdir(parents=True, exist_ok=True)

    workdir = None
    if target.is_file() and target.suffix.lower() == ".zip":
        workdir = out / "_extracted"
        safe_unzip(target, workdir)
        root = workdir.resolve()
    elif target.is_dir():
        root = target.resolve()
    else:
        print("error: target must be a .zip file or a directory")
        return 2

    report = run_scan(root)
    report["target"] = str(target)
    write_json(out, report)
    write_html(out, report)
    pdf = write_pdf(out, report)

    s = report["summary"]
    bysev = s["by_severity"]
    sev_str = ", ".join(f"{k}:{bysev[k]}" for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] if k in bysev) or "none"
    pdf_note = " +report.pdf" if pdf else ""
    print(f"AISA: {s['total_findings']} findings ({sev_str}) | rules: {', '.join(s['rules_hit']) or 'none'} "
          f"| -> {out / 'report.html'}{pdf_note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
