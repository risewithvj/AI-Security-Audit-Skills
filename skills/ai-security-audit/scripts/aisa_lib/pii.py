# -----------------------------------------------------------------------------
# AI-Security-Audit-Skills
# Author   : Vijaya Kumar L  (Rise With VJ)
# GitHub   : https://github.com/risewithvj
# LinkedIn : https://www.linkedin.com/in/vijayakumarl/
# License  : MIT
# -----------------------------------------------------------------------------
"""PII inventory for the DPDP audit.

Finds where personal data is defined, stored, logged and sent to third
parties, so the AI review starts from facts instead of guesses. It never
prints personal data values: only counts and locations.
"""

from __future__ import annotations

import re
from pathlib import Path

from .common import compose_db_dirs, read_text, rel, walk_files

# data type -> regex for field / column / property names
FIELD_PATTERNS = {
    "Aadhaar number": r"aadh?aa?r|adhaar|uidai|uid_?(no|number)",
    "PAN": r"\bpan(_?(no|number|card|num))?\b|pancard|pan_card",
    "Passport": r"passport(_?(no|number))?",
    "Voter ID / Driving licence": r"voter_?id|epic_?(no|number)|driving_?licen[cs]e|dl_?(no|number)",
    "Bank account / IFSC / UPI": r"bank_?(acc(ount)?|ac)(_?(no|number))?|account_?(no|number)|ifsc|upi_?id|vpa\b",
    "Salary / compensation": r"\bsalary|\bctc\b|gross_?pay|net_?pay|basic_?pay|payslip|pay_?slip|form_?16|tds\b",
    "PF / ESIC / UAN": r"\buan\b|epf|pf_?(no|number|account)|esic|esi_?(no|number)",
    "Health / medical": r"medical|health|diagnos|disease|blood_?group|disabilit|insurance_?claim|prescription",
    "Biometric": r"biometric|fingerprint|face_?(id|template|embedding)|iris",
    "Date of birth / age": r"\bdob\b|date_?of_?birth|birth_?date|birthday|\bage\b",
    "Phone number": r"phone|mobile(_?(no|number))?|msisdn|whatsapp_?(no|number)",
    "Email address": r"\bemail\b|e_?mail_?(id|address)",
    "Physical address": r"\baddress(_?line)?\b|pincode|pin_?code|postal_?code|zip_?code",
    "Precise location": r"latitude|longitude|\blat\b|\blng\b|geo_?location|gps",
    "Government / tax ID": r"gstin|tan_?(no|number)|ssn\b|national_?id",
    "Caste / religion": r"\bcaste\b|religion|community_?category",
    "Gender / sexual orientation": r"\bgender\b|\bsex\b|sexual_?orientation",
    "Children / dependants": r"guardian|parent_?(name|consent|email|phone)|dependant|dependent|child(ren)?_?(name|dob|age)|minor",
    "Credentials": r"password|passwd|pwd\b|otp\b|pin_?hash|secret_?answer",
    "Photo / signature": r"photo(_?url)?|avatar|selfie|signature_?(img|image|url)?|profile_?pic",
    "Device / online identifier": r"device_?id|imei|advertising_?id|\bip_?address\b|fcm_?token",
}
FIELD_RX = {k: re.compile(v, re.I) for k, v in FIELD_PATTERNS.items()}

# where to look for definitions (schemas, models, migrations, types, forms)
SCHEMA_FILE = re.compile(r"(model|schema|entity|entities|migration|migrations|dto|types?|serializer|form|prisma|graphql|sql|\.proto$)", re.I)
DEF_LINE = re.compile(
    r"(\bcolumn\b|\bfield\b|\bColumn\(|models\.\w+Field|Field\(|@Column|@Prop|:\s*(String|string|str|int|number|Date|varchar|text|bigint|Int)\b|"
    r"\bvarchar\b|\btext\b|\bCREATE TABLE\b|\bADD COLUMN\b|t\.(string|text|integer)|\$table->|\w+\s*:\s*\{\s*type|name=\"|^\s*\w+\s+(String|Int|DateTime)\b)",
    re.I,
)
LOG_LINE = re.compile(r"(console\.(log|info|debug|warn|error)|logger\.\w+|log\.(info|debug|warn|error)|logging\.\w+|print\(|System\.out\.print|Log\.[divwe]\(|echo |error_log\(|puts |Rails\.logger|Sentry\.capture|captureException|captureMessage)")

THIRD_PARTY = {
    "Google Analytics / GTM": r"gtag\(|googletagmanager|google-analytics|@next/third-parties/google|react-ga",
    "Meta Pixel": r"fbq\(|connect\.facebook\.net",
    "Mixpanel": r"mixpanel",
    "Segment": r"analytics\.(track|identify)|@segment/",
    "Amplitude": r"amplitude",
    "Hotjar / Clarity": r"hotjar|clarity\.ms|microsoft-clarity",
    "Sentry": r"@sentry/|sentry_sdk|Sentry\.init",
    "Firebase Analytics": r"firebase/analytics|getAnalytics\(|FirebaseAnalytics",
    "CleverTap / MoEngage / WebEngage": r"clevertap|moengage|webengage",
    "Intercom / Zoho SalesIQ / Freshchat / Tawk": r"intercom|salesiq|zoho\.com/salesiq|freshchat|tawk\.to",
    "OpenAI / Anthropic / Gemini (LLM)": r"api\.openai\.com|new OpenAI\(|openai\.chat|anthropic\.messages|new Anthropic\(|generativelanguage\.googleapis|GoogleGenerativeAI",
    "SMS / WhatsApp gateways": r"twilio|msg91|exotel|gupshup|textlocal|kaleyra|interakt|wati\.io",
    "Email providers": r"sendgrid|mailgun|ses\.amazonaws|SESClient|mailchimp|postmark",
    "Resend (email)": r"\bresend\b|resend\.com|new Resend\(|RESEND_API_KEY",
    "SMTP / nodemailer": r"nodemailer|createTransport\(|smtp\.[a-z0-9.-]+|SMTP_HOST|SMTP_USER|\.sendMail\(",
    "Supabase (DB/storage/auth)": r"@supabase/supabase-js|supabase\.co|supabaseAdmin|createClient\(\s*supabase|SUPABASE_URL|SUPABASE_SERVICE_ROLE",
    "Google Sheets / Drive API": r"googleapis|sheets\.googleapis\.com|drive\.googleapis\.com|google-spreadsheet|GoogleSpreadsheet|googleapis\.com/auth/(spreadsheets|drive)|google\.sheets\(",
    "Payment gateways": r"stripe|razorpay|payu|cashfree|paytm|phonepe|ccavenue",
    "Background verification / KYC": r"digilocker|karza|signzy|idfy|hyperverge|authbridge|ongrid",
}
THIRD_RX = {k: re.compile(v, re.I) for k, v in THIRD_PARTY.items()}

CONSENT_HINTS = re.compile(r"consent|opt[-_ ]?in|opt[-_ ]?out|cookie[-_ ]?banner|cookieconsent|onetrust|cookiebot|privacy[-_ ]?notice|privacy[-_ ]?policy|terms[-_ ]?accept|withdraw[-_ ]?consent|consent[-_ ]?manager", re.I)
# Erasure must be a real delete/erase/anonymise on a personal-data entity, not a
# cache TTL or invalidation. Three parts: an action, a personal-data entity, and
# a cache/noise exclusion. A few explicit rights phrases count on their own.
ERASURE_ACTION = re.compile(r"\b(delete|destroy|erase|erasure|anonymi[sz]e|pseudonymi[sz]e|purge|soft[-_ ]?delete|hard[-_ ]?delete|remove)\b", re.I)
ERASURE_ENTITY = re.compile(r"\b(user|users|lead|leads|customer|client|employee|candidate|applicant|member|person|people|profile|account|data[-_ ]?subject|principal|contact|subscriber|patient|record|row)\b", re.I)
ERASURE_STRONG = re.compile(r"right[-_ ]?to[-_ ]?be[-_ ]?forgotten|\berasure\b|grievance|data[-_ ]?export|download[-_ ]?my[-_ ]?data|anonymi[sz]e|delete[-_ ]?account|delete_?user", re.I)
CACHE_NOISE = re.compile(r"\b(cache|redis|revalidate|invalidate|ttl|memcach|cdn|next/cache|unstable_cache|stale)\b|expire[sd]?_?at", re.I)


def _is_erasure(line: str) -> bool:
    if CACHE_NOISE.search(line):
        return False
    if ERASURE_STRONG.search(line):
        return True
    return bool(ERASURE_ACTION.search(line) and ERASURE_ENTITY.search(line))
BREACH_HINTS = re.compile(r"breach|incident[-_ ]?response|security[-_ ]?incident|notify[-_ ]?board|cert[-_ ]?in", re.I)
ENCRYPT_HINTS = re.compile(r"encrypt|cipher|kms|pgcrypto|aes|fernet|crypto\.createCipher|EncryptedField|encrypted_", re.I)
REGION_HINTS = re.compile(r"(region\s*[:=]\s*[\"']?)([a-z]{2}-[a-z]+-\d|[a-z]+-[a-z]+\d)", re.I)

# value detectors for committed data files
PAN_VAL = re.compile(r"\b[A-Z]{3}[PCHABGJLFT][A-Z]\d{4}[A-Z]\b")
AADHAAR_VAL = re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b")
IN_MOBILE_VAL = re.compile(r"(?<!\d)(?:\+91[\s-]?|0)?[6-9]\d{9}(?!\d)")
IFSC_VAL = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
EMAIL_VAL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DATA_EXT = {".csv", ".json", ".sql", ".xlsx", ".xls", ".txt", ".tsv", ".yaml", ".yml", ".xml", ".ndjson", ".dump", ".bak"}

_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def verhoeff_ok(num: str) -> bool:
    """Aadhaar numbers carry a Verhoeff check digit; this cuts false positives."""
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def _is_code(p: Path) -> bool:
    return p.suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".php", ".java", ".kt", ".go", ".cs", ".swift", ".dart",
                                ".vue", ".svelte", ".astro", ".gs", ".sql", ".prisma", ".graphql", ".gql", ".proto", ".cshtml", ".blade.php", ".html"}


def inventory(target: Path, scope: list[str] | None = None) -> dict:
    target = target.resolve()
    fields: dict[str, list[dict]] = {}
    logs: list[dict] = []
    third: dict[str, list[str]] = {}
    value_files: list[dict] = []
    markers = {"consent": [], "erasure_retention_rights": [], "breach_readiness": [], "encryption": [], "regions": []}
    extra_ignore = compose_db_dirs(target)

    for p in walk_files(target, scope, extra_ignore):
        r = rel(target, p)
        ext = p.suffix.lower()
        is_code = _is_code(p)
        if ext in DATA_EXT and not is_code or ext in (".csv", ".sql", ".tsv", ".ndjson", ".dump", ".bak"):
            txt = read_text(p)
            if txt:
                aad = sum(1 for m in AADHAAR_VAL.finditer(txt) if verhoeff_ok(m.group(0).replace(" ", "")))
                counts = {"aadhaar_like": aad, "pan_like": len(PAN_VAL.findall(txt)), "ifsc_like": len(IFSC_VAL.findall(txt)),
                          "indian_mobile_like": len(IN_MOBILE_VAL.findall(txt)), "email_like": len(EMAIL_VAL.findall(txt))}
                strong = counts["aadhaar_like"] + counts["pan_like"] + counts["ifsc_like"]
                if strong >= 1 or counts["indian_mobile_like"] + counts["email_like"] >= 20:
                    value_files.append({"file": r, "counts": counts, "note": "values not shown"})
        if not is_code and ext not in (".json", ".yaml", ".yml", ".env", ".example", ".tf", ".toml"):
            continue
        txt = read_text(p)
        if not txt:
            continue
        schema_like = bool(SCHEMA_FILE.search(r))
        for i, line in enumerate(txt.splitlines(), 1):
            if len(line) > 400:
                continue
            low = line.lower()
            hit_types = [k for k, rx in FIELD_RX.items() if rx.search(low)]
            if hit_types:
                if schema_like or DEF_LINE.search(line):
                    for k in hit_types:
                        lst = fields.setdefault(k, [])
                        if len(lst) < 60:
                            lst.append({"file": r, "line": i, "code": line.strip()[:160]})
                if LOG_LINE.search(line) and len(logs) < 200:
                    logs.append({"file": r, "line": i, "data_types": hit_types, "code": line.strip()[:160]})
            for k, rx in THIRD_RX.items():
                if rx.search(line):
                    lst = third.setdefault(k, [])
                    loc = f"{r}:{i}"
                    if len(lst) < 15 and loc not in lst:
                        lst.append(loc)
            for key, rx in (("consent", CONSENT_HINTS), ("breach_readiness", BREACH_HINTS), ("encryption", ENCRYPT_HINTS)):
                if rx.search(line) and len(markers[key]) < 40:
                    markers[key].append(f"{r}:{i}")
            if _is_erasure(line) and len(markers["erasure_retention_rights"]) < 40:
                markers["erasure_retention_rights"].append(f"{r}:{i}")
            m = REGION_HINTS.search(line)
            if m and len(markers["regions"]) < 30:
                markers["regions"].append(f"{r}:{i} {m.group(2)}")

    sensitive = {"Aadhaar number", "PAN", "Passport", "Bank account / IFSC / UPI", "Salary / compensation", "Health / medical",
                 "Biometric", "Children / dependants", "Caste / religion", "Credentials", "Precise location"}
    return {
        "data_types": {k: {"references": v, "count": len(v), "high_sensitivity": k in sensitive} for k, v in sorted(fields.items())},
        "possible_pii_in_logs": logs,
        "third_party_recipients": third,
        "files_with_pii_like_values": value_files,
        "markers": markers,
        "summary": {
            "data_types": len(fields), "fields": sum(len(v) for v in fields.values()),
            "high_sensitivity_types": sorted(k for k in fields if k in sensitive),
            "log_sinks": len(logs), "third_parties": len(third), "value_files": len(value_files),
            "consent_markers": len(markers["consent"]), "erasure_markers": len(markers["erasure_retention_rights"]),
        },
        "note": "Heuristic inventory. Every item is a lead for the DPDP review, not a finding. Values are never shown.",
    }
