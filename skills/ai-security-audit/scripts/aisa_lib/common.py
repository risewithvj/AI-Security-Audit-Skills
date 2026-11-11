# -----------------------------------------------------------------------------
# AI-Security-Audit-Skills
# Author   : Vijaya Kumar L  (Rise With VJ)
# GitHub   : https://github.com/risewithvj
# LinkedIn : https://www.linkedin.com/in/vijayakumarl/
# License  : MIT
# -----------------------------------------------------------------------------
"""Shared helpers: paths, JSON I/O, file walking, secret redaction."""

from __future__ import annotations

import datetime as _dt
import json
import os
import platform
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Iterator

IS_WINDOWS = platform.system() == "Windows"

# Folders that are never the application's own source.
IGNORE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor", "dist", "build", "out",
    ".next", ".nuxt", ".svelte-kit", ".output", ".vercel", ".netlify", ".turbo", ".cache",
    "coverage", ".nyc_output", "__pycache__", ".venv", "venv", "env", ".tox", ".mypy_cache",
    ".pytest_cache", "target", "bin", "obj", "Pods", "DerivedData", ".gradle", ".idea", ".vscode",
    ".terraform", "site-packages", ".expo", "storybook-static", ".dart_tool",
    # WordPress core and heavy backup/cache folders: huge, vendored, never custom source.
    "wp-admin", "wp-includes", "wpvividbackups", "updraft", "updraftplus", "cache", "wp-cache",
}
MAX_FILE_BYTES = 2 * 1024 * 1024

# Well-known public WordPress plugins: present in many installs, audited upstream,
# so treat them as dependencies (list their versions) rather than custom code.
WP_PUBLIC_PLUGINS = (
    "elementor", "elementor-pro", "wpforms-lite", "wpforms", "wordpress-seo", "revslider",
    "w3-total-cache", "woocommerce", "contact-form-7", "akismet", "wpvivid-backuprestore",
    "updraftplus", "jetpack", "wordfence", "all-in-one-wp-migration", "classic-editor",
    "wp-optimize", "redirection", "cmb2", "popup-maker", "header-footer-elementor",
)

# A file path we should treat as vendored / framework-core / build output, not the
# project's own source. Used to suppress india_pii noise and to flag leads.
VENDOR_PATH = re.compile(
    r"(^|/)(vendor|vendor_prefixed|vendored|third[-_]?party|node_modules|bower_components|"
    r"wp-admin|wp-includes|dist|build|out|assets/vendor|languages|lang|i18n|locale|"
    r"twentytwenty\w*)(/|$)"
    r"|(^|/)wp-content/(?:plugins|themes|mu-plugins)/(?:" + "|".join(WP_PUBLIC_PLUGINS) + r")(/|$)"
    r"|\.min\.|-bundle\.|\.bundle\.",
    re.I,
)


def is_vendor_path(rel: str) -> bool:
    """True when the forward-slash relative path is vendored, framework-core, a
    build artefact, or a well-known public WordPress plugin."""
    return bool(VENDOR_PATH.search(rel.replace("\\", "/")))


def wp_scope(target: Path) -> dict:
    """For `init --wp`: locate wp-content and return the auto-scope (custom theme/
    plugin/mu-plugin dirs, wp-config.php and docker-compose.yml) plus the list of
    well-known public plugins present (excluded from hunting, still version-checked)."""
    target = Path(target)
    wc = None
    for cand in (target / "wp-content", target / "wordpress" / "wp-content"):
        if cand.is_dir():
            wc = cand
            break
    if wc is None:
        for p in target.rglob("wp-content"):
            if p.is_dir() and not any(part in IGNORE_DIRS for part in p.parts):
                wc = p
                break
    if wc is None:
        return {"scope": None, "public_plugins": []}
    wcrel = wc.relative_to(target).as_posix()
    scope = [f"{wcrel}/themes", f"{wcrel}/plugins", f"{wcrel}/mu-plugins"]
    scope = [s for s in scope if (target / s).is_dir()]
    cfg = wc.parent / "wp-config.php"
    if cfg.exists():
        scope.append(cfg.relative_to(target).as_posix())
    for comp in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        if (target / comp).exists():
            scope.append(comp)
            break
    public = []
    plugins = wc / "plugins"
    if plugins.is_dir():
        present = {d.name.lower() for d in plugins.iterdir() if d.is_dir()}
        public = sorted(present & set(WP_PUBLIC_PLUGINS))
    return {"scope": scope, "public_plugins": public, "wp_content": wcrel}


# Container mount points whose host folder is a database data directory, not source.
DB_VOLUME_TARGETS = ("/var/lib/mysql", "/var/lib/postgresql", "/data/db", "/var/lib/postgresql/data")


def compose_db_dirs(target: Path) -> set[Path]:
    """Parse docker-compose files under target and return the host folders bind-mounted
    to a database data directory (MySQL/Postgres/Mongo), so the walker can skip them
    instead of crawling gigabytes of DB files."""
    out: set[Path] = set()
    target = Path(target)
    vol = re.compile(r"""^\s*-?\s*["']?([^"':#]+?)["']?\s*:\s*["']?([^"':#]+)["']?""")
    for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        f = target / name
        if not f.exists():
            continue
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            m = vol.match(line)
            if not m:
                continue
            host, cont = m.group(1).strip(), m.group(2).strip().rstrip("/")
            if not any(cont == t or cont.startswith(t + "/") or cont.startswith(t + ":") for t in DB_VOLUME_TARGETS):
                continue
            if host.startswith("./") or host.startswith("../") or host.startswith("."):
                p = (target / host).resolve()
                if p.is_dir():
                    out.add(p)
    return out


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def reports_root() -> Path:
    env = os.environ.get("AISA_REPORTS_DIR")
    return Path(env).expanduser() if env else Path.home() / "ai-security-audit-reports"


def config_path() -> Path:
    return Path.home() / ".ai-security-audit" / "config.json"


def load_config() -> dict:
    p = config_path()
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    return {}


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, path)


def _extra_bin_dirs() -> list[Path]:
    """Directories where package managers drop CLIs that are often missing from
    PATH: pip --user Scripts, winget Links/Packages, scoop shims, ~/.local/bin,
    Homebrew and /usr/local/bin. Lets `doctor` find scanners the installer put
    there without the user editing PATH first."""
    import sysconfig

    dirs: list[Path] = []
    try:
        scheme = f"{os.name}_user"
        if scheme in sysconfig.get_scheme_names():
            scripts = sysconfig.get_path("scripts", scheme)
            if scripts:
                dirs.append(Path(scripts))
    except (KeyError, OSError):
        pass
    home = Path.home()
    if IS_WINDOWS:
        local = os.environ.get("LOCALAPPDATA")
        if local:
            dirs.append(Path(local) / "Microsoft" / "WinGet" / "Links")
            pkgs = Path(local) / "Microsoft" / "WinGet" / "Packages"
            if pkgs.is_dir():
                dirs += sorted(p for p in pkgs.glob("*") if p.is_dir())
        dirs.append(home / "scoop" / "shims")
    dirs += [home / ".local" / "bin", Path("/opt/homebrew/bin"), Path("/usr/local/bin")]
    return [d for d in dirs if d.is_dir()]


def which(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    if IS_WINDOWS:
        for ext in (".exe", ".cmd", ".bat"):
            found = shutil.which(name + ext)
            if found:
                return found
    extra = os.pathsep.join(str(d) for d in _extra_bin_dirs())
    if extra:
        found = shutil.which(name, path=extra)
        if found:
            return found
        if IS_WINDOWS:
            for ext in (".exe", ".cmd", ".bat"):
                found = shutil.which(name + ext, path=extra)
                if found:
                    return found
    return None


# Process-wide path-glob excludes, set once per run from `--exclude`. Every walker
# goes through walk_files(), so one setter keeps init, scan and the exposed sweep in
# step without threading the list through every call site.
_GLOBAL_EXCLUDE: list[str] = []


def set_global_exclude(globs) -> None:
    """Register path globs (relative to the target, POSIX, fnmatch) to skip everywhere."""
    global _GLOBAL_EXCLUDE
    _GLOBAL_EXCLUDE = [g.strip() for g in (globs or []) if g and g.strip()]


def is_excluded(relpath: str, globs=None) -> bool:
    """True if a target-relative path matches any active exclude glob."""
    import fnmatch
    rp = relpath.replace("\\", "/")
    pats = list(_GLOBAL_EXCLUDE) + list(globs or [])
    for g in pats:
        g = g.replace("\\", "/")
        if fnmatch.fnmatch(rp, g) or (g.endswith("/**") and (rp == g[:-3] or rp.startswith(g[:-2]))):
            return True
        # a bare dir glob like "data/static/codefixes" should also prune its contents
        if not any(c in g for c in "*?[") and (rp == g or rp.startswith(g.rstrip("/") + "/")):
            return True
    return False


def walk_files(root: Path, scope: list[str] | None = None, extra_ignore: set[Path] | None = None,
               exclude: list[str] | None = None) -> Iterator[Path]:
    """Yield source files under root, skipping vendored, build and (when given)
    database-volume folders. `extra_ignore` holds absolute directory paths to prune.
    Paths matching `exclude` (or the process-wide excludes) are skipped."""
    ignore_abs = {Path(p).resolve() for p in (extra_ignore or set())}
    bases = [root / s for s in scope] if scope else [root]
    for base in bases:
        if base.is_file():
            if not is_excluded(rel(root, base), exclude):
                yield base
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [
                d for d in dirnames
                if ((d not in IGNORE_DIRS and not d.startswith(".") or d in {".github", ".claude-plugin", ".well-known"})
                    and (Path(dirpath) / d).resolve() not in ignore_abs
                    and not is_excluded(rel(root, Path(dirpath) / d), exclude))
            ]
            for fn in filenames:
                p = Path(dirpath) / fn
                try:
                    if p.is_symlink() or p.stat().st_size > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                if is_excluded(rel(root, p), exclude):
                    continue
                yield p


def rel(root: Path, path: Path | str) -> str:
    p = Path(path)
    try:
        return p.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return Path(str(path)).as_posix()


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# --- Secret detection and redaction -----------------------------------------

SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("stripe_secret", re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{16,}\b")),
    ("razorpay_secret", re.compile(r"\brzp_live_[0-9A-Za-z]{10,}\b")),
    ("github_token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("openai_key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b")),
    ("private_key", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("db_url_with_password", re.compile(r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^:\s/]+:[^@\s]{4,}@")),
]


def mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 6:
        return "****"
    return f"{value[:4]}****({len(value)} chars)"


def find_secrets(text: str) -> list[tuple[str, str]]:
    hits = []
    for name, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            hits.append((name, m.group(0)))
    return hits


def redact_text(text: str) -> str:
    for _name, rx in SECRET_PATTERNS:
        text = rx.sub(lambda m: mask(m.group(0)), text)
    return text


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def die(msg: str, code: int = 2) -> None:
    eprint(f"error: {msg}")
    sys.exit(code)


def resolve_run(run: str | None) -> Path:
    """Accept a run folder path; fall back to the newest run when omitted."""
    if run:
        p = Path(run).expanduser()
        if not (p / "run-metadata.json").exists():
            die(f"not a run folder (no run-metadata.json): {p}")
        return p
    root = reports_root()
    runs = sorted(root.glob("*/run-*/run-metadata.json"), key=lambda x: x.stat().st_mtime)
    if not runs:
        die("no runs found; run 'aisa.py init' first")
    return runs[-1].parent
