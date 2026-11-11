# -----------------------------------------------------------------------------
# AI-Security-Audit-Skills
# Author   : Vijaya Kumar L  (Rise With VJ)
# GitHub   : https://github.com/risewithvj
# LinkedIn : https://www.linkedin.com/in/vijayakumarl/
# License  : MIT
# -----------------------------------------------------------------------------
"""Fast pass for files that should not sit in a web-served folder: backups,
archives, SQL dumps, editor leftovers, logs and env files. These are the
highest-signal WordPress/PHP findings and scanners miss them. We record the path
and size only - never the contents.

This pass ALWAYS walks the whole document root (root files, wp-content/uploads,
wpvividbackups, updraft, ...), regardless of the audit --scope: real backups live
outside the code scope, so honouring --scope here would miss exactly what matters.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .common import compose_db_dirs, is_excluded, rel

# Unlike the general walker we do NOT skip wpvividbackups/updraft/uploads/cache
# here - those are exactly where exposed backups and logs live. We still skip
# code dependencies and WordPress core to keep it fast and relevant.
_SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", "vendor", "vendor_prefixed",
              "bower_components", "wp-admin", "wp-includes", "dist", "__pycache__"}

# Known backup-OUTPUT directory names (exact path components). A file anywhere
# under one of these is a backup artefact. We match on the exact folder name, not
# a substring of "backup", so the plugin source folder `wpvivid-backuprestore`
# (the backup plugin's own code) is NOT flagged.
_BACKUP_DIRS = {
    "wpvividbackups", "updraft", "updraftplus", "ai1wm-backups", "backwpup",
    "backups", "backup", "wp-backups", "db-backups", "sql-backups",
}

# Backup/archive and database-dump extensions (matched anywhere in the tree).
_ARCHIVE_RX = re.compile(r"\.(zip|tar|tar\.gz|tgz|tar\.bz2|tar\.xz|rar|7z|wpress)$", re.I)
_DBDUMP_RX = re.compile(r"\.(sql|sql\.gz|sql\.zip|dump|mdb)$", re.I)

# (regex, reason, severity) - matched against the forward-slash relative path.
# Backups-by-directory and backups-by-extension are handled in _match() directly.
_RULES = [
    (_ARCHIVE_RX, "archive", "high"),
    (_DBDUMP_RX, "database dump", "high"),
    (re.compile(r"(^|/)\.env(\.[\w.-]+)?$", re.I), "env file", "high"),
    (re.compile(r"\.php-\d|\.php~$|\.php\.(bak|old|orig|save|txt)$", re.I), "php source backup", "medium"),
    (re.compile(r"\.(bak|old|orig|save|swp|swo)$|~$", re.I), "editor/backup leftover", "medium"),
    (re.compile(r"(^|/)(debug\.log|error_log|php_errorlog|access\.log)$", re.I), "log file", "medium"),
    (re.compile(r"phpinfo", re.I), "phpinfo file", "medium"),
    (re.compile(r"(^|/)wp-config\.php\.(bak|old|orig|save|txt|_orig)$|(^|/)wp-config-sample\.php$", re.I), "wp-config leftover", "high"),
]

# Report a size next to every hit; flag files over this as large (a 200 MB web-root
# zip is far more serious than a stray 2 KB .bak).
_LARGE_BYTES = 1024 * 1024  # 1 MB

# Cap to keep a pathological tree bounded. On reaching it we WARN (not silently
# truncate) so the operator knows the list is incomplete.
_MAX = 5000


def _match(r: str) -> tuple[str, str] | None:
    parts = [p.lower() for p in r.split("/")[:-1]]  # directory components only
    if any(p in _BACKUP_DIRS for p in parts):
        return "backup directory file", "high"
    for rx, reason, sev in _RULES:
        if rx.search(r):
            return reason, sev
    return None


def find_exposed(target: Path, scope: list[str] | None = None) -> list[dict]:
    """Walk the whole document root (the target), never just the code --scope,
    because exposed backups/logs/dumps live outside the scanned source tree."""
    target = Path(target).resolve()
    extra = {p.resolve() for p in compose_db_dirs(target)}
    out: list[dict] = []
    seen: set[str] = set()
    truncated = False
    for dp, dns, fns in os.walk(target):
        dns[:] = [d for d in dns if d not in _SKIP_DIRS and (Path(dp) / d).resolve() not in extra
                  and not is_excluded(rel(target, Path(dp) / d))]
        for fn in fns:
            p = Path(dp) / fn
            if is_excluded(rel(target, p)):
                continue
            hit = _match(rel(target, p))
            if hit:
                _add(out, seen, target, p, hit)
                if len(out) >= _MAX:
                    truncated = True
                    break
        if truncated:
            break
    if truncated:
        print(f"  ! exposed-files: stopped at the {_MAX}-file cap; the list is incomplete. "
              f"Sweep the document root manually for more backups/dumps.", flush=True)
    return out


def _add(out: list[dict], seen: set, target: Path, p: Path, hit: tuple[str, str]) -> None:
    r = rel(target, p)
    if r in seen:
        return
    seen.add(r)
    try:
        size = p.stat().st_size
    except OSError:
        size = 0
    out.append({"file": r, "bytes": size, "reason": hit[0], "severity_hint": hit[1],
                "large": size > _LARGE_BYTES})
