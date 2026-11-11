#!/usr/bin/env python3
# AI-Security-Audit-Skills | Vijaya Kumar L (Rise With VJ) | github.com/risewithvj | MIT
"""Originality gate for AI-Security-Audit-Skills.

Fails (exit 1) if any 8-word sequence of our *prose* also appears, word-for-word
after normalisation, in one of the upstream projects this work was inspired by.

What counts as a shared sequence is deliberately narrow so the check measures
copied *writing*, not shared vocabulary:

  * Only prose is compared. Fenced code blocks, indented code, inline `code`
    spans, HTML comment headers and Markdown tables of tool output are stripped.
  * Tokens that everyone in the field necessarily shares are removed *before*
    sequences are formed, so they can never glue a match together:
      - standard identifiers: OWASP, CWE-79, CVSS, A01:2021, MASVS, ASVS ...
      - tool names: semgrep, gitleaks, trivy, osv-scanner ...
      - file paths and filenames (anything with a slash or a code extension)
  * Comparison is case- and punctuation-insensitive.

Usage:
    python tools/originality_check.py --refs <dir-with-upstream-clones>
    python tools/originality_check.py            # auto-discovers ../orig-refs etc.

Exit code 0 means zero overlapping 8-grams.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

WINDOW = 8  # length of the word sequence we treat as "the same writing"

# Repo-relative globs whose prose we police.
OUR_GLOBS = (
    "skills/**/*.md",
    "prompts/**/*.md",
    "docs/**/*.md",
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "START.md",
)

# Our own paths we never police (generated, third-party or our engine code).
OUR_SKIP = ("third_party/", "/__pycache__/", "examples/")

# Upstream repos to compare against (folder name -> informational label).
REF_LABELS = {
    "cloudflare": "cloudflare/security-audit-skill",
    "vibe": "raroque/vibe-security-skill",
    "ponytail": "DietrichGebert/ponytail",
}

# Tokens that are shared ground truth of the domain, not authored phrasing.
# They are dropped before sequences are built.
_STD_ID = re.compile(
    r"""^(
        owasp | cwe | cvss | cve | masvs | asvs | mstg | wstg | nist | sans |
        pci | dss | gdpr | dpdp | hipaa | iso | soc | capec | mitre | att&ck |
        a\d{1,2} | m\d{1,2} | v\d+(\.\d+)* | cwe-\d+ | cve-\d{4}-\d+
    )$""",
    re.IGNORECASE | re.VERBOSE,
)
_TOOLS = {
    "semgrep", "gitleaks", "trivy", "osv", "osv-scanner", "osvscanner",
    "bandit", "codeql", "snyk", "npm", "pip", "cargo", "git", "docker",
    "sarif", "json", "sast", "dast", "reportlab", "docx", "python-docx",
}
# A token that is really a path / filename / identifier, not a prose word.
_PATHISH = re.compile(r"[\\/]|[._-][a-z0-9]+$|\.(md|py|js|ts|go|php|yaml|yml|json|html|gs|sql|sh|ps1|png|pdf|docx)$", re.IGNORECASE)
_WORD = re.compile(r"[a-z0-9]+(?:'[a-z0-9]+)?", re.IGNORECASE)


# A filename / path reference written in prose or a Markdown link, e.g.
# memory-safety-and-binary.md or rules/evidence-gate.md — explicitly ignored.
_FILENAME = re.compile(
    r"[A-Za-z0-9_./\\-]*\.(md|mdc|py|js|ts|tsx|jsx|cjs|mjs|go|php|yaml|yml|json|"
    r"html|htm|gs|sql|sh|ps1|png|pdf|docx|txt|toml|ini|cfg|lock|xml)\b",
    re.IGNORECASE,
)


def strip_code(text: str) -> str:
    """Remove fenced/indented code, inline code spans and HTML-comment headers."""
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    text = re.sub(r"~~~.*?~~~", " ", text, flags=re.DOTALL)
    text = re.sub(r"<!--.*?-->", " ", text, flags=re.DOTALL)
    text = re.sub(r"`[^`]*`", " ", text)
    # Drop Markdown link/image targets: keep the visible text, discard the URL/path.
    text = re.sub(r"\]\(\s*[^)]*\)", "] ", text)
    # Drop filename/path references wholesale so a shared file name can never
    # glue a prose sequence together.
    text = _FILENAME.sub(" ", text)
    out = []
    for line in text.splitlines():
        if re.match(r"^(\s{4,}|\t)", line):  # indented code block
            continue
        out.append(line)
    return "\n".join(out)


def tokenize(text: str) -> list[str]:
    """Return the prose token stream with domain/tool/path tokens removed."""
    toks = []
    for raw in _WORD.findall(strip_code(text).lower()):
        if _STD_ID.match(raw) or raw in _TOOLS or _PATHISH.search(raw):
            continue
        toks.append(raw)
    return toks


def ngrams(tokens: list[str], n: int = WINDOW):
    for i in range(len(tokens) - n + 1):
        yield " ".join(tokens[i : i + n])


def ref_ngram_set(ref_root: Path) -> set[str]:
    grams: set[str] = set()
    for path in ref_root.rglob("*"):
        if not path.is_file() or "/.git/" in path.as_posix():
            continue
        if path.suffix.lower() not in (".md", ".mdc", ".txt", ".json", ""):
            # Prose lives in markdown/text; skip binaries & most code wholesale.
            if path.suffix.lower() not in (".md", ".mdc", ".txt"):
                continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        grams.update(ngrams(tokenize(text)))
    return grams


def our_files(repo: Path):
    seen = set()
    for glob in OUR_GLOBS:
        for path in repo.glob(glob):
            if not path.is_file():
                continue
            posix = path.as_posix()
            if any(s in posix for s in OUR_SKIP) or posix in seen:
                continue
            seen.add(posix)
            yield path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--refs", default=None, help="dir containing upstream clones")
    ap.add_argument("--repo", default=None, help="repo root (default: script's repo)")
    ap.add_argument("--max-report", type=int, default=40)
    args = ap.parse_args()

    repo = Path(args.repo).resolve() if args.repo else Path(__file__).resolve().parents[1]

    refs_dir = None
    if args.refs:
        refs_dir = Path(args.refs).resolve()
    else:
        for cand in (repo.parent / "orig-refs", repo.parent.parent / "orig-refs", Path("/d/tmp/orig-refs")):
            if cand.is_dir():
                refs_dir = cand
                break
    if not refs_dir or not refs_dir.is_dir():
        print("ERROR: reference clones not found. Pass --refs <dir>.", file=sys.stderr)
        return 2

    ref_grams: set[str] = set()
    found_refs = []
    for name, label in REF_LABELS.items():
        root = refs_dir / name
        if root.is_dir():
            ref_grams |= ref_ngram_set(root)
            found_refs.append(label)
    if not found_refs:
        print(f"ERROR: no known upstream clones under {refs_dir}.", file=sys.stderr)
        return 2

    matches = []
    for path in our_files(repo):
        text = path.read_text(encoding="utf-8", errors="ignore")
        toks = tokenize(text)
        for gram in ngrams(toks):
            if gram in ref_grams:
                matches.append((path.relative_to(repo).as_posix(), gram))

    print(f"Originality check: {WINDOW}-word prose sequences vs {', '.join(found_refs)}")
    print(f"Reference {WINDOW}-grams indexed: {len(ref_grams):,}")
    if not matches:
        print("RESULT: 0 shared sequences. PASS.")
        return 0

    print(f"RESULT: {len(matches)} shared sequence(s). FAIL.\n")
    shown = {}
    for relpath, gram in matches:
        shown.setdefault(relpath, []).append(gram)
    for relpath in sorted(shown):
        print(f"  {relpath}:")
        for gram in shown[relpath][: args.max_report]:
            print(f"      … {gram} …")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
