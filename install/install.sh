#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# AI-Security-Audit-Skills - macOS / Linux installer
# Author   : Vijaya Kumar L  (Rise With VJ)
# GitHub   : https://github.com/risewithvj
# LinkedIn : https://www.linkedin.com/in/vijayakumarl/
# License  : MIT
#
# Usage (from the repository folder):
#   bash install/install.sh                  # all projects (~/.claude/skills)
#   bash install/install.sh --project        # current project only (./.claude/skills)
#   add --with-scanners to install Semgrep, Gitleaks, Trivy and OSV-Scanner (Homebrew on macOS)
# -----------------------------------------------------------------------------
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$HOME/.claude/skills"
SCANNERS=0
for a in "$@"; do
  case "$a" in
    --project) DEST="$(pwd)/.claude/skills" ;;
    --with-scanners) SCANNERS=1 ;;
  esac
done

echo "AI-Security-Audit-Skills installer  |  Rise With VJ  |  github.com/risewithvj"
echo "Installing skills to $DEST"
mkdir -p "$DEST"
for s in ai-security-audit ai-dpdp-audit; do
  rm -rf "${DEST:?}/$s"
  cp -R "$REPO/skills/$s" "$DEST/$s"
  echo "  installed $s"
done

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  echo "Python 3.9+ not found. macOS: brew install python   Linux: use your package manager. Then re-run."
  exit 1
fi
echo "Installing Python packages (python-docx, jsonschema, cvss)"
"$PY" -m pip install --user --quiet --upgrade python-docx jsonschema cvss 2>/dev/null \
  || "$PY" -m pip install --user --quiet --upgrade --break-system-packages python-docx jsonschema cvss

if [ "$SCANNERS" = "1" ]; then
  if command -v brew >/dev/null 2>&1; then
    brew install semgrep gitleaks trivy osv-scanner
  else
    "$PY" -m pip install --user --quiet semgrep || true
    echo "  Install Gitleaks, Trivy and OSV-Scanner from their GitHub releases or your package manager."
  fi
fi

echo
"$PY" "$DEST/ai-security-audit/scripts/aisa.py" doctor || true
echo
echo "Done. In Claude Code, open your project and type:  /ai-security-audit   or   /ai-dpdp-audit"
echo "Restart Claude Code (or open a new session) so /ai-security-audit and /ai-dpdp-audit appear."
