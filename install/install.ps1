# -----------------------------------------------------------------------------
# AI-Security-Audit-Skills - Windows installer
# Author   : Vijaya Kumar L  (Rise With VJ)
# GitHub   : https://github.com/risewithvj
# LinkedIn : https://www.linkedin.com/in/vijayakumarl/
# License  : MIT
#
# Usage (from the repository folder, in PowerShell):
#   powershell -ExecutionPolicy Bypass -File .\install\install.ps1            # all projects (~\.claude\skills)
#   powershell -ExecutionPolicy Bypass -File .\install\install.ps1 -Project   # current project only (.\.claude\skills)
#   add -WithScanners to install Gitleaks, Trivy and OSV-Scanner with winget/scoop
# -----------------------------------------------------------------------------
param(
    [switch]$Project,
    [switch]$WithScanners
)
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$Dest = if ($Project) { Join-Path (Get-Location) ".claude\skills" } else { Join-Path $HOME ".claude\skills" }

Write-Host "AI-Security-Audit-Skills installer  |  Rise With VJ  |  github.com/risewithvj" -ForegroundColor Cyan
Write-Host "Installing skills to $Dest"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
foreach ($s in @("ai-security-audit", "ai-dpdp-audit")) {
    $target = Join-Path $Dest $s
    if (Test-Path $target) { Remove-Item -Recurse -Force $target }
    Copy-Item -Recurse -Force (Join-Path $Repo "skills\$s") $target
    Write-Host "  installed $s"
}

$py = $null
foreach ($c in @("python", "py", "python3")) {
    if (Get-Command $c -ErrorAction SilentlyContinue) { $py = $c; break }
}
if (-not $py) {
    Write-Host "Python 3.9+ not found. Install it with:  winget install Python.Python.3.12" -ForegroundColor Yellow
    Write-Host "then run this installer again."
    exit 1
}
Write-Host "Installing Python packages (python-docx, jsonschema, cvss)"
& $py -m pip install --user --quiet --upgrade python-docx jsonschema cvss

if ($WithScanners) {
    Write-Host "Installing scanners"
    & $py -m pip install --user --quiet semgrep
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --silent --accept-source-agreements --accept-package-agreements Gitleaks.Gitleaks
        winget install --silent --accept-source-agreements --accept-package-agreements AquaSecurity.Trivy
    }
    if (Get-Command scoop -ErrorAction SilentlyContinue) {
        scoop install osv-scanner
    } else {
        Write-Host "  OSV-Scanner: install scoop (https://scoop.sh) then 'scoop install osv-scanner', or download from https://github.com/google/osv-scanner/releases"
    }
}

# pip --user installs console scripts (semgrep, etc.) into the Python user
# Scripts folder, which is often not on PATH. Add it to the user PATH if missing
# so scanners are found now and in future sessions.
try {
    $userScripts = (& $py -c "import sysconfig, os; print(sysconfig.get_path('scripts', os.name + '_user'))").Trim()
    if ($userScripts -and (Test-Path $userScripts)) {
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if (-not (($userPath -split ';') -contains $userScripts)) {
            [Environment]::SetEnvironmentVariable("Path", (($userPath.TrimEnd(';') + ";" + $userScripts).TrimStart(';')), "User")
            Write-Host "  added $userScripts to your user PATH"
        }
        if (-not (($env:PATH -split ';') -contains $userScripts)) {
            $env:PATH = "$userScripts;$env:PATH"
        }
    }
} catch {
    Write-Host "  (could not update PATH automatically; add your Python user Scripts folder if scanners are not found)"
}

Write-Host ""
& $py (Join-Path $Dest "ai-security-audit\scripts\aisa.py") doctor
Write-Host ""
Write-Host "Done. In Claude Code, open your project and type:  /ai-security-audit   or   /ai-dpdp-audit" -ForegroundColor Green
Write-Host "Restart Claude Code (or open a new session) so /ai-security-audit and /ai-dpdp-audit appear." -ForegroundColor Yellow
