# Publish a new NetWarden version to GitHub.
#
#   powershell -ExecutionPolicy Bypass -File release.ps1 2.2.0 "Short description of what changed"
#   (or double-click release.bat, which asks for both)
#
# Steps: set __version__ in netwarden\__init__.py, commit everything, tag vX.Y.Z, push main + tag.
# Installed copies check GitHub's main branch for a higher __version__ (at start-up and twice a day)
# and offer "Install update" in the window.
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$Message = ""
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$git = (Get-Command git -ErrorAction SilentlyContinue).Source
if (-not $git) { $git = "C:\Program Files\Git\cmd\git.exe" }
if (-not (Test-Path $git)) { throw "Git not found. Install it with: winget install Git.Git" }

if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Version must look like 2.2.0" }
$init = Join-Path $PSScriptRoot "netwarden\__init__.py"
$text = Get-Content $init -Raw
$cur = [regex]::Match($text, '__version__\s*=\s*"([0-9.]+)"').Groups[1].Value
if ([version]$Version -le [version]$cur) { throw "New version $Version must be higher than the current $cur" }

$branch = (& $git rev-parse --abbrev-ref HEAD).Trim()
if ($branch -ne "main") { throw "Releases are made from 'main' (you are on '$branch')." }

Write-Host "Releasing NetWarden $cur -> $Version" -ForegroundColor Cyan
$text = [regex]::Replace($text, '__version__\s*=\s*"[0-9.]+"', "__version__ = `"$Version`"")
[IO.File]::WriteAllText($init, $text, (New-Object Text.UTF8Encoding $false))

& $git add -A
$title = "Release v$Version" + $(if ($Message) { ": $Message" } else { "" })
& $git commit -m $title
if ($LASTEXITCODE -ne 0) { throw "git commit failed" }
& $git tag -a "v$Version" -m $title
& $git push origin main
if ($LASTEXITCODE -ne 0) { throw "git push failed" }
& $git push origin "v$Version"

Write-Host ""
Write-Host "Done. Installed copies will offer version $Version within 12 hours" -ForegroundColor Green
Write-Host "(or right away: NetWarden > Pro > Settings > Updates > Check now)." -ForegroundColor Green
