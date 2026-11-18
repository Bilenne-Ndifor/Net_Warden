# NetWarden installer
# - copies NetWarden to C:\Program Files\NetWarden (admin-only folder: the code runs with admin rights)
# - creates a private Python environment with its dependencies
# - registers a logon task that starts NetWarden in the background with admin rights (no UAC prompt)
# - adds Start-menu + desktop shortcuts and an "Apps & features" entry (uninstall)
# Run through "Install NetWarden.bat".
#
# -Update: unattended mode used by NetWarden's own updater (no prompts, output to -LogFile).
param([switch]$Update, [string]$LogFile = "")

$ErrorActionPreference = "Continue"   # native tools write to stderr; failures are checked explicitly
$ProgressPreference = "SilentlyContinue"
$AppName = "NetWarden"
$Src = Split-Path -Parent $PSScriptRoot
# single source of truth for the version: __version__ in netwarden\__init__.py
$Version = "0.0.0"
$m = Select-String -Path (Join-Path $Src "netwarden\__init__.py") -Pattern '__version__\s*=\s*"([0-9.]+)"' -ErrorAction SilentlyContinue
if ($m) { $Version = $m.Matches[0].Groups[1].Value }
if ($Update -and $LogFile) { try { Start-Transcript -Path $LogFile -Force | Out-Null } catch { } }
function Pause-End { if (-not $Update) { Read-Host "Press Enter to close" | Out-Null } }
$Dest = Join-Path $env:ProgramFiles $AppName
$TaskName = $AppName

function Say($msg, $color = "Gray") { Write-Host $msg -ForegroundColor $color }
function Step($msg) { Write-Host ""; Write-Host "==> $msg" -ForegroundColor Cyan }
function Fail($msg) { Write-Host ""; Write-Host "Install failed: $msg" -ForegroundColor Red; Pause-End; exit 1 }

# ---------------------------------------------------------------- admin
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Fail "please run 'Install NetWarden.bat' (it asks for administrator rights)." }

Write-Host ""
Write-Host "  NetWarden $Version setup" -ForegroundColor White
Write-Host "  Installs to $Dest and starts automatically when you sign in." -ForegroundColor DarkGray

# The signed-in desktop user (may differ from the admin account that approved the UAC prompt)
$User = (Get-CimInstance Win32_ComputerSystem).UserName
if (-not $User) { $User = "$env:USERDOMAIN\$env:USERNAME" }
Say "  For user: $User" DarkGray
try {
    $admins = @(Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop | ForEach-Object { $_.Name })
    if ($admins -and -not ($admins -contains $User) -and -not $Update) {
        Say "  WARNING: $User is not an administrator. NetWarden would start without admin rights and could only" Yellow
        Say "  watch traffic (no blocking, no block-all). Sign in with an administrator account to install it." Yellow
        $ans = Read-Host "  Continue anyway? (y/N)"
        if ($ans -notmatch '^[yY]') { exit 1 }
    }
} catch { }

# ---------------------------------------------------------------- python
Step "Looking for Python 3.10 or newer"
function Find-Python {
    foreach ($c in @("py -3", "python")) {
        $parts = $c.Split(" ")
        $exe = $parts[0]
        $rest = @($parts | Select-Object -Skip 1)
        try {
            $out = & $exe @rest -c "import sys; print(sys.version_info >= (3, 10)); print(sys.base_prefix); print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $out -and $out[0] -eq "True") {
                return [pscustomobject]@{ Prefix = $out[1]; Exe = $out[2] }
            }
        } catch { }
    }
    return $null
}
function Refresh-Path {
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
}

$py = Find-Python
$userProfile = [Environment]::GetFolderPath("UserProfile")
$needMachine = (-not $py) -or ($py.Prefix -like "$userProfile*") -or ($py.Prefix -like "*\AppData\*")
if ($needMachine) {
    if ($py) {
        Say "  Found Python in a user folder ($($py.Prefix))." Yellow
        Say "  NetWarden runs with admin rights, so it should use a Python that only admins can modify." Yellow
    } else {
        Say "  Python was not found." Yellow
    }
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        Say "  Installing Python 3.12 for all users with winget (takes a minute)..."
        & winget install -e --id Python.Python.3.12 --scope machine --silent --accept-package-agreements --accept-source-agreements | Out-Host
        Refresh-Path
        $machinePy = Join-Path $env:ProgramFiles "Python312\python.exe"
        if (Test-Path $machinePy) {
            $py = [pscustomobject]@{ Prefix = (Split-Path $machinePy); Exe = $machinePy }
        } else {
            $py = Find-Python
        }
    }
    if (-not $py) { Fail "Python 3.10+ is required. Install it from https://www.python.org/downloads/ ('Install for all users') and run setup again." }
    if ($py.Prefix -like "$userProfile*") {
        Say "  Continuing with the per-user Python. (Less secure: install Python 'for all users' later and re-run setup.)" Yellow
    }
}
$PyExe = $py.Exe
Say "  Using $PyExe" Green

# ---------------------------------------------------------------- stop a running copy
Step "Stopping NetWarden if it is running"
try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch { }
Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*-m netwarden*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 800

# ---------------------------------------------------------------- copy files
Step "Copying files to $Dest"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
$null = & robocopy (Join-Path $Src "netwarden") (Join-Path $Dest "netwarden") /MIR /XD __pycache__ /NFL /NDL /NJH /NJS /NP
if ($LASTEXITCODE -ge 8) { Fail "copying files (robocopy code $LASTEXITCODE)" }
foreach ($f in @("requirements.txt", "README.md", "LICENSE", "cleanup.bat", "cleanup.ps1")) {
    $p = Join-Path $Src $f
    if (Test-Path $p) { Copy-Item $p $Dest -Force }
}
Copy-Item (Join-Path $PSScriptRoot "uninstall.ps1") $Dest -Force
$DataDir = Join-Path $Dest "data"
if (-not (Test-Path $DataDir)) {
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    # bring over rules / permissions from the portable copy, if it was used
    $oldData = Join-Path $Src "data"
    foreach ($f in @("rules.json", "permissions.json", "settings.json", "usage.json")) {
        $p = Join-Path $oldData $f
        if (Test-Path $p) { Copy-Item $p $DataDir -Force; Say "  Kept your $f" }
    }
}
# data (token, rules, UI profile) readable and writable only by Administrators and SYSTEM
& icacls $DataDir /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null

# ---------------------------------------------------------------- python environment
Step "Setting up NetWarden's Python environment"
$Venv = Join-Path $Dest ".venv"
$VPy = Join-Path $Venv "Scripts\python.exe"
$VPyw = Join-Path $Venv "Scripts\pythonw.exe"
if (-not (Test-Path $VPy)) {
    & $PyExe -m venv $Venv
    if ($LASTEXITCODE -ne 0) { Fail "could not create the Python environment" }
}
& $VPy -m pip install --disable-pip-version-check -q --upgrade pip | Out-Null
& $VPy -m pip install --disable-pip-version-check -q -r (Join-Path $Dest "requirements.txt")
if ($LASTEXITCODE -ne 0) { Fail "installing dependencies (psutil, pydivert, pystray, pillow)" }
$null = & $VPy -c "import tkinter" 2>&1
if ($LASTEXITCODE -ne 0) { Say "  Note: this Python has no Tk, so permission requests show as tray notifications instead of pop-ups." Yellow }
$Ico = Join-Path $Dest "netwarden.ico"
Push-Location $Dest
& $VPy -c "from netwarden.agent import make_ico; make_ico(r'$Ico')"
Pop-Location

# ---------------------------------------------------------------- autostart task
Step "Registering autostart (runs in the background when $User signs in)"
$action = New-ScheduledTaskAction -Execute $VPyw -Argument "-m netwarden --background" -WorkingDirectory $Dest
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $User
$principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
try {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description "NetWarden network monitor and firewall (background)" -Force -ErrorAction Stop | Out-Null
} catch { Fail "could not register the autostart task: $($_.Exception.Message)" }

# ---------------------------------------------------------------- shortcuts
Step "Creating shortcuts"
$shell = New-Object -ComObject WScript.Shell
$startMenu = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\NetWarden.lnk"
$desktop = Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "NetWarden.lnk"
foreach ($lnkPath in @($startMenu, $desktop)) {
    $lnk = $shell.CreateShortcut($lnkPath)
    $lnk.TargetPath = $VPyw
    $lnk.Arguments = "-m netwarden --open"
    $lnk.WorkingDirectory = $Dest
    $lnk.IconLocation = "$Ico,0"
    $lnk.Description = "Open NetWarden"
    $lnk.Save()
}
# Emergency reset: works without Python (turns block-all off, removes every NetWarden rule)
$reset = $shell.CreateShortcut((Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\NetWarden emergency reset.lnk"))
$reset.TargetPath = Join-Path $env:SystemRoot "System32\cmd.exe"
$reset.Arguments = "/c `"$Dest\cleanup.bat`""
$reset.WorkingDirectory = $Dest
$reset.IconLocation = (Join-Path $env:SystemRoot "System32\shell32.dll") + ",77"
$reset.Description = "Turn NetWarden block-all off and remove all of its firewall rules"
$reset.Save()

# ---------------------------------------------------------------- Apps & features
Step "Registering in Apps & features"
$key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\NetWarden"
New-Item -Path $key -Force | Out-Null
$size = [int]((Get-ChildItem $Dest -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1KB)
$props = @{
    DisplayName = "NetWarden"; DisplayVersion = $Version; Publisher = "NetWarden (built for this PC)";
    InstallLocation = $Dest; DisplayIcon = $Ico; NoModify = 1; NoRepair = 1; EstimatedSize = $size;
    UninstallString = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$Dest\uninstall.ps1`"";
    QuietUninstallString = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$Dest\uninstall.ps1`" -Quiet"
}
foreach ($k in $props.Keys) {
    $type = if ($props[$k] -is [int]) { "DWord" } else { "String" }
    New-ItemProperty -Path $key -Name $k -Value $props[$k] -PropertyType $type -Force | Out-Null
}

# ---------------------------------------------------------------- start
Step "Starting NetWarden"
Start-ScheduledTask -TaskName $TaskName
$port = $null
for ($i = 0; $i -lt 40 -and -not $port; $i++) {
    Start-Sleep -Milliseconds 500
    foreach ($p in 47800..47805) {
        try {
            $r = Invoke-RestMethod -Uri "http://127.0.0.1:$p/api/hello" -TimeoutSec 1
            if ($r.app -eq "NetWarden") { $port = $p; break }
        } catch { }
    }
}
if ($port) {
    try { Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$port/api/open" -Body "{}" -ContentType "application/json" | Out-Null } catch { }
    Say "  NetWarden is running. Look for the shield icon near the clock." Green
} else {
    Say "  NetWarden didn't answer yet. Check $DataDir\netwarden.log, or start it from the Start menu." Yellow
}

Write-Host ""
if ($Update) {
    Write-Host "  Updated to NetWarden $Version." -ForegroundColor Green
    try { Stop-Transcript | Out-Null } catch { }
} else {
    Write-Host "  Installed NetWarden $Version. It now starts by itself every time you sign in." -ForegroundColor Green
    Write-Host "  Open it from the Start menu / desktop, or the tray icon. Uninstall from Settings > Apps." -ForegroundColor Green
    Write-Host ""
    Pause-End
}
