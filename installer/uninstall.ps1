# NetWarden uninstaller: stops it, restores the normal firewall policy, removes every
# NetWarden firewall rule / QoS limit, the autostart task, shortcuts and files.
param([switch]$Quiet)

$AppName = "NetWarden"
$Dest = Join-Path $env:ProgramFiles $AppName

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $a = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Quiet) { $a += " -Quiet" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a
    exit
}

if (-not $Quiet) {
    Add-Type -AssemblyName System.Windows.Forms
    $r = [System.Windows.Forms.MessageBox]::Show(
        "Remove NetWarden?`n`nAll NetWarden blocks, limits and block-all mode are removed and Windows Firewall goes back to its normal settings.",
        "Uninstall NetWarden", "YesNo", "Question")
    if ($r -ne "Yes") { exit }
}

# 1. stop it
try { Stop-ScheduledTask -TaskName $AppName -ErrorAction SilentlyContinue } catch { }
Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*-m netwarden*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 800

# 2. restore the firewall's normal outbound policy and connection auditing (block-all mode)
& (Join-Path $Dest "cleanup.ps1") -Quiet -NoStop

# 3. task, shortcuts, Apps & features entry
Unregister-ScheduledTask -TaskName $AppName -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\NetWarden.lnk") -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\NetWarden emergency reset.lnk") -Force -ErrorAction SilentlyContinue
# the packet-capture driver service, only if it is NetWarden's own copy (other tools such as
# GoodbyeDPI / zapret also use WinDivert and must keep working)
$drv = Get-CimInstance Win32_SystemDriver -Filter "Name='WinDivert'" -ErrorAction SilentlyContinue
if ($drv -and $drv.PathName -like "*\NetWarden\*") {
    & sc.exe stop WinDivert | Out-Null
    & sc.exe delete WinDivert | Out-Null
}
Remove-Item (Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "NetWarden.lnk") -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\NetWarden" -Recurse -Force -ErrorAction SilentlyContinue

# 4. files (this script lives inside the folder, so finish the delete from a separate process)
Set-Location $env:TEMP
Remove-Item $Dest -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path $Dest) {
    Start-Process cmd.exe -WindowStyle Hidden -ArgumentList "/c timeout /t 3 >nul & rmdir /s /q `"$Dest`""
}

if (-not $Quiet) {
    [System.Windows.Forms.MessageBox]::Show("NetWarden was removed.", "NetWarden", "OK", "Information") | Out-Null
}
