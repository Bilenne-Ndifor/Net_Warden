# Emergency undo for NetWarden (used by cleanup.bat and the uninstaller).
#  - stops NetWarden (unless -NoStop)
#  - switches block-all mode off and restores Windows Firewall's normal outbound policy
#  - turns blocked-connection auditing back off if NetWarden turned it on
#  - removes every NetWarden firewall rule and QoS speed limit
param([switch]$Quiet, [switch]$NoStop)

$root = $PSScriptRoot
$perm = Join-Path $root "data\permissions.json"

if (-not $NoStop) {
    try { Stop-ScheduledTask -TaskName "NetWarden" -ErrorAction SilentlyContinue } catch { }
    Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*-m netwarden*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 800
}

$j = $null
if (Test-Path $perm) { try { $j = Get-Content $perm -Raw | ConvertFrom-Json } catch { $j = $null } }

# outbound policy: put back what was there before block-all mode, otherwise Windows' default
if ($j -and $j.saved_profiles) {
    foreach ($p in $j.saved_profiles.PSObject.Properties) {
        Set-NetFirewallProfile -Name $p.Name -DefaultOutboundAction $p.Value -ErrorAction SilentlyContinue
    }
} elseif ($j -and (($j.mode -and $j.mode -ne "off") -or $j.policy_set_by_us)) {
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction NotConfigured -ErrorAction SilentlyContinue
}
if ($j -and $j.audit_by_us) {
    & auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /failure:disable | Out-Null
}
# remember block-all is off, so it doesn't switch itself back on at the next start
if ($j) {
    $j.mode = "off"; $j.saved_profiles = $null; $j.audit_by_us = $false
    if ($j.PSObject.Properties.Name -contains "policy_set_by_us") { $j.policy_set_by_us = $false }
    $j | ConvertTo-Json -Depth 10 | Set-Content -Path $perm -Encoding UTF8
}

Get-NetFirewallRule -DisplayName "NetWarden_*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskPath "\NetWarden\" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "NetWarden_*" } |
    Remove-NetQosPolicy -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue

if (-not $Quiet) {
    Write-Host ""
    Write-Host "Done - block-all mode is off and every NetWarden block and limit is removed." -ForegroundColor Green
    Write-Host "Your saved rules stay in data\rules.json and come back the next time NetWarden starts."
    Write-Host "Delete that file too if you want a completely fresh start."
}
