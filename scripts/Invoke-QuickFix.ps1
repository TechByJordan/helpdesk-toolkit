#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the common help desk "quick fixes" on a Windows PC, safely, with -WhatIf support.
 
.DESCRIPTION
    Pick one or more fixes (or -All):
      -FlushDns           Clear the DNS client cache (fixes stale or wrong name lookups).
      -RenewIP            Renew the DHCP lease on connected DHCP adapters (no release, so
                          the connection does not drop).
      -UpdateGroupPolicy  Force a Group Policy refresh (gpupdate /force).
      -RestartSpooler     Stop the Print Spooler, clear stuck print jobs, start it again.
      -ClearTemp          Delete temp files older than -TempOlderThanDays (default 2).
                          Files in use are skipped.
 
    Add -WhatIf to preview exactly what would change without changing anything.
    Fixes that need admin rights are skipped with a clear message when run as a
    standard user; the rest still run. Every real change is logged.
 
.PARAMETER TempOlderThanDays
    Only delete temp files last modified more than this many days ago. Default 2.
 
.EXAMPLE
    .\Invoke-QuickFix.ps1 -All -WhatIf
    Preview every fix without changing anything.
 
.EXAMPLE
    .\Invoke-QuickFix.ps1 -FlushDns -RenewIP
    Typical fix for "websites or network drives will not load".
 
.EXAMPLE
    .\Invoke-QuickFix.ps1 -RestartSpooler
    Typical fix for "my print job is stuck".
 
.NOTES
    Project: helpdesk-toolkit (github.com/TechByJordan)
    Changes are logged to Logs\quickfix-history.log next to the script.
    Exit code: number of fixes that failed (0 = no failures).
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$FlushDns,
    [switch]$RenewIP,
    [switch]$UpdateGroupPolicy,
    [switch]$RestartSpooler,
    [switch]$ClearTemp,
    [switch]$All,
    [ValidateRange(0, 365)][int]$TempOlderThanDays = 2
)
 
if ($All) { $FlushDns = $RenewIP = $UpdateGroupPolicy = $RestartSpooler = $ClearTemp = $true }
 
if (-not ($FlushDns -or $RenewIP -or $UpdateGroupPolicy -or $RestartSpooler -or $ClearTemp)) {
    Write-Host 'No fix selected. Choose one or more:' -ForegroundColor Yellow
    Write-Host '  -FlushDns  -RenewIP  -UpdateGroupPolicy  -RestartSpooler  -ClearTemp  -All'
    Write-Host 'Add -WhatIf to preview without changing anything.'
    Write-Host 'Example: .\Invoke-QuickFix.ps1 -All -WhatIf'
    exit 0
}
 
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin  = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$results  = New-Object System.Collections.Generic.List[object]
$adminMsg = 'Needs admin. Right-click Windows PowerShell > Run as administrator.'
 
function Add-Result {
    param([string]$Fix, [string]$Result, [string]$Detail)
    $results.Add([PSCustomObject]@{ Fix = $Fix; Result = $Result; Detail = $Detail })
}
 
function Write-Step {
    param([string]$Title)
    Write-Host ''
    Write-Host "=== $Title ===" -ForegroundColor Cyan
}
 
function Write-Log {
    # Audit trail of real changes (never called during -WhatIf).
    param([string]$Message)
    try {
        $logDir = Join-Path $PSScriptRoot 'Logs'
        New-Item -ItemType Directory -Path $logDir -Force -WhatIf:$false | Out-Null
        $line = '{0} | {1}\{2} on {3} | {4}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:USERDOMAIN, $env:USERNAME, $env:COMPUTERNAME, $Message
        Add-Content -Path (Join-Path $logDir 'quickfix-history.log') -Value $line -WhatIf:$false
    }
    catch {
        Write-Warning "Could not write the log: $($_.Exception.Message)"
    }
}
 
$mode = if ($WhatIfPreference) { 'PREVIEW (-WhatIf): nothing will be changed' } else { 'LIVE: changes will be made' }
$role = if ($isAdmin) { 'administrator' } else { 'standard user' }
Write-Host ''
Write-Host "Quick fix on $env:COMPUTERNAME as $env:USERDOMAIN\$env:USERNAME ($role)" -ForegroundColor Cyan
Write-Host "Mode: $mode" -ForegroundColor Cyan
 
# ---------------------------------------------------------------- Flush DNS
if ($FlushDns) {
    $name = 'Flush DNS cache'
    Write-Step $name
    if (-not $isAdmin) {
        Add-Result $name 'SKIPPED' $adminMsg
    }
    elseif ($PSCmdlet.ShouldProcess('DNS client cache', 'Clear all cached entries')) {
        try {
            $count = @(Get-DnsClientCache -ErrorAction SilentlyContinue).Count
            Clear-DnsClientCache -ErrorAction Stop -Confirm:$false
            Add-Result $name 'DONE' "Cleared $count cached DNS entries."
            Write-Log "Flushed DNS cache ($count entries)"
        }
        catch { Add-Result $name 'FAILED' $_.Exception.Message }
    }
    else {
        Add-Result $name 'PREVIEW' 'Would clear the DNS client cache.'
    }
}
 
# ----------------------------------------------------------------- Renew IP
if ($RenewIP) {
    $name = 'Renew IP (DHCP)'
    Write-Step $name
    if (-not $isAdmin) {
        Add-Result $name 'SKIPPED' $adminMsg
    }
    else {
        # Only connected adapters that get their address from DHCP. Static and
        # disconnected adapters are left alone.
        $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
            $_.Status -eq 'Up' -and
            (Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp -eq 'Enabled'
        })
 
        if (-not $adapters) {
            Add-Result $name 'SKIPPED' 'No connected adapters use DHCP.'
        }
        foreach ($a in $adapters) {
            $label = "Renew IP ($($a.Name))"
            if ($PSCmdlet.ShouldProcess($a.Name, 'Renew DHCP lease (ipconfig /renew)')) {
                $out = ipconfig.exe /renew "$($a.Name)" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $ip = (Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
                    Add-Result $label 'DONE' "Lease renewed. Address: $ip"
                    Write-Log "Renewed DHCP lease on $($a.Name) ($ip)"
                }
                else {
                    Add-Result $label 'FAILED' (($out | Where-Object { $_ -match '\S' }) -join ' ')
                }
            }
            else {
                Add-Result $label 'PREVIEW' 'Would renew the DHCP lease.'
            }
        }
    }
}
 
# ------------------------------------------------------ Group Policy update
if ($UpdateGroupPolicy) {
    $name = 'Group Policy refresh'
    Write-Step $name
    if ($PSCmdlet.ShouldProcess('Group Policy', 'Force refresh (gpupdate /force)')) {
        # gpupdate can ask "OK to log off? (Y/N)". Answer N so the script never hangs.
        $out  = 'N' | gpupdate.exe /force /wait:120 2>&1
        $text = ($out | Where-Object { $_ -match '\S' }) -join ' '
        if ($LASTEXITCODE -eq 0) {
            Add-Result $name 'DONE' 'User and computer policy refreshed.'
            Write-Log 'Ran gpupdate /force'
        }
        else {
            Add-Result $name 'FAILED' $text
        }
    }
    else {
        Add-Result $name 'PREVIEW' 'Would run gpupdate /force.'
    }
}
 
# ---------------------------------------------------------- Restart spooler
if ($RestartSpooler) {
    $name = 'Restart Print Spooler'
    Write-Step $name
    if (-not $isAdmin) {
        Add-Result $name 'SKIPPED' $adminMsg
    }
    else {
        $spoolDir = Join-Path $env:SystemRoot 'System32\spool\PRINTERS'
        $jobs     = @(Get-ChildItem -Path $spoolDir -File -ErrorAction SilentlyContinue)
 
        if ($PSCmdlet.ShouldProcess('Print Spooler', "Stop service, delete $($jobs.Count) stuck job file(s), start service")) {
            try {
                Stop-Service -Name Spooler -Force -ErrorAction Stop -Confirm:$false
                $jobs | Remove-Item -Force -ErrorAction SilentlyContinue -Confirm:$false
                Start-Service -Name Spooler -ErrorAction Stop -Confirm:$false
                $status = (Get-Service -Name Spooler).Status
                Add-Result $name 'DONE' "Spooler is $status. Cleared $($jobs.Count) stuck job file(s)."
                Write-Log "Restarted Print Spooler, cleared $($jobs.Count) job file(s)"
            }
            catch {
                Add-Result $name 'FAILED' $_.Exception.Message
                # Never leave printing broken: try to start the spooler again.
                Start-Service -Name Spooler -ErrorAction SilentlyContinue -Confirm:$false
            }
        }
        else {
            Add-Result $name 'PREVIEW' "Would restart the spooler and clear $($jobs.Count) stuck job file(s)."
        }
    }
}
 
# --------------------------------------------------------------- Clear temp
if ($ClearTemp) {
    Write-Step 'Clear temp files'
    $cutoff  = (Get-Date).AddDays(-$TempOlderThanDays)
    $folders = @($env:TEMP)
    if ($isAdmin) { $folders += (Join-Path $env:SystemRoot 'Temp') }
    else { Add-Result 'Clear temp (Windows\Temp)' 'SKIPPED' $adminMsg }
 
    foreach ($folder in ($folders | Select-Object -Unique)) {
        $label = "Clear temp ($folder)"
        $files = @(Get-ChildItem -Path $folder -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoff })
        $sizeMB = [math]::Round((($files | Measure-Object -Property Length -Sum).Sum) / 1MB, 1)
 
        if (-not $files) {
            Add-Result $label 'DONE' "Nothing older than $TempOlderThanDays day(s)."
        }
        elseif ($PSCmdlet.ShouldProcess($folder, "Delete $($files.Count) file(s), $sizeMB MB, older than $TempOlderThanDays day(s)")) {
            $deleted = 0
            $freed   = 0
            foreach ($f in $files) {
                try {
                    $length = $f.Length
                    Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop -Confirm:$false
                    $deleted++
                    $freed += $length
                }
                catch { }  # File is in use by a running program. Skip it.
            }
            $freedMB = [math]::Round($freed / 1MB, 1)
            $skipped = $files.Count - $deleted
            Add-Result $label 'DONE' "Deleted $deleted file(s), freed $freedMB MB. $skipped in use and skipped."
            Write-Log "Cleared temp in ${folder}: $deleted file(s), $freedMB MB"
        }
        else {
            Add-Result $label 'PREVIEW' "Would delete $($files.Count) file(s), $sizeMB MB."
        }
    }
}
 
# ------------------------------------------------------------------ Summary
Write-Step 'Summary'
$colors = @{ DONE = 'Green'; PREVIEW = 'Cyan'; SKIPPED = 'Yellow'; FAILED = 'Red' }
foreach ($r in $results) {
    Write-Host ('[{0}] ' -f $r.Result) -ForegroundColor $colors[$r.Result] -NoNewline
    Write-Host "$($r.Fix): $($r.Detail)"
}
 
$failed  = @($results | Where-Object { $_.Result -eq 'FAILED' }).Count
$skipped = @($results | Where-Object { $_.Result -eq 'SKIPPED' }).Count
 
Write-Host ''
if ($skipped -gt 0) {
    Write-Host "$skipped fix(es) skipped because they need admin rights." -ForegroundColor Yellow
}
if (-not $WhatIfPreference -and ($results | Where-Object { $_.Result -eq 'DONE' })) {
    Write-Host "Changes logged to $(Join-Path $PSScriptRoot 'Logs\quickfix-history.log')" -ForegroundColor Gray
}
 
exit $failed
