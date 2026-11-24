#Requires -Version 5.1
<#
.SYNOPSIS
    Collects a quick health snapshot of a Windows PC for help desk troubleshooting.

.DESCRIPTION
    Gathers OS, uptime, CPU, memory, disk, network and domain information,
    flags common problems as warnings, and can save an HTML report.
    Runs as a standard user. No admin rights required.

.PARAMETER SaveReport
    Save an HTML report in addition to the console output.

.PARAMETER ReportPath
    Folder for the HTML report. Defaults to a Reports folder next to the script.
    Falls back to %TEMP%\SystemReports if that folder is not writable.

.PARAMETER OpenReport
    Open the saved HTML report in the default browser. Use with -SaveReport.

.PARAMETER DiskWarnPercent
    Warn when a drive has less than this percent free space. Default 15.

.PARAMETER MemoryWarnPercent
    Warn when memory usage is above this percent. Default 85.

.PARAMETER UptimeWarnDays
    Warn when the PC has not been restarted in this many days. Default 7.

.EXAMPLE
    .\Get-SystemReport.ps1
    Shows the report in the console only.

.EXAMPLE
    .\Get-SystemReport.ps1 -SaveReport -OpenReport
    Shows the report, saves it as HTML and opens it in the browser.

.NOTES
    Project: helpdesk-toolkit (github.com/TechByJordan)
    Based on CST 3523 Task Automation in System Administration.
#>
[CmdletBinding()]
param(
    [switch]$SaveReport,
    [string]$ReportPath,
    [switch]$OpenReport,
    [ValidateRange(1, 99)][int]$DiskWarnPercent = 15,
    [ValidateRange(1, 99)][int]$MemoryWarnPercent = 85,
    [ValidateRange(1, 365)][int]$UptimeWarnDays = 7
)

# Collects every problem found so it can be shown in one place at the end.
$warnings = New-Object System.Collections.Generic.List[string]

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host "=== $Title ===" -ForegroundColor Cyan
}

function Show-Data {
    # Format-List/Table piped through Out-String keeps output in order with Write-Host.
    param($Data, [switch]$Table)
    if ($Table) { $text = $Data | Format-Table -AutoSize | Out-String -Width 200 }
    else        { $text = $Data | Format-List | Out-String -Width 200 }
    Write-Host $text.Trim()
}

Write-Host "Collecting system information for $env:COMPUTERNAME..." -ForegroundColor Gray

# ---------------------------------------------------------------- OS & uptime
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cs = Get-CimInstance -ClassName Win32_ComputerSystem

$uptime     = (Get-Date) - $os.LastBootUpTime
$uptimeText = '{0}d {1}h {2}m' -f $uptime.Days, $uptime.Hours, $uptime.Minutes

# These registry keys exist only while Windows is waiting for a restart.
$rebootKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
)
$pendingReboot = [bool](@($rebootKeys | Where-Object { Test-Path $_ }).Count)

$osInfo = [PSCustomObject]@{
    ComputerName  = $env:COMPUTERNAME
    OS            = $os.Caption
    Version       = "$($os.Version) (build $($os.BuildNumber))"
    Architecture  = $os.OSArchitecture
    Manufacturer  = $cs.Manufacturer
    Model         = $cs.Model
    LastBoot      = $os.LastBootUpTime
    Uptime        = $uptimeText
    PendingReboot = $pendingReboot
}

if ($uptime.TotalDays -gt $UptimeWarnDays) {
    $warnings.Add("Uptime is $uptimeText. A restart is recommended (threshold: $UptimeWarnDays days).")
}
if ($pendingReboot) {
    $warnings.Add('Windows is waiting for a restart to finish installing updates.')
}

# ---------------------------------------------------------------------- CPU
$cpus    = @(Get-CimInstance -ClassName Win32_Processor)
$cpuLoad = ($cpus | Measure-Object -Property LoadPercentage -Average).Average

$cpuInfo = [PSCustomObject]@{
    Name              = $cpus[0].Name.Trim()
    Cores             = ($cpus | Measure-Object -Property NumberOfCores -Sum).Sum
    LogicalProcessors = ($cpus | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    LoadPercent       = if ($null -ne $cpuLoad) { [math]::Round($cpuLoad, 0) } else { 'n/a' }
}

if ($null -ne $cpuLoad -and $cpuLoad -gt 90) {
    $warnings.Add("CPU load is $([math]::Round($cpuLoad, 0))%. Check Task Manager for busy processes.")
}

# ------------------------------------------------------------------- Memory
# Win32_OperatingSystem reports memory in KB. KB / 1MB = GB.
$memTotalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
$memFreeGB  = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
$memUsedPct = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 1)

$memInfo = [PSCustomObject]@{
    TotalGB     = $memTotalGB
    FreeGB      = $memFreeGB
    UsedPercent = $memUsedPct
}

if ($memUsedPct -gt $MemoryWarnPercent) {
    $warnings.Add("Memory usage is $memUsedPct% (threshold: $MemoryWarnPercent%).")
}

# --------------------------------------------------------------------- Disk
# DriveType 3 = local fixed disks (skips USB sticks, DVD drives and network drives).
$diskInfo = foreach ($disk in Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3') {
    if (-not $disk.Size) { continue }
    $freePct = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1)

    if ($freePct -lt $DiskWarnPercent) {
        $warnings.Add("Drive $($disk.DeviceID) has only $freePct% free space (threshold: $DiskWarnPercent%).")
    }

    [PSCustomObject]@{
        Drive       = $disk.DeviceID
        Label       = $disk.VolumeName
        SizeGB      = [math]::Round($disk.Size / 1GB, 1)
        FreeGB      = [math]::Round($disk.FreeSpace / 1GB, 1)
        FreePercent = $freePct
    }
}

# ------------------------------------------------------------------ Network
# The adapter name ("Ethernet") lives in Win32_NetworkAdapter; IP settings live in
# Win32_NetworkAdapterConfiguration. InterfaceIndex links the two.
$nics    = @(Get-CimInstance -ClassName Win32_NetworkAdapter -Filter 'NetEnabled=True')
$configs = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True')

$netInfo = foreach ($cfg in $configs) {
    $nic  = $nics | Where-Object { $_.InterfaceIndex -eq $cfg.InterfaceIndex } | Select-Object -First 1
    $name = if ($nic -and $nic.NetConnectionID) { $nic.NetConnectionID } else { $cfg.Description }
    $ipv4 = @($cfg.IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })
    $dhcp = if ($cfg.DHCPEnabled) { "Yes ($($cfg.DHCPServer))" } else { 'No (static)' }

    foreach ($ip in $ipv4) {
        if ($ip -like '169.254.*') {
            $warnings.Add("Adapter '$name' has APIPA address $ip. It could not reach a DHCP server.")
        }
    }
    if (-not $cfg.DNSServerSearchOrder) {
        $warnings.Add("Adapter '$name' has no DNS servers configured.")
    }

    [PSCustomObject]@{
        Adapter    = $name
        IPv4       = $ipv4 -join ', '
        Gateway    = @($cfg.DefaultIPGateway) -join ', '
        DNSServers = @($cfg.DNSServerSearchOrder) -join ', '
        DHCP       = $dhcp
        MAC        = $cfg.MACAddress
    }
}

if (-not $netInfo) {
    $warnings.Add('No active network adapter with an IP address was found.')
}

# ------------------------------------------------------------------- Domain
$domainResolves = 'n/a'
if ($cs.PartOfDomain) {
    try {
        Resolve-DnsName -Name $cs.Domain -Type A -ErrorAction Stop | Out-Null
        $domainResolves = 'Yes'
    }
    catch {
        $domainResolves = 'No'
        $warnings.Add("DNS cannot resolve the domain name '$($cs.Domain)'. Run Test-NetworkHealth.ps1 for details.")
    }
}
else {
    $warnings.Add("This PC is not joined to a domain (workgroup: $($cs.Domain)).")
}

if ($env:USERDOMAIN -eq $env:COMPUTERNAME) {
    $warnings.Add("Signed in with a local account ($env:USERNAME), not a domain account.")
}

$domainInfo = [PSCustomObject]@{
    DomainJoined      = $cs.PartOfDomain
    Domain            = $cs.Domain
    DomainDNSResolves = $domainResolves
    LogonServer       = $env:LOGONSERVER -replace '^\\\\', ''
    CurrentUser       = "$env:USERDOMAIN\$env:USERNAME"
}

# ----------------------------------------------------------- Console output
Write-Section 'Operating System'; Show-Data $osInfo
Write-Section 'CPU';              Show-Data $cpuInfo
Write-Section 'Memory';           Show-Data $memInfo
Write-Section 'Disks';            Show-Data $diskInfo -Table
Write-Section 'Network';          Show-Data $netInfo
Write-Section 'Domain';           Show-Data $domainInfo

Write-Section 'Warnings'
if ($warnings.Count -eq 0) {
    Write-Host 'No warnings. System looks healthy.' -ForegroundColor Green
}
else {
    foreach ($w in $warnings) { Write-Host "[!] $w" -ForegroundColor Yellow }
}

# -------------------------------------------------------------- HTML report
if ($SaveReport) {
    if (-not $ReportPath) { $ReportPath = Join-Path $PSScriptRoot 'Reports' }

    try {
        New-Item -ItemType Directory -Path $ReportPath -Force -ErrorAction Stop | Out-Null
    }
    catch {
        $ReportPath = Join-Path $env:TEMP 'SystemReports'
        Write-Warning "Could not write to the report folder. Saving to $ReportPath instead."
        New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
    }

    $stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
    $filePath = Join-Path $ReportPath "SystemReport_$($env:COMPUTERNAME)_$stamp.html"

    $head = @"
<title>System Report - $env:COMPUTERNAME</title>
<style>
  body  { font-family: Segoe UI, Arial, sans-serif; margin: 2em; color: #222; }
  h1    { color: #1f4e79; margin-bottom: 0.2em; }
  h2    { color: #1f4e79; border-bottom: 2px solid #1f4e79; padding-bottom: 0.2em; margin-top: 1.5em; }
  table { border-collapse: collapse; margin-top: 0.5em; }
  th, td { border: 1px solid #ccc; padding: 6px 12px; text-align: left; }
  th    { background: #e8eef5; }
  .meta { color: #666; }
  .ok   { color: #1e7b34; font-weight: bold; }
  .warn li { color: #9c5700; font-weight: bold; margin: 4px 0; }
</style>
"@

    if ($warnings.Count -eq 0) {
        $warnHtml = '<p class="ok">No warnings. System looks healthy.</p>'
    }
    else {
        $items    = $warnings | ForEach-Object { '<li>' + [System.Net.WebUtility]::HtmlEncode($_) + '</li>' }
        $warnHtml = '<ul class="warn">' + ($items -join '') + '</ul>'
    }

    $body = @(
        "<h1>System Report: $env:COMPUTERNAME</h1>"
        "<p class=""meta"">Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by $env:USERDOMAIN\$env:USERNAME</p>"
        '<h2>Warnings</h2>';         $warnHtml
        '<h2>Operating System</h2>'; ($osInfo     | ConvertTo-Html -As List -Fragment)
        '<h2>CPU</h2>';              ($cpuInfo    | ConvertTo-Html -As List -Fragment)
        '<h2>Memory</h2>';           ($memInfo    | ConvertTo-Html -As List -Fragment)
        '<h2>Disks</h2>';            ($diskInfo   | ConvertTo-Html -As Table -Fragment)
        '<h2>Network</h2>';          ($netInfo    | ConvertTo-Html -As Table -Fragment)
        '<h2>Domain</h2>';           ($domainInfo | ConvertTo-Html -As List -Fragment)
    )

    ConvertTo-Html -Head $head -Body ($body -join "`n") | Out-File -FilePath $filePath -Encoding utf8

    Write-Host ''
    Write-Host "HTML report saved to: $filePath" -ForegroundColor Green

    if ($OpenReport) { Invoke-Item -Path $filePath }
}
