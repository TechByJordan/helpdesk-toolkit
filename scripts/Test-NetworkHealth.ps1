#Requires -Version 5.1
<#
.SYNOPSIS
    Tests the network path from a Windows PC to its domain controller, layer by layer,
    and reports exactly where it breaks.
 
.DESCRIPTION
    Runs the checks a help desk technician would do by hand for a "can't log in /
    can't reach the network drive / Group Policy won't apply" ticket, in order:
 
      1. Local IP address     - does this PC have a valid (non-APIPA) IPv4 address?
      2. DC reachable by IP   - can we reach the domain controller at all?
      3. DNS server setting   - is the PC using the DC for DNS? (warning only)
      4. DNS resolves domain  - can DNS find the domain name?
      5. DC locator record    - can DNS find the SRV record clients use to find a DC?
      6. SMB port 445 on DC   - is file sharing reachable on the DC?
      7. SYSVOL share         - can this user open SYSVOL (needed for Group Policy)?
 
    Each step depends on the ones before it, so as soon as one fails the rest are
    skipped and the script tells you where the problem is and what to check next.
    Runs as a standard user. No admin rights required.
 
.PARAMETER DCIPAddress
    IP address of the domain controller. Default is the lab DC (192.168.56.10).
 
.PARAMETER DomainName
    DNS name of the domain. Default is the signed-in user's domain.
 
.PARAMETER TimeoutMs
    Timeout for each network test in milliseconds. Default 2000.
 
.PARAMETER PassThru
    Also output the results as objects (for piping to Export-Csv, etc.).
 
.EXAMPLE
    .\Test-NetworkHealth.ps1
 
.EXAMPLE
    .\Test-NetworkHealth.ps1 -DCIPAddress 10.0.0.5 -DomainName corp.example.com
 
.EXAMPLE
    .\Test-NetworkHealth.ps1 -PassThru | Export-Csv .\network-health.csv -NoTypeInformation
 
.NOTES
    Project: helpdesk-toolkit (github.com/TechByJordan)
    Exit code: 0 if every test passed, otherwise the number of the step that failed.
#>
[CmdletBinding()]
param(
    [string]$DCIPAddress = '192.168.56.10',
    [string]$DomainName,
    [ValidateRange(250, 30000)][int]$TimeoutMs = 2000,
    [switch]$PassThru
)
 
if (-not $DomainName) {
    if ($env:USERDNSDOMAIN) { $DomainName = $env:USERDNSDOMAIN.ToLower() }
    else { $DomainName = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain.ToLower() }
}
 
$results = New-Object System.Collections.Generic.List[object]
$script:failed = $false
 
function Test-TcpPort {
    # Fast TCP check with a real timeout (Test-NetConnection can take 20+ seconds to fail).
    param([string]$Address, [int]$Port, [int]$Timeout)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $attempt = $client.BeginConnect($Address, $Port, $null, $null)
        if ($attempt.AsyncWaitHandle.WaitOne($Timeout, $false) -and $client.Connected) {
            $client.EndConnect($attempt)
            return $true
        }
        return $false
    }
    catch { return $false }
    finally { $client.Close() }
}
 
function Add-Result {
    param([int]$Step, [string]$Test, [string]$Result, [string]$Detail, [string]$Fix)
    $results.Add([PSCustomObject]@{
        Step   = $Step
        Test   = $Test
        Result = $Result
        Detail = $Detail
        Fix    = $Fix
    })
    if ($Result -eq 'FAIL') { $script:failed = $true }
}
 
function Skip-Step {
    # Once an earlier step fails, later steps cannot give a meaningful answer.
    param([int]$Step, [string]$Test)
    Add-Result -Step $Step -Test $Test -Result 'SKIP' -Detail 'Skipped because an earlier step failed.'
}
 
Write-Host ''
Write-Host "Network health check: $env:COMPUTERNAME -> $DomainName (DC $DCIPAddress)" -ForegroundColor Cyan
Write-Host ''
 
# ------------------------------------------------- 1. Local IP address
$configs = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True')
$nics    = @(Get-CimInstance -ClassName Win32_NetworkAdapter -Filter 'NetEnabled=True')
 
$validIPs = @()
$apipaIPs = @()
foreach ($cfg in $configs) {
    $nic  = $nics | Where-Object { $_.InterfaceIndex -eq $cfg.InterfaceIndex } | Select-Object -First 1
    $name = if ($nic -and $nic.NetConnectionID) { $nic.NetConnectionID } else { $cfg.Description }
    foreach ($ip in @($cfg.IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })) {
        if ($ip -like '169.254.*') { $apipaIPs += "${name}: $ip" }
        else { $validIPs += "${name}: $ip" }
    }
}
 
if ($validIPs) {
    Add-Result 1 'Local IP address' 'PASS' ($validIPs -join ', ')
}
elseif ($apipaIPs) {
    Add-Result 1 'Local IP address' 'FAIL' ("Only APIPA address(es): " + ($apipaIPs -join ', ')) `
        'The PC could not get an address from DHCP. Check the network cable or VM adapter, make sure the DHCP server is running, then run: ipconfig /renew'
}
else {
    Add-Result 1 'Local IP address' 'FAIL' 'No active network adapter has an IPv4 address.' `
        'Check that the network adapter is enabled and connected (ncpa.cpl).'
}
 
# ------------------------------------------------- 2. DC reachable by IP
$step2 = 'DC reachable by IP'
if ($script:failed) { Skip-Step 2 $step2 }
else {
    $ping = Test-Connection -ComputerName $DCIPAddress -Count 2 -Quiet -ErrorAction SilentlyContinue
    if ($ping) {
        Add-Result 2 $step2 'PASS' "$DCIPAddress replied to ping."
    }
    elseif (Test-TcpPort -Address $DCIPAddress -Port 389 -Timeout $TimeoutMs) {
        # Ping can be blocked by a firewall even when the DC is fine, so confirm with LDAP.
        Add-Result 2 $step2 'PASS' "$DCIPAddress did not answer ping (ICMP may be blocked) but LDAP port 389 is open."
    }
    else {
        Add-Result 2 $step2 'FAIL' "$DCIPAddress did not answer ping or LDAP (port 389)." `
            'The DC is down or the network path to it is broken. Check that the DC is running, that both machines are on the same network/VLAN, and the IP settings from step 1.'
    }
}
 
# ------------------------------------------------- 3. DNS server setting
$dnsServers = @($configs | ForEach-Object { $_.DNSServerSearchOrder } | Where-Object { $_ } | Select-Object -Unique)
$step3 = 'DNS server setting'
if ($script:failed) { Skip-Step 3 $step3 }
elseif (-not $dnsServers) {
    Add-Result 3 $step3 'FAIL' 'No DNS servers are configured.' `
        'Set the adapter DNS server to the DC, or check DHCP option 006 on the DHCP server.'
}
elseif ($dnsServers -contains $DCIPAddress) {
    Add-Result 3 $step3 'PASS' ("Using " + ($dnsServers -join ', '))
}
else {
    # Warning, not failure: another AD-integrated DNS server could still work. Step 4 decides.
    Add-Result 3 $step3 'WARN' ("DNS points to " + ($dnsServers -join ', ') + ", not the DC ($DCIPAddress).") `
        'Domain members should use the DC (or another AD DNS server) for DNS. Public DNS like 8.8.8.8 cannot find lab.local.'
}
 
# ------------------------------------------------- 4. DNS resolves domain
# Query the configured DNS servers directly with -Server so a cached answer cannot hide a problem.
function Resolve-AgainstServers {
    param([string]$Name, [string]$Type)
    foreach ($server in $dnsServers) {
        try {
            $answer = Resolve-DnsName -Name $Name -Type $Type -Server $server -DnsOnly -QuickTimeout -ErrorAction Stop |
                Where-Object { $_.Type -eq $Type } | Select-Object -First 1
            if ($answer) { return [PSCustomObject]@{ Server = $server; Answer = $answer } }
        }
        catch { continue }
    }
    return $null
}
 
$step4 = 'DNS resolves domain'
if ($script:failed) { Skip-Step 4 $step4 }
else {
    $a = Resolve-AgainstServers -Name $DomainName -Type 'A'
    if ($a) {
        Add-Result 4 $step4 'PASS' "$DomainName -> $($a.Answer.IPAddress) (answered by $($a.Server))"
    }
    else {
        Add-Result 4 $step4 'FAIL' "None of the DNS servers ($($dnsServers -join ', ')) could resolve $DomainName." `
            'Point the PC DNS at the DC (see step 3). On the DC, check that the DNS Server service is running and the zone exists in DNS Manager.'
    }
}
 
# ------------------------------------------------- 5. DC locator record
$step5 = 'DC locator record'
$srvName = "_ldap._tcp.dc._msdcs.$DomainName"
if ($script:failed) { Skip-Step 5 $step5 }
else {
    $srv = Resolve-AgainstServers -Name $srvName -Type 'SRV'
    if ($srv) {
        Add-Result 5 $step5 'PASS' "Found DC $($srv.Answer.NameTarget) via $srvName"
    }
    else {
        Add-Result 5 $step5 'FAIL' "No SRV record found for $srvName." `
            'Domain members use this record to find a DC. On the DC, run: ipconfig /registerdns and restart the Netlogon service.'
    }
}
 
# ------------------------------------------------- 6. SMB port 445 on DC
$step6 = 'SMB port 445 on DC'
if ($script:failed) { Skip-Step 6 $step6 }
elseif (Test-TcpPort -Address $DCIPAddress -Port 445 -Timeout $TimeoutMs) {
    Add-Result 6 $step6 'PASS' "TCP 445 is open on $DCIPAddress."
}
else {
    Add-Result 6 $step6 'FAIL' "TCP 445 is closed or blocked on $DCIPAddress." `
        'File sharing is unreachable. On the DC, check the Server (LanmanServer) service and the Windows Firewall File and Printer Sharing rules.'
}
 
# ------------------------------------------------- 7. SYSVOL share
$step7 = 'SYSVOL share'
$sysvol = "\\$DomainName\SYSVOL\$DomainName"
if ($script:failed) { Skip-Step 7 $step7 }
elseif (Test-Path -Path $sysvol -ErrorAction SilentlyContinue) {
    Add-Result 7 $step7 'PASS' "$sysvol is accessible."
}
else {
    Add-Result 7 $step7 'FAIL' "Cannot open $sysvol." `
        'Group Policy will not apply. On the DC, check that the SYSVOL and NETLOGON shares exist (net share) and the DFS Replication service is running.'
}
 
# ------------------------------------------------------------- Output
$colors = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; SKIP = 'DarkGray' }
foreach ($r in $results) {
    $label = '{0}. {1}' -f $r.Step, $r.Test
    Write-Host ('[{0}] ' -f $r.Result) -ForegroundColor $colors[$r.Result] -NoNewline
    Write-Host ('{0,-24}' -f $label) -NoNewline
    Write-Host $r.Detail
}
 
Write-Host ''
$firstFail = $results | Where-Object { $_.Result -eq 'FAIL' } | Select-Object -First 1
$warns     = @($results | Where-Object { $_.Result -eq 'WARN' })
 
if ($firstFail) {
    Write-Host "RESULT: Broken at step $($firstFail.Step) - $($firstFail.Test)" -ForegroundColor Red
    Write-Host "NEXT STEP: $($firstFail.Fix)" -ForegroundColor Yellow
    $exitCode = $firstFail.Step
}
else {
    Write-Host 'RESULT: All network tests passed. The path to the domain controller is healthy.' -ForegroundColor Green
    foreach ($w in $warns) { Write-Host "NOTE: $($w.Fix)" -ForegroundColor Yellow }
    $exitCode = 0
}
 
if ($PassThru) { $results }
exit $exitCode
 
