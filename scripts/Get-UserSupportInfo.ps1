#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Shows everything a help desk technician needs for a "user can't sign in" ticket,
    and can safely unlock the account.
 
.DESCRIPTION
    Looks up an Active Directory user and reports:
      - Account details (name, title, department, created, last logon)
      - Status (enabled, locked out and until when, bad password count, account expiry)
      - Password (last set, expiry date, days left, expired, must change at next logon)
      - Group memberships
      - Optional: which computer caused the lockout (Security event 4740)
    It ends with a plain-English diagnosis of why the user cannot sign in.
 
    -Unlock unlocks a locked-out account and supports -WhatIf. It deliberately does
    NOT re-enable disabled accounts, because a disabled account is often an
    offboarded employee and needs approval first. Every unlock is logged.
 
    Run on a domain controller (or a PC with RSAT) as an account that can unlock
    users. Queries go to the PDC emulator, which holds the most accurate lockout
    and bad password information.
 
.PARAMETER Identity
    The user's logon name (sAMAccountName), for example mlopez.
 
.PARAMETER Unlock
    Unlock the account if it is locked out. Use -WhatIf to preview.
 
.PARAMETER IncludeLockoutSource
    Search the PDC Security log for event 4740 to find which computer locked the account.
 
.PARAMETER PasswordWarnDays
    Warn when the password expires within this many days. Default 7.
 
.PARAMETER PassThru
    Also output the results as an object.
 
.EXAMPLE
    .\Get-UserSupportInfo.ps1 mlopez
 
.EXAMPLE
    .\Get-UserSupportInfo.ps1 dclarke -IncludeLockoutSource
 
.EXAMPLE
    .\Get-UserSupportInfo.ps1 dclarke -Unlock -WhatIf
 
.NOTES
    Project: helpdesk-toolkit (github.com/TechByJordan)
    Unlocks are logged to Logs\unlock-history.log next to the script.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Identity,
    [switch]$Unlock,
    [switch]$IncludeLockoutSource,
    [ValidateRange(1, 90)][int]$PasswordWarnDays = 7,
    [switch]$PassThru
)
 
Import-Module ActiveDirectory -ErrorAction Stop
 
$warnings = New-Object System.Collections.Generic.List[string]
 
function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host "=== $Title ===" -ForegroundColor Cyan
}
 
function Show-Data {
    param($Data)
    $text = $Data | Format-List | Out-String -Width 200
    Write-Host $text.Trim()
}
 
# Lockouts are processed by the PDC emulator, so ask it directly.
$pdc    = (Get-ADDomain).PDCEmulator
$policy = Get-ADDefaultDomainPasswordPolicy -Server $pdc
 
$props = @(
    'DisplayName', 'Title', 'Department', 'EmailAddress', 'whenCreated', 'LastLogonDate',
    'Enabled', 'LockedOut', 'lockoutTime', 'BadLogonCount', 'LastBadPasswordAttempt',
    'AccountExpirationDate', 'PasswordLastSet', 'PasswordExpired', 'PasswordNeverExpires',
    'msDS-UserPasswordExpiryTimeComputed', 'MemberOf'
)
 
# ------------------------------------------------------------ Find the user
try {
    $user = Get-ADUser -Identity $Identity -Properties $props -Server $pdc -ErrorAction Stop
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    Write-Host "No user with the logon name '$Identity' was found." -ForegroundColor Red
    # Ambiguous name resolution matches first name, last name, display name or logon name.
    $similar = @(Get-ADUser -LDAPFilter "(anr=$Identity)" -Server $pdc | Select-Object -First 5)
    if ($similar) {
        Write-Host 'Did you mean:' -ForegroundColor Yellow
        foreach ($s in $similar) { Write-Host "  $($s.SamAccountName)  ($($s.Name))" }
    }
    exit 1
}
 
# --------------------------------------------------------- Account details
$accountInfo = [PSCustomObject]@{
    Name       = $user.Name
    LogonName  = $user.SamAccountName
    Title      = $user.Title
    Department = $user.Department
    Email      = $user.EmailAddress
    Created    = $user.whenCreated
    LastLogon  = $user.LastLogonDate
}
 
# ------------------------------------------------------------------ Status
$lockedUntil = $null
if ($user.LockedOut) {
    if ($policy.LockoutDuration.TotalMinutes -gt 0 -and $user.lockoutTime) {
        $lockedUntil = [datetime]::FromFileTime($user.lockoutTime) + $policy.LockoutDuration
    }
    else {
        $lockedUntil = 'Until an admin unlocks it'
    }
}
 
$statusInfo = [PSCustomObject]@{
    Enabled          = $user.Enabled
    LockedOut        = $user.LockedOut
    LockedOutUntil   = $lockedUntil
    BadPasswordCount = $user.BadLogonCount
    LastBadPassword  = $user.LastBadPasswordAttempt
    AccountExpires   = if ($user.AccountExpirationDate) { $user.AccountExpirationDate } else { 'Never' }
}
 
# ---------------------------------------------------------------- Password
$expiryDate = $null
$daysLeft   = $null
$rawExpiry  = $user.'msDS-UserPasswordExpiryTimeComputed'
 
if ($user.PasswordNeverExpires) {
    $expires = 'Never (password set to never expire)'
}
elseif (-not $user.PasswordLastSet) {
    $expires = 'User must change password at next logon'
}
elseif ($rawExpiry -and $rawExpiry -ne [int64]::MaxValue) {
    $expiryDate = [datetime]::FromFileTime($rawExpiry)
    $daysLeft   = [math]::Floor(($expiryDate - (Get-Date)).TotalDays)
    $expires    = $expiryDate
}
else {
    $expires = 'Never (domain has no maximum password age)'
}
 
$passwordInfo = [PSCustomObject]@{
    LastSet      = if ($user.PasswordLastSet) { $user.PasswordLastSet } else { 'Never / reset required' }
    Expires      = $expires
    DaysLeft     = if ($null -ne $daysLeft) { $daysLeft } else { 'n/a' }
    Expired      = $user.PasswordExpired
    NeverExpires = $user.PasswordNeverExpires
}
 
$policyInfo = [PSCustomObject]@{
    LockoutThreshold = if ($policy.LockoutThreshold -gt 0) { "$($policy.LockoutThreshold) bad attempts" } else { 'Disabled (accounts never lock)' }
    LockoutDuration  = if ($policy.LockoutDuration.TotalMinutes -gt 0) { "$($policy.LockoutDuration.TotalMinutes) minutes" } else { 'Until an admin unlocks' }
    MaxPasswordAge   = if ($policy.MaxPasswordAge.TotalDays -gt 0) { "$($policy.MaxPasswordAge.TotalDays) days" } else { 'Never expires' }
}
 
# ------------------------------------------------------------------ Groups
# memberOf does not include the primary group (usually Domain Users), so add it.
$groups = @($user.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' } | Sort-Object)
$groups += 'Domain Users (primary group)'
 
# --------------------------------------------------------------- Diagnosis
if (-not $user.Enabled) {
    $warnings.Add('Account is DISABLED. If this person has left (offboarded), do not re-enable it without approval from their manager or HR.')
}
if ($user.LockedOut) {
    $when = if ($lockedUntil -is [datetime]) { "It unlocks automatically at $lockedUntil." } else { 'It will stay locked until an admin unlocks it.' }
    $warnings.Add("Account is LOCKED OUT after too many bad passwords. $when Run with -Unlock to unlock it now.")
}
if ($user.PasswordExpired) {
    $warnings.Add('Password has EXPIRED. The user must set a new one, or reset it in Active Directory Users and Computers.')
}
elseif (-not $user.PasswordLastSet -and -not $user.PasswordNeverExpires) {
    $warnings.Add('User must change their password at next logon.')
}
elseif ($null -ne $daysLeft -and $daysLeft -le $PasswordWarnDays) {
    $warnings.Add("Password expires in $daysLeft day(s), on $expiryDate. Remind the user to change it.")
}
if ($user.AccountExpirationDate -and $user.AccountExpirationDate -lt (Get-Date)) {
    $warnings.Add("Account EXPIRED on $($user.AccountExpirationDate).")
}
if (-not $user.LockedOut -and $user.BadLogonCount -gt 0) {
    $limit = if ($policy.LockoutThreshold -gt 0) { " Lockout happens at $($policy.LockoutThreshold)." } else { '' }
    $warnings.Add("$($user.BadLogonCount) recent bad password attempt(s), last at $($user.LastBadPasswordAttempt).$limit")
}
 
# ------------------------------------------------------------------ Output
Write-Host ''
Write-Host "User support info: $($user.SamAccountName) ($($user.Name)) - queried $pdc" -ForegroundColor Cyan
 
Write-Section 'Account';         Show-Data $accountInfo
Write-Section 'Status';          Show-Data $statusInfo
Write-Section 'Password';        Show-Data $passwordInfo
Write-Section 'Domain Policy';   Show-Data $policyInfo
Write-Section 'Groups';          Write-Host ($groups -join ', ')
 
# ---------------------------------------------------- Lockout source (4740)
$lockoutEvents = @()
if ($IncludeLockoutSource) {
    Write-Section 'Lockout Source (event 4740)'
    $winEventArgs = @{ FilterHashtable = @{ LogName = 'Security'; Id = 4740 }; MaxEvents = 500; ErrorAction = 'Stop' }
    if ($pdc -notlike "$env:COMPUTERNAME*") { $winEventArgs.ComputerName = $pdc }
 
    try {
        $lockoutEvents = @(foreach ($e in Get-WinEvent @winEventArgs) {
            $data = @{}
            foreach ($d in ([xml]$e.ToXml()).Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
            if ($data['TargetUserName'] -eq $user.SamAccountName) {
                # In event 4740, TargetDomainName holds the caller computer name.
                [PSCustomObject]@{ Time = $e.TimeCreated; LockedBy = $data['TargetDomainName'] }
            }
        })
    }
    catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
            Write-Host "Could not read the Security log: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
 
    if ($lockoutEvents) {
        Write-Host (($lockoutEvents | Select-Object -First 5 | Format-Table -AutoSize | Out-String).Trim())
        Write-Host "Most recent lockout came from: $($lockoutEvents[0].LockedBy)" -ForegroundColor Yellow
    }
    else {
        Write-Host 'No lockout events found for this user.'
    }
}
 
Write-Section 'Diagnosis'
if ($warnings.Count -eq 0) {
    Write-Host 'No problems found. The account can sign in.' -ForegroundColor Green
}
else {
    foreach ($w in $warnings) { Write-Host "[!] $w" -ForegroundColor Yellow }
}
 
# ------------------------------------------------------------------ Unlock
if ($Unlock) {
    Write-Section 'Unlock'
    if (-not $user.LockedOut) {
        Write-Host 'Account is not locked out. Nothing to unlock.'
    }
    elseif ($PSCmdlet.ShouldProcess($user.SamAccountName, 'Unlock Active Directory account')) {
        Unlock-ADAccount -Identity $user -Server $pdc -ErrorAction Stop
        $check = Get-ADUser -Identity $user -Properties LockedOut -Server $pdc
 
        if (-not $check.LockedOut) {
            Write-Host "Account $($user.SamAccountName) is now unlocked." -ForegroundColor Green
 
            # Audit trail: who unlocked whom, and when.
            try {
                $logDir = Join-Path $PSScriptRoot 'Logs'
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
                $line = '{0} | {1}\{2} unlocked {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:USERDOMAIN, $env:USERNAME, $user.SamAccountName
                Add-Content -Path (Join-Path $logDir 'unlock-history.log') -Value $line
                Write-Host "Logged to $logDir\unlock-history.log" -ForegroundColor Gray
            }
            catch {
                Write-Warning "Unlocked, but could not write the log: $($_.Exception.Message)"
            }
        }
        else {
            Write-Host 'Unlock was sent but the account still shows as locked. Check replication and try again.' -ForegroundColor Red
        }
    }
 
    if (-not $user.Enabled) {
        Write-Host 'Note: the account is DISABLED. -Unlock never enables accounts; that needs approval.' -ForegroundColor Yellow
    }
}
 
if ($PassThru) {
    [PSCustomObject]@{
        Account        = $accountInfo
        Status         = $statusInfo
        Password       = $passwordInfo
        Groups         = $groups
        LockoutEvents  = $lockoutEvents
        Warnings       = $warnings.ToArray()
    }
}
