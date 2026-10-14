<#
.SYNOPSIS
    Windows 11 defensive toolkit against AI-orchestrated autonomous attack frameworks
    (nmap/masscan recon -> Nuclei/sqlmap scanning -> Metasploit exploitation ->
    Hydra/John credential attacks -> SSH/WinRM command execution).

.DESCRIPTION
    One script, six actions:

      Audit          Read-only. Checks the host against the baseline and prints PASS/FAIL.
      Harden         Applies the baseline. Every change is recorded so Undo can revert it.
      Monitor        Detects scans, brute force, PsExec-style service installs, new accounts,
                     attacker tooling and reverse-shell connections. Optionally auto-blocks.
      InstallMonitor Registers a SYSTEM scheduled task that runs Monitor periodically.
      RemoveMonitor  Removes that scheduled task.
      Undo           Reverts everything Harden changed and removes this script's firewall rules.

    Run from an elevated PowerShell (Windows PowerShell 5.1 or PowerShell 7).

.EXAMPLE
    .\AiAttackCounter.ps1                                   # audit only
.EXAMPLE
    .\AiAttackCounter.ps1 -Action Harden -DryRun            # preview every change
.EXAMPLE
    .\AiAttackCounter.ps1 -Action Harden -KeepRemoteAdmin -TrustedAddresses 192.168.1.0/24
.EXAMPLE
    .\AiAttackCounter.ps1 -Action InstallMonitor -AutoBlock
.EXAMPLE
    .\AiAttackCounter.ps1 -Action Undo
#>
[CmdletBinding()]
param(
    [ValidateSet('Audit', 'Harden', 'Monitor', 'InstallMonitor', 'RemoveMonitor', 'Undo')]
    [string]$Action = 'Audit',

    # Keep RDP / WinRM / SSH / WMI / remote service management usable, but only from -TrustedAddresses.
    [switch]$KeepRemoteAdmin,
    # Keep SMB file sharing usable, but only from -TrustedAddresses.
    [switch]$KeepFileSharing,
    # Do not block inbound ping (ICMP echo).
    [switch]$AllowPing,
    # Remote addresses allowed to reach kept services. Firewall syntax: LocalSubnet, 10.0.0.0/24, 192.168.1.5 ...
    [string[]]$TrustedAddresses = @('LocalSubnet'),

    [switch]$SkipDefender,
    [switch]$SkipAccountPolicy,
    [ValidateSet('Enabled', 'AuditMode')]
    [string]$AsrMode = 'Enabled',

    # Monitor options
    [switch]$AutoBlock,
    [string[]]$NeverBlock = @(),
    [int]$WindowMinutes = 15,
    [int]$ScanPortThreshold = 15,
    [int]$FailedLogonThreshold = 5,
    [int]$BlockHours = 24,
    [int]$IntervalMinutes = 5,

    [switch]$DryRun,
    [switch]$Force,
    [string]$StatePath = (Join-Path $(if ($env:ProgramData) { $env:ProgramData } else { [IO.Path]::GetTempPath() }) 'AiAttackCounter')
)

$ErrorActionPreference = 'Stop'

$script:GroupName   = 'AiAttackCounter'
$script:TaskName    = 'AiAttackCounter-Monitor'
$script:EventSource = 'AiAttackCounter'
$script:StateFile   = Join-Path $StatePath 'state.json'
$script:MonitorFile = Join-Path $StatePath 'monitor-state.json'
$script:AlertFile   = Join-Path $StatePath 'alerts.jsonl'
$script:Changes     = [ordered]@{}
$script:Results     = New-Object System.Collections.Generic.List[object]
$script:Apply       = ($Action -eq 'Harden')

$TrustedAddresses = @($TrustedAddresses | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$NeverBlock       = @($NeverBlock | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

function Add-Result {
    param([string]$Category, [string]$Name, [string]$Status, [string]$Detail = '')
    $script:Results.Add([pscustomobject]@{ Category = $Category; Name = $Name; Status = $Status; Detail = $Detail })
    $color = switch ($Status) {
        'PASS'     { 'Green' }
        'FIXED'    { 'Cyan' }
        'WOULD-FIX' { 'Cyan' }
        'FAIL'     { 'Red' }
        'WARN'     { 'Yellow' }
        'ERROR'    { 'Magenta' }
        default    { 'Gray' }
    }
    $line = '[{0,-9}] {1,-14} {2}' -f $Status, $Category, $Name
    if ($Detail) { $line += "  -- $Detail" }
    Write-Host $line -ForegroundColor $color
}

function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host ("=== {0} ===" -f $Title) -ForegroundColor White
}

function Test-Admin {
    if ($IsLinux -or $IsMacOS) { return $false }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-StateDir {
    if (-not (Test-Path -LiteralPath $StatePath)) {
        New-Item -ItemType Directory -Path $StatePath -Force | Out-Null
    }
    # SYSTEM executes a copy of this script from here, so only SYSTEM and Administrators may write to it.
    & icacls.exe $StatePath /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
}

# ---------------------------------------------------------------------------
# State / undo journal
# ---------------------------------------------------------------------------

function Import-State {
    $script:Changes = [ordered]@{}
    if (Test-Path -LiteralPath $script:StateFile) {
        $obj = Get-Content -LiteralPath $script:StateFile -Raw | ConvertFrom-Json
        foreach ($c in @($obj.changes)) { $script:Changes[$c.key] = $c }
    }
}

function Save-State {
    Initialize-StateDir
    $doc = [pscustomobject]@{
        version = 1
        updated = (Get-Date).ToString('o')
        changes = @($script:Changes.Values)
    }
    $doc | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:StateFile -Encoding UTF8
}

# First write wins, so repeated Harden runs never overwrite the original values Undo must restore.
function Save-Change {
    param([string]$Key, [hashtable]$Record)
    if ($script:Changes.Contains($Key)) { return }
    $Record['key'] = $Key
    $script:Changes[$Key] = [pscustomobject]$Record
    Save-State
}

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

function Get-RegValue {
    param([string]$Path, [string]$Name)
    $r = [pscustomobject]@{ Exists = $false; Value = $null; Kind = $null }
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($key.GetValueNames() -contains $Name) {
            $r.Exists = $true
            $r.Value  = $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
            $r.Kind   = $key.GetValueKind($Name).ToString()
        }
    } catch { }
    $r
}

function Test-ValueEqual($A, $B) {
    if ($A -is [array] -or $B -is [array]) { return ((@($A) -join '|') -eq (@($B) -join '|')) }
    return ("$A" -eq "$B")
}

function Confirm-Reg {
    param([string]$Category, [string]$Path, [string]$Name, $Value, [string]$Desc, [string]$Type = 'DWord')
    $cur = Get-RegValue $Path $Name
    if ($cur.Exists -and (Test-ValueEqual $cur.Value $Value)) {
        Add-Result $Category $Desc 'PASS'; return
    }
    $curText = if ($cur.Exists) { "$($cur.Value)" } else { '<not set>' }
    $detail = "$Path\$Name is $curText, want $Value"
    if (-not $script:Apply) { Add-Result $Category $Desc 'FAIL' $detail; return }
    if ($DryRun) { Add-Result $Category $Desc 'WOULD-FIX' $detail; return }
    try {
        Save-Change "reg|$Path|$Name" @{ type = 'registry'; path = $Path; name = $Name; existed = $cur.Exists; value = $cur.Value; kind = $cur.Kind }
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        Add-Result $Category $Desc 'FIXED' "$Name = $Value"
    } catch { Add-Result $Category $Desc 'ERROR' $_.Exception.Message }
}

function Get-RegistryBaseline {
    $lsa    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $srv    = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $wks    = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $ts     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdp    = "$ts\WinStations\RDP-Tcp"
    $winrm  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM'
    $sys    = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $expl   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $tcp4   = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    $tcp6   = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'

    $list = New-Object System.Collections.Generic.List[hashtable]
    function Add-Baseline($c, $p, $n, $v, $d) { $list.Add(@{ Category = $c; Path = $p; Name = $n; Value = $v; Desc = $d }) }

    # Credential attacks (Hydra, John, Metasploit post-exploitation, pass-the-hash)
    Add-Baseline 'Credentials' $lsa 'RunAsPPL' 1 'LSA runs as protected process (blocks LSASS dumping)'
    Add-Baseline 'Credentials' $lsa 'LmCompatibilityLevel' 5 'NTLMv2 only, refuse LM and NTLMv1'
    Add-Baseline 'Credentials' $lsa 'NoLMHash' 1 'Do not store LM password hashes'
    Add-Baseline 'Credentials' $lsa 'RestrictAnonymous' 1 'Restrict anonymous enumeration'
    Add-Baseline 'Credentials' $lsa 'RestrictAnonymousSAM' 1 'Block anonymous SAM enumeration'
    Add-Baseline 'Credentials' $lsa 'EveryoneIncludesAnonymous' 0 'Everyone group excludes anonymous'
    Add-Baseline 'Credentials' $lsa 'LimitBlankPasswordUse' 1 'Blank passwords cannot be used over the network'
    Add-Baseline 'Credentials' 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 'WDigest does not cache cleartext passwords'
    Add-Baseline 'Credentials' $sys 'LocalAccountTokenFilterPolicy' 0 'Remote token filtering for local admins (blocks pass-the-hash)'
    Add-Baseline 'Credentials' $sys 'EnableLUA' 1 'User Account Control enabled'

    # Reconnaissance / lateral movement surface
    Add-Baseline 'Network' $srv 'SMB1' 0 'SMBv1 server disabled'
    Add-Baseline 'Network' $srv 'RequireSecuritySignature' 1 'SMB server requires signing'
    Add-Baseline 'Network' $srv 'EnableSecuritySignature' 1 'SMB server signing enabled'
    Add-Baseline 'Network' $srv 'RestrictNullSessAccess' 1 'SMB null sessions restricted'
    Add-Baseline 'Network' $wks 'RequireSecuritySignature' 1 'SMB client requires signing'
    Add-Baseline 'Network' $wks 'EnableSecuritySignature' 1 'SMB client signing enabled'
    Add-Baseline 'Network' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 'LLMNR disabled (stops Responder-style poisoning)'
    Add-Baseline 'Network' 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS' 0 'mDNS disabled'
    Add-Baseline 'Network' $tcp4 'DisableIPSourceRouting' 2 'IPv4 source routing disabled'
    Add-Baseline 'Network' $tcp4 'EnableICMPRedirect' 0 'ICMP redirects ignored'
    Add-Baseline 'Network' $tcp6 'DisableIPSourceRouting' 2 'IPv6 source routing disabled'

    $netbt = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    if (Test-Path -LiteralPath $netbt) {
        foreach ($k in Get-ChildItem -LiteralPath $netbt -ErrorAction SilentlyContinue) {
            Add-Baseline 'Network' $k.PSPath.Replace('Microsoft.PowerShell.Core\Registry::', 'Registry::') 'NetbiosOptions' 2 "NetBIOS over TCP/IP disabled ($($k.PSChildName))"
        }
    }

    # Remote access (SSH / WinRM / RDP are the framework's command-execution channels)
    Add-Baseline 'RemoteAccess' $rdp 'UserAuthentication' 1 'RDP requires Network Level Authentication'
    Add-Baseline 'RemoteAccess' $rdp 'SecurityLayer' 2 'RDP uses TLS security layer'
    Add-Baseline 'RemoteAccess' "$winrm\Service" 'AllowBasic' 0 'WinRM service refuses Basic auth'
    Add-Baseline 'RemoteAccess' "$winrm\Service" 'AllowUnencryptedTraffic' 0 'WinRM service refuses unencrypted traffic'
    Add-Baseline 'RemoteAccess' "$winrm\Client" 'AllowBasic' 0 'WinRM client refuses Basic auth'
    Add-Baseline 'RemoteAccess' "$winrm\Client" 'AllowUnencryptedTraffic' 0 'WinRM client refuses unencrypted traffic'
    Add-Baseline 'RemoteAccess' 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp' 0 'Remote Assistance disabled'
    if (-not $KeepRemoteAdmin) {
        Add-Baseline 'RemoteAccess' $ts 'fDenyTSConnections' 1 'Inbound RDP disabled'
    }

    # Exploitation delivery and detection
    Add-Baseline 'Exploitation' $expl 'NoDriveTypeAutoRun' 255 'AutoRun disabled on all drives'
    Add-Baseline 'Exploitation' $expl 'NoAutorun' 1 'AutoRun commands disabled'

    # Detection
    Add-Baseline 'Logging' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1 'PowerShell script block logging'
    Add-Baseline 'Logging' "$sys\Audit" 'ProcessCreationIncludeCmdLine_Enabled' 1 'Process creation events include command line'
    $list
}

# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------

function Get-ServiceBaseline {
    $s = New-Object System.Collections.Generic.List[hashtable]
    $s.Add(@{ Name = 'RemoteRegistry'; Desc = 'Remote Registry service disabled' })
    $s.Add(@{ Name = 'SSDPSRV';        Desc = 'SSDP discovery service disabled' })
    $s.Add(@{ Name = 'upnphost';       Desc = 'UPnP device host disabled' })
    $s.Add(@{ Name = 'FDResPub';       Desc = 'Function Discovery Resource Publication disabled' })
    if (-not $KeepRemoteAdmin) {
        $s.Add(@{ Name = 'sshd';  Desc = 'OpenSSH server disabled' })
        $s.Add(@{ Name = 'WinRM'; Desc = 'WinRM service disabled' })
    }
    if (-not $KeepFileSharing) {
        $s.Add(@{ Name = 'LanmanServer'; Desc = 'Server (SMB file sharing, port 445) disabled' })
    }
    $s
}

function Confirm-ServiceDisabled {
    param([string]$Name, [string]$Desc)
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if (-not $svc) { Add-Result 'Services' $Desc 'PASS' 'not installed'; return }
    if ($svc.StartMode -eq 'Disabled' -and $svc.State -ne 'Running') { Add-Result 'Services' $Desc 'PASS'; return }
    $detail = "$Name is $($svc.StartMode)/$($svc.State)"
    if (-not $script:Apply) { Add-Result 'Services' $Desc 'FAIL' $detail; return }
    if ($DryRun) { Add-Result 'Services' $Desc 'WOULD-FIX' $detail; return }
    try {
        Save-Change "svc|$Name" @{ type = 'service'; name = $Name; startMode = $svc.StartMode; wasRunning = ($svc.State -eq 'Running') }
        if ($svc.State -eq 'Running') { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue }
        Set-Service -Name $Name -StartupType Disabled
        Add-Result 'Services' $Desc 'FIXED'
    } catch { Add-Result 'Services' $Desc 'ERROR' $_.Exception.Message }
}

# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------

$script:RemoteAdminGroups = @(
    'Remote Desktop*', 'Windows Remote Management*', 'Windows Management Instrumentation*',
    'Remote Service Management*', 'Remote Event Log Management*', 'Remote Scheduled Tasks Management*',
    'Remote Volume Management*', 'Remote Event Monitor*', 'Remote Shutdown*', 'Windows Firewall Remote Management*',
    'OpenSSH*', 'COM+ Network Access*', 'COM+ Remote Administration*', 'Distributed Transaction Coordinator*',
    'Performance Logs and Alerts*', 'Netlogon Service*'
)
$script:FileSharingGroups = @('File and Printer Sharing*')
$script:AlwaysOffGroups   = @(
    'Network Discovery*', 'mDNS*', 'Remote Assistance*', 'Wireless Portable Devices*',
    'Cast to Device*', 'Proximity Sharing*', 'Windows Peer to Peer Collaboration*'
)

function Test-GroupMatch([string]$Group, [string[]]$Patterns) {
    if (-not $Group) { return $false }
    foreach ($p in $Patterns) { if ($Group -like $p) { return $true } }
    return $false
}

function Confirm-FirewallProfiles {
    foreach ($p in Get-NetFirewallProfile) {
        $logFile = $p.LogFileName
        $logOk   = ($logFile -and "$logFile" -ne 'NotConfigured')
        $ok = ("$($p.Enabled)" -eq 'True') -and ("$($p.DefaultInboundAction)" -eq 'Block') -and ("$($p.LogBlocked)" -eq 'True') -and $logOk
        $name = "Firewall profile $($p.Name): enabled, inbound default Block, dropped packets logged"
        if ($ok) { Add-Result 'Firewall' $name 'PASS'; continue }
        $detail = "enabled=$($p.Enabled) inbound=$($p.DefaultInboundAction) logBlocked=$($p.LogBlocked)"
        if (-not $script:Apply) { Add-Result 'Firewall' $name 'FAIL' $detail; continue }
        if ($DryRun) { Add-Result 'Firewall' $name 'WOULD-FIX' $detail; continue }
        try {
            Save-Change "fwprofile|$($p.Name)" @{
                type = 'fwprofile'; name = $p.Name; enabled = "$($p.Enabled)"; inbound = "$($p.DefaultInboundAction)"
                logBlocked = "$($p.LogBlocked)"; logFile = "$($p.LogFileName)"; logSize = [int]$p.LogMaxSizeKilobytes
            }
            $set = @{ Name = $p.Name; Enabled = 'True'; DefaultInboundAction = 'Block'; LogBlocked = 'True'; LogMaxSizeKilobytes = 16384 }
            if (-not $logOk) { $set.LogFileName = '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log' }
            Set-NetFirewallProfile @set
            Add-Result 'Firewall' $name 'FIXED'
        } catch { Add-Result 'Firewall' $name 'ERROR' $_.Exception.Message }
    }
}

function Confirm-FirewallExposure {
    $patterns = @($script:AlwaysOffGroups)
    $scoped   = @()
    if ($KeepRemoteAdmin) { $scoped += $script:RemoteAdminGroups } else { $patterns += $script:RemoteAdminGroups }
    if ($KeepFileSharing) { $scoped += $script:FileSharingGroups } else { $patterns += $script:FileSharingGroups }

    $rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -ErrorAction SilentlyContinue)
    $offHits = 0; $scopeHits = 0; $problems = 0
    foreach ($r in $rules) {
        $wantOff   = Test-GroupMatch $r.DisplayGroup $patterns
        $wantScope = (-not $wantOff) -and (Test-GroupMatch $r.DisplayGroup $scoped)
        if (-not ($wantOff -or $wantScope)) { continue }
        $remote = @((Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r).RemoteAddress)

        if ($wantOff) {
            $offHits++
            if ("$($r.Enabled)" -ne 'True') { continue }
            $label = "Inbound rule disabled: $($r.DisplayName)"
            if (-not $script:Apply) { Add-Result 'Firewall' $label 'FAIL' "group '$($r.DisplayGroup)'"; $problems++; continue }
            if ($DryRun) { Add-Result 'Firewall' $label 'WOULD-FIX'; continue }
            try {
                Save-Change "fwrule|$($r.Name)" @{ type = 'fwrule'; name = $r.Name; enabled = "$($r.Enabled)"; remote = $remote }
                Disable-NetFirewallRule -Name $r.Name
                Add-Result 'Firewall' $label 'FIXED'
            } catch { Add-Result 'Firewall' $label 'ERROR' $_.Exception.Message }
        } else {
            $scopeHits++
            if ("$($r.Enabled)" -ne 'True') { continue }
            if (Test-ValueEqual ($remote | Sort-Object) ($TrustedAddresses | Sort-Object)) { continue }
            $label = "Inbound rule scoped to trusted addresses: $($r.DisplayName)"
            $detail = "remote scope is $($remote -join ',')"
            if (-not $script:Apply) { Add-Result 'Firewall' $label 'FAIL' $detail; $problems++; continue }
            if ($DryRun) { Add-Result 'Firewall' $label 'WOULD-FIX' $detail; continue }
            try {
                Save-Change "fwrule|$($r.Name)" @{ type = 'fwrule'; name = $r.Name; enabled = "$($r.Enabled)"; remote = $remote }
                Set-NetFirewallRule -Name $r.Name -RemoteAddress $TrustedAddresses
                Add-Result 'Firewall' $label 'FIXED' ($TrustedAddresses -join ',')
            } catch { Add-Result 'Firewall' $label 'ERROR' $_.Exception.Message }
        }
    }
    if ($problems -eq 0 -and ($offHits + $scopeHits) -gt 0) { Add-Result 'Firewall' 'Remote-management and discovery inbound rules' 'PASS' }
    if (($offHits + $scopeHits) -eq 0) {
        Add-Result 'Firewall' 'Remote-management rule groups' 'INFO' 'no matching rule groups found (non-English Windows display names?)'
    }
}

function Get-BlockRuleSet {
    $sets = New-Object System.Collections.Generic.List[hashtable]
    $sets.Add(@{ Id = 'legacy-tcp'; Desc = 'Block Telnet, RPC mapper, NetBIOS session (TCP)'; Protocol = 'TCP'; Ports = @('23', '135', '139') })
    $sets.Add(@{ Id = 'legacy-udp'; Desc = 'Block NetBIOS name/datagram, SSDP, mDNS, LLMNR (UDP)'; Protocol = 'UDP'; Ports = @('137', '138', '1900', '5353', '5355') })
    if (-not $KeepFileSharing)  { $sets.Add(@{ Id = 'smb';  Desc = 'Block inbound SMB (445)'; Protocol = 'TCP'; Ports = @('445') }) }
    if (-not $KeepRemoteAdmin) {
        $sets.Add(@{ Id = 'remote-tcp'; Desc = 'Block inbound SSH, RDP, WinRM (TCP)'; Protocol = 'TCP'; Ports = @('22', '3389', '5985', '5986') })
        $sets.Add(@{ Id = 'remote-udp'; Desc = 'Block inbound RDP (UDP)'; Protocol = 'UDP'; Ports = @('3389') })
    }
    if (-not $AllowPing) {
        $sets.Add(@{ Id = 'icmp4'; Desc = 'Block inbound ping (ICMPv4 echo)'; Protocol = 'ICMPv4'; IcmpType = '8' })
        $sets.Add(@{ Id = 'icmp6'; Desc = 'Block inbound ping (ICMPv6 echo)'; Protocol = 'ICMPv6'; IcmpType = '128' })
    }
    $sets
}

function Confirm-FirewallBlockRules {
    foreach ($b in Get-BlockRuleSet) {
        $name = "$($script:GroupName)-Block-$($b.Id)"
        if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) { Add-Result 'Firewall' $b.Desc 'PASS'; continue }
        if (-not $script:Apply) { Add-Result 'Firewall' $b.Desc 'FAIL' "rule $name missing"; continue }
        if ($DryRun) { Add-Result 'Firewall' $b.Desc 'WOULD-FIX'; continue }
        try {
            $p = @{
                Name = $name; DisplayName = "AiAttackCounter: $($b.Desc)"; Group = $script:GroupName
                Direction = 'Inbound'; Action = 'Block'; Protocol = $b.Protocol; Profile = 'Any'
            }
            if ($b.Ports)    { $p.LocalPort = $b.Ports }
            if ($b.IcmpType) { $p.IcmpType = $b.IcmpType }
            New-NetFirewallRule @p | Out-Null
            Save-Change "fwnew|$name" @{ type = 'fwnew'; name = $name }
            Add-Result 'Firewall' $b.Desc 'FIXED'
        } catch { Add-Result 'Firewall' $b.Desc 'ERROR' $_.Exception.Message }
    }
}

# ---------------------------------------------------------------------------
# Account policy (Hydra / John mitigation)
# ---------------------------------------------------------------------------

function Get-LocalSecurityPolicy {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "aac-secpol-$PID.inf"
    try {
        & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY | Out-Null
        $text = Get-Content -LiteralPath $tmp -Raw
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    $p = @{}
    foreach ($k in 'MinimumPasswordLength', 'LockoutBadCount', 'ResetLockoutCount', 'LockoutDuration') {
        if ($text -match "(?m)^\s*$k\s*=\s*(-?\d+)") { $p[$k] = [int]$Matches[1] }
    }
    $p
}

function Confirm-AccountPolicy {
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        Add-Result 'Accounts' 'Local account policy' 'INFO' 'domain-joined: password and lockout policy come from Group Policy'
    } else {
        $pol = Get-LocalSecurityPolicy
        $needLock = (-not $pol.ContainsKey('LockoutBadCount')) -or $pol.LockoutBadCount -eq 0 -or $pol.LockoutBadCount -gt 10
        $needLen  = (-not $pol.ContainsKey('MinimumPasswordLength')) -or $pol.MinimumPasswordLength -lt 14
        $lockDesc = 'Account lockout after 5 bad passwords for 30 min (throttles Hydra)'
        $lenDesc  = 'Minimum password length 14 (slows John/hash cracking)'

        if ($needLock) {
            $detail = "LockoutBadCount=$($pol.LockoutBadCount)"
            if (-not $script:Apply) { Add-Result 'Accounts' $lockDesc 'FAIL' $detail }
            elseif ($DryRun) { Add-Result 'Accounts' $lockDesc 'WOULD-FIX' $detail }
            else {
                try {
                    Save-Change 'acct|lockout' @{ type = 'acctpolicy'; part = 'lockout'; threshold = $pol.LockoutBadCount; window = $pol.ResetLockoutCount; duration = $pol.LockoutDuration }
                    & net.exe accounts /lockoutthreshold:5 /lockoutwindow:30 /lockoutduration:30 | Out-Null
                    Add-Result 'Accounts' $lockDesc 'FIXED'
                } catch { Add-Result 'Accounts' $lockDesc 'ERROR' $_.Exception.Message }
            }
        } else { Add-Result 'Accounts' $lockDesc 'PASS' }

        if ($needLen) {
            $detail = "MinimumPasswordLength=$($pol.MinimumPasswordLength)"
            if (-not $script:Apply) { Add-Result 'Accounts' $lenDesc 'FAIL' $detail }
            elseif ($DryRun) { Add-Result 'Accounts' $lenDesc 'WOULD-FIX' $detail }
            else {
                try {
                    Save-Change 'acct|minlen' @{ type = 'acctpolicy'; part = 'minlen'; minlen = $pol.MinimumPasswordLength }
                    & net.exe accounts /minpwlen:14 | Out-Null
                    Add-Result 'Accounts' $lenDesc 'FIXED'
                } catch { Add-Result 'Accounts' $lenDesc 'ERROR' $_.Exception.Message }
            }
        } else { Add-Result 'Accounts' $lenDesc 'PASS' }
    }

    $guest = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -First 1
    if ($guest) {
        $desc = 'Guest account disabled'
        if (-not $guest.Enabled) { Add-Result 'Accounts' $desc 'PASS' }
        elseif (-not $script:Apply) { Add-Result 'Accounts' $desc 'FAIL' }
        elseif ($DryRun) { Add-Result 'Accounts' $desc 'WOULD-FIX' }
        else {
            try {
                Save-Change "user|$($guest.SID.Value)" @{ type = 'localuser'; name = $guest.Name; enabled = $true }
                Disable-LocalUser -Name $guest.Name
                Add-Result 'Accounts' $desc 'FIXED'
            } catch { Add-Result 'Accounts' $desc 'ERROR' $_.Exception.Message }
        }
    }

    foreach ($u in Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -and -not $_.PasswordRequired }) {
        Add-Result 'Accounts' "Enabled local account '$($u.Name)' does not require a password" 'WARN' 'set a password (Hydra tries blank passwords first)'
    }
}

# ---------------------------------------------------------------------------
# Audit policy (so Monitor has events to read)
# ---------------------------------------------------------------------------

$script:AuditSubcategories = [ordered]@{
    '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'Logon'
    '{0CCE9217-69AE-11D9-BED3-505054503030}' = 'Account Lockout'
    '{0CCE921B-69AE-11D9-BED3-505054503030}' = 'Special Logon'
    '{0CCE922B-69AE-11D9-BED3-505054503030}' = 'Process Creation'
    '{0CCE923F-69AE-11D9-BED3-505054503030}' = 'Credential Validation'
    '{0CCE9235-69AE-11D9-BED3-505054503030}' = 'User Account Management'
    '{0CCE9237-69AE-11D9-BED3-505054503030}' = 'Security Group Management'
}

function Test-AuditSubcategory([string]$Guid) {
    $csv = & auditpol.exe /get /subcategory:$Guid /r 2>$null | ConvertFrom-Csv
    $setting = "$(@($csv)[0].'Inclusion Setting')"
    # auditpol prints localised text, so on non-English Windows this reports false and Harden simply
    # re-applies the (idempotent) setting.
    return ($setting -match 'Success' -and $setting -match 'Failure')
}

function Confirm-AuditPolicy {
    $backup = Join-Path $StatePath 'auditpol-backup.csv'
    foreach ($guid in $script:AuditSubcategories.Keys) {
        $desc = "Audit success+failure: $($script:AuditSubcategories[$guid])"
        $ok = $false
        try { $ok = Test-AuditSubcategory $guid } catch { }
        if ($ok) { Add-Result 'Logging' $desc 'PASS'; continue }
        if (-not $script:Apply) { Add-Result 'Logging' $desc 'FAIL'; continue }
        if ($DryRun) { Add-Result 'Logging' $desc 'WOULD-FIX'; continue }
        try {
            if (-not $script:Changes.Contains('auditpol')) {
                Initialize-StateDir
                & auditpol.exe /backup /file:$backup | Out-Null
                Save-Change 'auditpol' @{ type = 'auditpol'; file = $backup }
            }
            & auditpol.exe /set /subcategory:$guid /success:enable /failure:enable | Out-Null
            Add-Result 'Logging' $desc 'FIXED'
        } catch { Add-Result 'Logging' $desc 'ERROR' $_.Exception.Message }
    }
}

# ---------------------------------------------------------------------------
# Microsoft Defender, ASR, SMB1, exploit protection
# ---------------------------------------------------------------------------

$script:DefenderPrefs = [ordered]@{
    DisableRealtimeMonitoring           = $false
    DisableBehaviorMonitoring           = $false
    DisableIOAVProtection               = $false
    DisableScriptScanning               = $false
    MAPSReporting                       = 2
    SubmitSamplesConsent                = 1
    CloudBlockLevel                     = 2
    PUAProtection                       = 1
    EnableNetworkProtection             = 1
    CheckForSignaturesBeforeRunningScan = $true
}

# GUID -> description
$script:AsrRules = [ordered]@{
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations from PsExec and WMI commands'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JS/VBS launching downloaded executable content'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Advanced ransomware protection'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block Office apps from creating child processes'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office apps from creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office apps from injecting into other processes'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
}

function ConvertTo-PlainPref($v) {
    if ($v -is [bool]) { return $v }
    if ($v -is [Enum]) { return [int]$v }
    return $v
}

function Confirm-Defender {
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        Add-Result 'Defender' 'Microsoft Defender cmdlets' 'WARN' 'not available (third-party AV active?)'; return
    }
    $mp = Get-MpPreference
    foreach ($k in $script:DefenderPrefs.Keys) {
        $want = $script:DefenderPrefs[$k]
        $have = ConvertTo-PlainPref $mp.$k
        $desc = "Defender $k = $want"
        if ("$have" -eq "$want") { Add-Result 'Defender' $desc 'PASS'; continue }
        $detail = "currently $have"
        if (-not $script:Apply) { Add-Result 'Defender' $desc 'FAIL' $detail; continue }
        if ($DryRun) { Add-Result 'Defender' $desc 'WOULD-FIX' $detail; continue }
        try {
            Save-Change "mp|$k" @{ type = 'defender'; name = $k; value = $have }
            $splat = @{ $k = $want }
            Set-MpPreference @splat
            $after = ConvertTo-PlainPref ((Get-MpPreference).$k)
            if ("$after" -eq "$want") { Add-Result 'Defender' $desc 'FIXED' }
            else { Add-Result 'Defender' $desc 'WARN' 'value did not change (Tamper Protection or policy is enforcing it)' }
        } catch { Add-Result 'Defender' $desc 'ERROR' $_.Exception.Message }
    }

    $ids = @($mp.AttackSurfaceReductionRules_Ids)
    $act = @($mp.AttackSurfaceReductionRules_Actions)
    $current = @{}
    for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i]) { $current["$($ids[$i])".ToLower()] = [int]$act[$i] } }
    $wantName = $AsrMode
    foreach ($id in $script:AsrRules.Keys) {
        $desc = "ASR rule: $($script:AsrRules[$id])"
        $have = if ($current.ContainsKey($id)) { $current[$id] } else { $null }
        # 1 = Block, 6 = Warn, 2 = Audit. Never downgrade a rule that already blocks.
        if ($have -eq 1 -or $have -eq 6 -or ($AsrMode -eq 'AuditMode' -and $have -eq 2)) { Add-Result 'Defender' $desc 'PASS'; continue }
        $detail = if ($null -eq $have) { 'not configured' } else { "action $have" }
        if (-not $script:Apply) { Add-Result 'Defender' $desc 'FAIL' $detail; continue }
        if ($DryRun) { Add-Result 'Defender' $desc 'WOULD-FIX' "$detail -> $wantName"; continue }
        try {
            Save-Change "asr|$id" @{ type = 'asr'; id = $id; action = $have }
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $wantName
            Add-Result 'Defender' $desc 'FIXED' $wantName
        } catch { Add-Result 'Defender' $desc 'ERROR' $_.Exception.Message }
    }

    $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($status) {
        if ($status.IsTamperProtected) { Add-Result 'Defender' 'Tamper Protection' 'PASS' }
        else { Add-Result 'Defender' 'Tamper Protection' 'WARN' 'turn it on in Windows Security > Virus & threat protection settings (cannot be set by script)' }
        if ($status.AntivirusSignatureAge -gt 3) { Add-Result 'Defender' 'Signature freshness' 'WARN' "signatures are $($status.AntivirusSignatureAge) days old" }
        else { Add-Result 'Defender' 'Signature freshness' 'PASS' }
    }
}

function Confirm-Smb1 {
  #  if (-not (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue)) { return }
  #  $cfg = Get-SmbServerConfiguration
   # $desc = 'SMBv1 protocol disabled'
   # if (-not $cfg.EnableSMB1Protocol) { Add-Result 'Network' $desc 'PASS'; return }
   # if (-not $script:Apply) { Add-Result 'Network' $desc 'FAIL'; return }
   # if ($DryRun) { Add-Result 'Network' $desc 'WOULD-FIX'; return }
   # try {
   #     Save-Change 'smb1' @{ type = 'smb1'; enabled = $true }
   #     Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
   #     Add-Result 'Network' $desc 'FIXED'
   # } catch { Add-Result 'Network' $desc 'ERROR' $_.Exception.Message }
}

function Confirm-ExploitProtection {
    if (-not (Get-Command Get-ProcessMitigation -ErrorAction SilentlyContinue)) { return }
    $m = Get-ProcessMitigation -System
    $items = [ordered]@{
        DEP         = "$($m.DEP.Enable)"
        SEHOP       = "$($m.SEHOP.Enable)"
        BottomUp    = "$($m.ASLR.BottomUp)"
        HighEntropy = "$($m.ASLR.HighEntropy)"
    }
    foreach ($k in $items.Keys) {
        $desc = "Exploit protection (system-wide): $k"
        if ($items[$k] -eq 'ON') { Add-Result 'Exploitation' $desc 'PASS'; continue }
        if (-not $script:Apply) { Add-Result 'Exploitation' $desc 'FAIL' "state $($items[$k])"; continue }
        if ($DryRun) { Add-Result 'Exploitation' $desc 'WOULD-FIX'; continue }
        try {
            Save-Change "mitigation|$k" @{ type = 'mitigation'; name = $k }
            Set-ProcessMitigation -System -Enable $k
            Add-Result 'Exploitation' $desc 'FIXED'
        } catch { Add-Result 'Exploitation' $desc 'ERROR' $_.Exception.Message }
    }
}

# ---------------------------------------------------------------------------
# Read-only posture checks (Audit and Harden report these, never change them)
# ---------------------------------------------------------------------------

$script:RiskyPorts = @{
    21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 135 = 'RPC'; 139 = 'NetBIOS'; 445 = 'SMB'; 1433 = 'MSSQL'; 3306 = 'MySQL'
    3389 = 'RDP'; 5432 = 'PostgreSQL'; 5900 = 'VNC'; 5985 = 'WinRM'; 5986 = 'WinRM-TLS'; 6379 = 'Redis'
    9200 = 'Elasticsearch'; 11434 = 'Ollama'; 27017 = 'MongoDB'
}

function Get-ExposedListeners {
    $out = @()
    foreach ($c in Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue) {
        if ($c.LocalAddress -in '127.0.0.1', '::1') { continue }
        $proc = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        $out += [pscustomobject]@{ Address = $c.LocalAddress; Port = [int]$c.LocalPort; Process = $proc }
    }
    $out | Sort-Object Port -Unique
}

function Test-Posture {
    Write-Section 'Posture checks (read-only)'
    foreach ($l in Get-ExposedListeners) {
        if ($script:RiskyPorts.ContainsKey($l.Port)) {
            Add-Result 'Exposure' "Listening on $($l.Address):$($l.Port) ($($script:RiskyPorts[$l.Port]))" 'WARN' "process $($l.Process); reachable by nmap unless firewalled"
        }
    }
    $listeners = @(Get-ExposedListeners)
    Add-Result 'Exposure' 'Non-loopback TCP listeners' 'INFO' "$($listeners.Count) total: $((($listeners | Select-Object -First 15 | ForEach-Object { $_.Port }) -join ', '))"

    $hf = Get-HotFix -ErrorAction SilentlyContinue | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($hf) {
        $age = [int]((Get-Date) - $hf.InstalledOn).TotalDays
        if ($age -gt 45) { Add-Result 'Patching' 'Latest installed update' 'WARN' "$($hf.HotFixID) is $age days old; unpatched CVEs are what Metasploit/Nuclei find first" }
        else { Add-Result 'Patching' 'Latest installed update' 'PASS' "$($hf.HotFixID), $age days old" }
    } else { Add-Result 'Patching' 'Latest installed update' 'INFO' 'could not determine' }

    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        if (@($dg.SecurityServicesRunning) -contains 1) { Add-Result 'Credentials' 'Credential Guard running' 'PASS' }
        else { Add-Result 'Credentials' 'Credential Guard running' 'WARN' 'enable Core isolation > Memory integrity / Credential Guard if hardware supports it' }
    } catch { Add-Result 'Credentials' 'Credential Guard running' 'INFO' 'status unavailable' }

    try {
        if (Confirm-SecureBootUEFI) { Add-Result 'Platform' 'Secure Boot' 'PASS' } else { Add-Result 'Platform' 'Secure Boot' 'WARN' 'disabled' }
    } catch { Add-Result 'Platform' 'Secure Boot' 'INFO' 'not supported or unavailable' }

    try {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ("$($bl.ProtectionStatus)" -eq 'On') { Add-Result 'Platform' 'BitLocker on system drive' 'PASS' }
        else { Add-Result 'Platform' 'BitLocker on system drive' 'WARN' 'off' }
    } catch { Add-Result 'Platform' 'BitLocker on system drive' 'INFO' 'status unavailable' }

    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue)
    Add-Result 'Accounts' 'Local Administrators members' 'INFO' (($admins | ForEach-Object { $_.Name }) -join ', ')
}

# ---------------------------------------------------------------------------
# Harden / Audit driver
# ---------------------------------------------------------------------------

function Invoke-Baseline {
    Write-Section 'Registry baseline'
    foreach ($b in Get-RegistryBaseline) { Confirm-Reg $b.Category $b.Path $b.Name $b.Value $b.Desc }

    Write-Section 'Services'
    foreach ($s in Get-ServiceBaseline) { Confirm-ServiceDisabled $s.Name $s.Desc }

    Write-Section 'Windows Firewall'
    Confirm-FirewallProfiles
    Confirm-FirewallExposure
    Confirm-FirewallBlockRules

    Write-Section 'Network protocols'
    Confirm-Smb1

    if (-not $SkipAccountPolicy) { Write-Section 'Accounts'; Confirm-AccountPolicy }

    Write-Section 'Audit policy'
    Confirm-AuditPolicy

    Write-Section 'Exploit protection'
    Confirm-ExploitProtection

    if (-not $SkipDefender) { Write-Section 'Microsoft Defender'; Confirm-Defender }

    Test-Posture
}

function Show-Summary {
    Write-Section 'Summary'
    $script:Results | Group-Object Status | Sort-Object Name | ForEach-Object { Write-Host ('{0,-10} {1}' -f $_.Name, $_.Count) }
    if ($script:Changes.Count -gt 0 -or $script:Results.Count -gt 0) {
        try {
            Initialize-StateDir
            $dir = Join-Path $StatePath 'reports'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $file = Join-Path $dir ("{0}-{1}.json" -f $Action.ToLower(), (Get-Date -Format 'yyyyMMdd-HHmmss'))
            $script:Results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $file -Encoding UTF8
            Write-Host "Report: $file"
        } catch { }
    }
}

function Invoke-Audit {
    Write-Host 'Read-only audit. Nothing will be changed.' -ForegroundColor Gray
    Invoke-Baseline
    Show-Summary
    $fails = @($script:Results | Where-Object Status -eq 'FAIL').Count
    if ($fails) { Write-Host "`n$fails check(s) failed. Run with -Action Harden -DryRun to preview the fixes." -ForegroundColor Yellow }
}

function Invoke-Harden {
    if (-not $DryRun -and -not $Force) {
        Write-Host 'This changes firewall rules, services, registry security settings, account policy and Defender settings.'
        Write-Host "Every change is journaled to $script:StateFile so -Action Undo can revert it."
        if ((Read-Host 'Continue? (y/N)') -notmatch '^(y|yes)$') { Write-Host 'Aborted.'; return }
        try {
            Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction SilentlyContinue
            Checkpoint-Computer -Description 'AiAttackCounter before Harden' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
            Write-Host 'System restore point created.' -ForegroundColor Gray
        } catch { Write-Host "Restore point skipped: $($_.Exception.Message)" -ForegroundColor DarkGray }
    }
    if (-not $DryRun) { Initialize-StateDir; Import-State }
    try { Invoke-Baseline } finally { if (-not $DryRun -and $script:Changes.Count) { Save-State } }
    Show-Summary
    if ($DryRun) { Write-Host "`nDry run: no changes were made." -ForegroundColor Cyan }
    else {
        Write-Host "`nA reboot is needed for LSA protection and some service changes to take effect." -ForegroundColor Cyan
        Write-Host 'Install continuous detection with: -Action InstallMonitor -AutoBlock'
    }
}

# ---------------------------------------------------------------------------
# Undo
# ---------------------------------------------------------------------------

function Restore-Change($c) {
    switch ($c.type) {
        'registry' {
            if ($c.existed) {
                if (-not (Test-Path -LiteralPath $c.path)) { New-Item -Path $c.path -Force | Out-Null }
                $kind = if ($c.kind) { $c.kind } else { 'DWord' }
                New-ItemProperty -LiteralPath $c.path -Name $c.name -Value $c.value -PropertyType $kind -Force | Out-Null
            } else {
                Remove-ItemProperty -LiteralPath $c.path -Name $c.name -ErrorAction SilentlyContinue
            }
        }
        'service' {
            $start = switch ($c.startMode) { 'Auto' { 'Automatic' } 'Manual' { 'Manual' } 'Disabled' { 'Disabled' } default { 'Manual' } }
            Set-Service -Name $c.name -StartupType $start
            if ($c.wasRunning) { Start-Service -Name $c.name -ErrorAction SilentlyContinue }
        }
        'fwprofile' {
            Set-NetFirewallProfile -Name $c.name -Enabled $c.enabled -DefaultInboundAction $c.inbound -LogBlocked $c.logBlocked -LogMaxSizeKilobytes $c.logSize
            if ($c.logFile -and $c.logFile -ne 'NotConfigured') { Set-NetFirewallProfile -Name $c.name -LogFileName $c.logFile }
        }
        'fwrule' {
            if (Get-NetFirewallRule -Name $c.name -ErrorAction SilentlyContinue) {
                Set-NetFirewallRule -Name $c.name -RemoteAddress @($c.remote)
                if ($c.enabled -eq 'True') { Enable-NetFirewallRule -Name $c.name } else { Disable-NetFirewallRule -Name $c.name }
            }
        }
        'fwnew' { Remove-NetFirewallRule -Name $c.name -ErrorAction SilentlyContinue }
        'acctpolicy' {
            if ($c.part -eq 'minlen') { & net.exe accounts "/minpwlen:$($c.minlen)" | Out-Null }
            else {
                if ([int]$c.threshold -eq 0) { & net.exe accounts /lockoutthreshold:0 | Out-Null }
                else {
                    $dur = if ([int]$c.duration -lt 0) { 0 } else { [int]$c.duration }
                    & net.exe accounts "/lockoutduration:$dur" "/lockoutwindow:$($c.window)" "/lockoutthreshold:$($c.threshold)" | Out-Null
                }
            }
        }
        'localuser' { if ($c.enabled) { Enable-LocalUser -Name $c.name } }
        'auditpol'  { & auditpol.exe /restore /file:$($c.file) | Out-Null }
        'defender'  { $splat = @{ $c.name = $c.value }; Set-MpPreference @splat }
        'asr' {
            if ($null -eq $c.action) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $c.id }
            else {
                $name = switch ([int]$c.action) { 0 { 'Disabled' } 1 { 'Enabled' } 2 { 'AuditMode' } 6 { 'Warn' } default { 'Disabled' } }
                Add-MpPreference -AttackSurfaceReductionRules_Ids $c.id -AttackSurfaceReductionRules_Actions $name
            }
        }
        'smb1'       { Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force }
        'mitigation' { Set-ProcessMitigation -System -Disable $c.name }
    }
}

function Invoke-Undo {
    Import-State
    Write-Section 'Undo'
    $items = @($script:Changes.Values)
    [array]::Reverse($items)
    foreach ($c in $items) {
        $label = "$($c.type): $($c.key)"
        if ($DryRun) { Add-Result 'Undo' $label 'WOULD-FIX'; continue }
        try { Restore-Change $c; Add-Result 'Undo' $label 'FIXED' }
        catch { Add-Result 'Undo' $label 'ERROR' $_.Exception.Message }
    }
    if (-not $DryRun) {
        Get-NetFirewallRule -Group $script:GroupName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Add-Result 'Undo' 'Removed all AiAttackCounter firewall rules (including auto-blocks)' 'FIXED'
        if (Test-Path -LiteralPath $script:StateFile) {
            Move-Item -LiteralPath $script:StateFile -Destination ($script:StateFile + '.' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.undone') -Force
        }
    }
    if ($items.Count -eq 0) { Write-Host 'No journal found; nothing to undo.' -ForegroundColor Yellow }
    Show-Summary
}

# ---------------------------------------------------------------------------
# Detection: pure parsers (unit-tested in tests/)
# ---------------------------------------------------------------------------

# pfirewall.log line: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path
function ConvertFrom-FirewallLogLine {
    param([string]$Line)
    if (-not $Line -or $Line[0] -eq '#') { return $null }
    $f = $Line -split ' '
    if ($f.Count -lt 8) { return $null }
    $time = [datetime]::MinValue
    if (-not [datetime]::TryParseExact("$($f[0]) $($f[1])", 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture, 'None', [ref]$time)) { return $null }
    $dport = 0; [void][int]::TryParse($f[7], [ref]$dport)
    [pscustomobject]@{
        Time     = $time
        Action   = $f[2]
        Protocol = $f[3]
        Src      = $f[4]
        Dst      = $f[5]
        DstPort  = $dport
        Path     = if ($f.Count -ge 17) { $f[16] } else { '' }
    }
}

function Read-FirewallLog {
    param([string]$Path, [datetime]$Since, [int]$MaxBytes = 8MB)
    $entries = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $Path)) { return $entries }
    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite,Delete')
    try {
        if ($fs.Length -gt $MaxBytes) { [void]$fs.Seek(-$MaxBytes, 'End') }
        $sr = New-Object IO.StreamReader($fs)
        if ($fs.Position -gt 0) { [void]$sr.ReadLine() }
        while ($null -ne ($line = $sr.ReadLine())) {
            if ($line.IndexOf(' DROP ') -lt 0) { continue }
            $e = ConvertFrom-FirewallLogLine $line
            if ($e -and $e.Time -ge $Since -and $e.Path -ne 'SEND') { $entries.Add($e) }
        }
    } finally { $fs.Dispose() }
    $entries
}

function Find-PortScans {
    param([object[]]$Entries, [int]$Threshold = 15)
    $Entries | Where-Object { ($_.Protocol -in @('TCP', 'UDP')) -and ($_.DstPort -gt 0) } |
        Group-Object Src | ForEach-Object {
            $ports = @($_.Group | Select-Object -ExpandProperty DstPort -Unique | Sort-Object)
            if ($ports.Count -ge $Threshold) {
                [pscustomobject]@{ Source = $_.Name; PortCount = $ports.Count; Packets = $_.Count; SamplePorts = (($ports | Select-Object -First 12) -join ',') }
            }
        }
}

function Test-RemoteIp([string]$Ip) {
    if (-not $Ip -or $Ip -in '-', '::1', '127.0.0.1', '0.0.0.0', '::') { return $false }
    $addr = $null
    return [ipaddress]::TryParse($Ip, [ref]$addr)
}

function Find-BruteForce {
    param([object[]]$Failed, [int]$Threshold = 5)
    $Failed | Where-Object { Test-RemoteIp $_.Ip } | Group-Object Ip | ForEach-Object {
        if ($_.Count -ge $Threshold) {
            $users = @($_.Group | Select-Object -ExpandProperty User -Unique)
            [pscustomobject]@{
                Source = $_.Name; Attempts = $_.Count; UserCount = $users.Count
                Users = (($users | Select-Object -First 8) -join ',')
                Spraying = ($users.Count -ge 3)
            }
        }
    }
}

$script:AttackToolPattern = '^(nmap|ncat|masscan|hydra|john|sqlmap|nuclei|msfconsole|msfvenom|msfrpcd|responder|mimikatz|crackmapexec|netexec|evil-winrm|chisel|ligolo.*|impacket.*|psexec.*|rubeus|sharphound|bloodhound|nc|nc64)$'
$script:FrameworkCmdPattern = 'ai-auto-attack|ai-attack\s|mcp_servers[./\\]|src\.cli\.commands|msfconsole|sqlmap\.py|nuclei\s+-'

function Get-AttackToolMatch {
    param([string]$ProcessName, [string]$CommandLine)
    $n = ($ProcessName -replace '\.exe$', '')
    if ($n -match $script:AttackToolPattern) { return "tool process '$n'" }
    if ($CommandLine -and $CommandLine -match $script:FrameworkCmdPattern) { return 'command line matches the AI attack framework or a known tool' }
    return $null
}

$script:SuspiciousServicePattern = '%COMSPEC%|cmd(\.exe)?"?\s+/c|powershell|pwsh|ADMIN\$|\\Windows\\Temp\\|\\AppData\\|-enc(odedcommand)?\s|\\\\[^\\]+\\[A-Za-z]\$'

function Test-SuspiciousServiceImage([string]$ImagePath) {
    return ($ImagePath -match $script:SuspiciousServicePattern)
}

# ---------------------------------------------------------------------------
# Detection: Windows event collection
# ---------------------------------------------------------------------------

function Get-EventRecords {
    param([string]$LogName, [int[]]$Id, [datetime]$Since)
    try {
        Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $Id; StartTime = $Since } -ErrorAction Stop
    } catch {
        if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') { Write-Verbose "Event query $LogName/$($Id -join ',') failed: $($_.Exception.Message)" }
        @()
    }
}

function ConvertTo-EventData($EventRecord) {
    $d = @{}
    $xml = [xml]$EventRecord.ToXml()
    foreach ($n in $xml.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = $n.'#text' } }
    $d
}

function Get-FailedLogons([datetime]$Since) {
    foreach ($e in Get-EventRecords 'Security' @(4625) $Since) {
        $d = ConvertTo-EventData $e
        [pscustomobject]@{ Time = $e.TimeCreated; Ip = $d['IpAddress']; User = $d['TargetUserName']; LogonType = $d['LogonType'] }
    }
}

function Get-RemoteSuccessLogons([datetime]$Since) {
    foreach ($e in Get-EventRecords 'Security' @(4624) $Since) {
        $d = ConvertTo-EventData $e
        if ($d['LogonType'] -in '3', '10') {
            [pscustomobject]@{ Time = $e.TimeCreated; Ip = $d['IpAddress']; User = $d['TargetUserName']; LogonType = $d['LogonType'] }
        }
    }
}

# ---------------------------------------------------------------------------
# Alerts and auto-block
# ---------------------------------------------------------------------------

function Get-MonitorState {
    if (Test-Path -LiteralPath $script:MonitorFile) {
        try {
            $o = Get-Content -LiteralPath $script:MonitorFile -Raw | ConvertFrom-Json
            $h = @{}; foreach ($p in $o.alerts.PSObject.Properties) { $h[$p.Name] = $p.Value }
            return $h
        } catch { }
    }
    @{}
}

function Save-MonitorState([hashtable]$Alerts) {
    Initialize-StateDir
    [pscustomobject]@{ alerts = $Alerts } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $script:MonitorFile -Encoding UTF8
}

$script:Seen = @{}
$script:AlertCount = 0

function Send-Alert {
    param([ValidateSet('Info', 'Warning', 'Critical')][string]$Severity, [string]$Title, [string]$Detail, [string]$Key)
    $now = Get-Date
    if ($script:Seen.ContainsKey($Key)) {
        if (($now - [datetime]$script:Seen[$Key]).TotalMinutes -lt 60) { return }
    }
    $script:Seen[$Key] = $now.ToString('o')
    $script:AlertCount++
    $color = switch ($Severity) { 'Critical' { 'Red' } 'Warning' { 'Yellow' } default { 'Gray' } }
    Write-Host ("[{0}] {1}: {2}" -f $Severity.ToUpper(), $Title, $Detail) -ForegroundColor $color

    try {
        Initialize-StateDir
        [pscustomobject]@{ time = $now.ToString('o'); severity = $Severity; title = $Title; detail = $Detail } |
            ConvertTo-Json -Compress | Add-Content -LiteralPath $script:AlertFile -Encoding UTF8
    } catch { }
    try {
        if (-not [Diagnostics.EventLog]::SourceExists($script:EventSource)) { [Diagnostics.EventLog]::CreateEventSource($script:EventSource, 'Application') }
        $type = switch ($Severity) { 'Critical' { 'Error' } 'Warning' { 'Warning' } default { 'Information' } }
        $id   = switch ($Severity) { 'Critical' { 4002 } 'Warning' { 4001 } default { 4000 } }
        [Diagnostics.EventLog]::WriteEntry($script:EventSource, "$Title`n$Detail", $type, $id)
    } catch { }
}

function Get-ProtectedAddresses {
    $set = New-Object System.Collections.Generic.HashSet[string]
    foreach ($a in '127.0.0.1', '::1') { [void]$set.Add($a) }
    foreach ($a in Get-NetIPAddress -ErrorAction SilentlyContinue) { [void]$set.Add("$($a.IPAddress)") }
    foreach ($c in Get-NetIPConfiguration -ErrorAction SilentlyContinue) {
        foreach ($g in @($c.IPv4DefaultGateway) + @($c.IPv6DefaultGateway)) { if ($g) { [void]$set.Add("$($g.NextHop)") } }
        foreach ($d in @($c.DNSServer.ServerAddresses)) { if ($d) { [void]$set.Add("$d") } }
    }
    foreach ($a in $NeverBlock) { [void]$set.Add($a) }
    $set
}

function Add-IpBlock {
    param([string]$Ip, [string]$Reason)
    if (-not (Test-RemoteIp $Ip)) { return }
    if ((Get-ProtectedAddresses).Contains($Ip)) {
        Send-Alert 'Info' 'Auto-block skipped' "$Ip is the local host, gateway, DNS server or in -NeverBlock" "skip|$Ip"; return
    }
    $name = "$($script:GroupName)-AutoBlock-" + ($Ip -replace '[:%]', '_')
    if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) { return }
    $expires = (Get-Date).AddHours($BlockHours).ToString('o')
    New-NetFirewallRule -Name $name -DisplayName "AiAttackCounter auto-block $Ip" -Group $script:GroupName `
        -Direction Inbound -Action Block -RemoteAddress $Ip -Profile Any -Description "expires=$expires;reason=$Reason" | Out-Null
    Send-Alert 'Warning' 'Source auto-blocked' "$Ip blocked inbound for $BlockHours h ($Reason)" "block|$Ip"
}

function Remove-ExpiredBlocks {
    foreach ($r in Get-NetFirewallRule -Group $script:GroupName -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*-AutoBlock-*' }) {
        if ($r.Description -match 'expires=([^;]+)') {
            $exp = [datetime]::MinValue
            if ([datetime]::TryParse($Matches[1], [ref]$exp) -and $exp -lt (Get-Date)) { Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue }
        }
    }
}

# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------

function Get-FirewallLogPath {
    $p = (Get-NetFirewallProfile -Name Public).LogFileName
    if (-not $p -or "$p" -eq 'NotConfigured') { $p = '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log' }
    [Environment]::ExpandEnvironmentVariables("$p")
}

function Invoke-Monitor {
    $since = (Get-Date).AddMinutes(-$WindowMinutes)
    $script:Seen = Get-MonitorState
    Write-Host ("Monitor window: last {0} min (since {1})" -f $WindowMinutes, $since.ToString('u')) -ForegroundColor Gray

    if ($AutoBlock) { Remove-ExpiredBlocks }

    # Reconnaissance: nmap / masscan hitting closed or filtered ports
    try {
        $log = Get-FirewallLogPath
        if (-not (Test-Path -LiteralPath $log)) {
            Send-Alert 'Warning' 'Firewall log missing' "$log not found; run -Action Harden so dropped packets are logged" 'nolog'
        } else {
            foreach ($s in @(Find-PortScans -Entries (Read-FirewallLog -Path $log -Since $since) -Threshold $ScanPortThreshold)) {
                if (-not (Test-RemoteIp $s.Source)) { continue }
                Send-Alert 'Warning' 'Port scan detected' "$($s.Source) probed $($s.PortCount) distinct ports ($($s.Packets) packets) e.g. $($s.SamplePorts)" "scan|$($s.Source)"
                if ($AutoBlock) { Add-IpBlock $s.Source 'port scan' }
            }
        }
    } catch { Write-Warning "Scan detection failed: $($_.Exception.Message)" }

    # Credential attacks: Hydra and similar
    try {
        $failed = @(Get-FailedLogons $since)
        $brutes = @(Find-BruteForce -Failed $failed -Threshold $FailedLogonThreshold)
        $success = @(Get-RemoteSuccessLogons $since)
        foreach ($b in $brutes) {
            $kind = if ($b.Spraying) { 'Password spraying' } else { 'Brute-force' }
            $won = @($success | Where-Object { $_.Ip -eq $b.Source })
            if ($won.Count) {
                Send-Alert 'Critical' "$kind SUCCEEDED" "$($b.Source) made $($b.Attempts) failed logons then logged on as $(($won | Select-Object -ExpandProperty User -Unique) -join ',') - assume compromise, rotate that password and review sessions" "bfwin|$($b.Source)"
            } else {
                Send-Alert 'Warning' "$kind detected" "$($b.Source) made $($b.Attempts) failed logons against $($b.UserCount) account(s): $($b.Users)" "bf|$($b.Source)"
            }
            if ($AutoBlock) { Add-IpBlock $b.Source $kind.ToLower() }
        }
    } catch { Write-Warning "Logon analysis failed: $($_.Exception.Message)" }

    # Lateral movement: Metasploit/Impacket psexec-style remote service installs
    try {
        foreach ($e in Get-EventRecords 'System' @(7045) $since) {
            $name = $e.Properties[0].Value; $image = "$($e.Properties[1].Value)"
            if (Test-SuspiciousServiceImage $image) {
                Send-Alert 'Critical' 'Suspicious service installed' "$name -> $image (PsExec/Metasploit-style remote execution)" "svc|$name|$image"
            }
        }
    } catch { Write-Warning "Service-install analysis failed: $($_.Exception.Message)" }

    # Persistence and anti-forensics
    try {
        foreach ($e in Get-EventRecords 'Security' @(4720) $since) {
            $d = ConvertTo-EventData $e
            Send-Alert 'Warning' 'Local user account created' "$($d['TargetUserName']) created by $($d['SubjectUserName'])" "newuser|$($d['TargetUserName'])|$($e.RecordId)"
        }
        foreach ($e in Get-EventRecords 'Security' @(4732) $since) {
            $d = ConvertTo-EventData $e
            if ($d['TargetSid'] -eq 'S-1-5-32-544') {
                Send-Alert 'Critical' 'Member added to local Administrators' "$($d['MemberName']) added by $($d['SubjectUserName'])" "admin|$($e.RecordId)"
            }
        }
        foreach ($e in Get-EventRecords 'Security' @(1102) $since) {
            Send-Alert 'Critical' 'Security event log cleared' "cleared at $($e.TimeCreated)" "clear|$($e.RecordId)"
        }
    } catch { Write-Warning "Account-change analysis failed: $($_.Exception.Message)" }

    # Defender detections
    try {
        if (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue) {
            foreach ($t in Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -ge $since }) {
                Send-Alert 'Critical' 'Defender detection' "threat id $($t.ThreatID) on $(@($t.Resources) -join '; ')" "mp|$($t.DetectionID)"
            }
        }
    } catch { }

    # Attacker tooling and reverse shells on this host
    try {
        foreach ($p in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) {
            if ($p.ProcessId -eq $PID) { continue }
            $m = Get-AttackToolMatch -ProcessName $p.Name -CommandLine $p.CommandLine
            if ($m) { Send-Alert 'Warning' 'Offensive tooling running' "$($p.Name) (pid $($p.ProcessId)): $m" "tool|$($p.Name)|$($p.ProcessId)" }
        }
        $shellPorts = 4444, 4445, 1337, 31337
        foreach ($c in Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemotePort -in $shellPorts }) {
            $proc = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            Send-Alert 'Critical' 'Possible reverse shell' "$proc (pid $($c.OwningProcess)) connected to $($c.RemoteAddress):$($c.RemotePort)" "rev|$($c.OwningProcess)|$($c.RemoteAddress)"
        }
        foreach ($l in Get-ExposedListeners) {
            if ($l.Port -in 4444, 4445, 31337) { Send-Alert 'Critical' 'Listener on common payload port' "$($l.Process) listening on $($l.Address):$($l.Port)" "lst|$($l.Port)|$($l.Process)" }
        }
    } catch { Write-Warning "Host triage failed: $($_.Exception.Message)" }

    $keep = @{}
    foreach ($k in $script:Seen.Keys) { if (([datetime]$script:Seen[$k]) -gt (Get-Date).AddHours(-24)) { $keep[$k] = $script:Seen[$k] } }
    Save-MonitorState $keep
    if ($script:AlertCount -eq 0) { Write-Host 'No new alerts.' -ForegroundColor Green }
}

function Install-MonitorTask {
    Initialize-StateDir
    $dest = Join-Path $StatePath 'AiAttackCounter.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $dest -Force
    $argList = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', "`"$dest`"", '-Action', 'Monitor',
        '-WindowMinutes', [Math]::Max($WindowMinutes, $IntervalMinutes * 2), '-ScanPortThreshold', $ScanPortThreshold,
        '-FailedLogonThreshold', $FailedLogonThreshold, '-BlockHours', $BlockHours, '-StatePath', "`"$StatePath`"")
    if ($AutoBlock) { $argList += '-AutoBlock' }
    if ($NeverBlock.Count) { $argList += @('-NeverBlock', "`"$($NeverBlock -join ',')`"") }

    $exe = (Get-Command powershell.exe -ErrorAction Stop).Source
    $act = New-ScheduledTaskAction -Execute $exe -Argument ($argList -join ' ')
    $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) -RepetitionDuration (New-TimeSpan -Days 3650)
    $pri = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $set = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    if ($DryRun) { Write-Host "Would register task '$script:TaskName': $exe $($argList -join ' ')"; return }
    Register-ScheduledTask -TaskName $script:TaskName -Action $act -Trigger $trg -Principal $pri -Settings $set -Force `
        -Description 'AiAttackCounter: detects scans, brute force and lateral movement' | Out-Null
    Write-Host "Scheduled task '$script:TaskName' registered (every $IntervalMinutes min, AutoBlock=$($AutoBlock.IsPresent))." -ForegroundColor Green
    Write-Host "Alerts: $script:AlertFile and Application event log, source '$script:EventSource' (IDs 4000-4002)."
}

function Remove-MonitorTask {
    if (Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue) {
        if ($DryRun) { Write-Host "Would remove task '$script:TaskName'"; return }
        Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false
        Write-Host "Removed scheduled task '$script:TaskName'." -ForegroundColor Green
    } else { Write-Host "Task '$script:TaskName' is not installed." }
}

# ---------------------------------------------------------------------------
# Entry point (skipped when dot-sourced, which lets tests load the functions)
# ---------------------------------------------------------------------------

function Invoke-Main {
    if (-not (Test-Admin)) {
        Write-Error 'Run this script from an elevated PowerShell (Run as administrator).'
        return
    }
    if ([Environment]::OSVersion.Version.Build -lt 22000) {
        Write-Warning 'Written for Windows 11 (build 22000+). Some checks may not apply on this build.'
    }
    switch ($Action) {
        'Audit'          { Invoke-Audit }
        'Harden'         { Invoke-Harden }
        'Monitor'        { Invoke-Monitor }
        'InstallMonitor' { Install-MonitorTask }
        'RemoveMonitor'  { Remove-MonitorTask }
        'Undo'           { Invoke-Undo }
    }
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-Main }
