<#
.SYNOPSIS
    Windows 11 defensive audit + hardening script against AI-orchestrated
    autonomous pentest frameworks (recon -> vuln scan -> exploit -> lateral -> exfil).

.DESCRIPTION
    Counters the toolset used by frameworks like
    saltless-bruh/ai-auto-attack-framework, which orchestrate:
      recon (nmap, masscan, dnsenum) | vuln scanning (nuclei, openvas) |
      exploitation (metasploit) | web abuse (playwright, sqlmap) |
      credential attacks (hydra, john) | remote exec (winrm, ssh/paramiko).

    Two modes:
      Audit  (default, read-only)  - inspects posture and hunts for IoCs,
                                     writes a JSON + TXT report, changes nothing.
      Harden (opt-in, reversible)   - applies safe, well-known Windows 11
                                     hardening on top of the audit.

    Safe by design:
      - Audit mode makes ZERO system changes.
      - Harden mode supports -WhatIf, logs every change, never forces a reboot,
        never deletes user data, and skips disruptive steps unless you pass an
        explicit flag (-DisableRDP, -BlockBruteForcers, -EnableASRRules).
      - Every hardening step is idempotent: re-running is safe.

.PARAMETER Mode
    Audit (default) or Harden.

.PARAMETER ReportPath
    Folder where the JSON + TXT reports are written.
    Default: Desktop, falling back to $env:TEMP.

.PARAMETER DisableRDP
    Harden-only. Disables Remote Desktop entirely (fDenyTSConnections=1).
    Default (without this flag): RDP is left as-is but NLA is enforced and the
    firewall rule is audited.

.PARAMETER KeepRemoteAccess
    Harden-only. Skips disabling the WinRM and OpenSSH-Server services.
    Use this on machines you manage remotely.

.PARAMETER EnableASRRules
    Harden-only. Enables Microsoft Defender Attack Surface Reduction (ASR) rules:
    3 safe rules in Block mode, 6 more in Audit mode (no user disruption).
    Without this flag, ASR rules are only audited.

.PARAMETER BlockBruteForcers
    Harden-only. Creates a Windows Firewall block rule for any IP with >= 10
    failed logons (Event 4625) in the last 24h. Default: report-only.

.PARAMETER Force
    Skips the Harden confirmation prompt.

.EXAMPLE
    # Read-only health check (run this first, no admin strictly required
    # but admin gives full event-log coverage):
    powershell -ExecutionPolicy Bypass -File .\Invoke-AntiAutoAttack.ps1 -Mode Audit

.EXAMPLE
    # Safe hardening, keeps remote access, enables ASR rules:
    powershell -ExecutionPolicy Bypass -File .\Invoke-AntiAutoAttack.ps1 -Mode Harden -KeepRemoteAccess -EnableASRRules

.EXAMPLE
    # Preview hardening changes without applying anything:
    powershell -ExecutionPolicy Bypass -File .\Invoke-AntiAutoAttack.ps1 -Mode Harden -WhatIf

.NOTES
    Target: Windows 11 (build 22000+). Must be run in Windows PowerShell 5.1+
    or PowerShell 7+. Some checks need Administrator; the script will tell you
    which ones were skipped when not elevated.
    Author: defensive sample for jean. No telemetry, no network calls.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Audit', 'Harden')]
    [string]$Mode = 'Audit',

    [string]$ReportPath = '',

    [switch]$DisableRDP,
    [switch]$KeepRemoteAccess,
    [switch]$EnableASRRules,
    [switch]$BlockBruteForcers,
    [switch]$Force
)

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# --------------------------------------------------------------------------
# Globals
# --------------------------------------------------------------------------
$Script:Findings   = New-Object System.Collections.Generic.List[object]
$Script:Changes    = New-Object System.Collections.Generic.List[object]
$Script:StartTime  = Get-Date
$Script:IsAdmin    = $false
$Script:IsWin11    = $false
$Script:OsCaption  = 'unknown'

function Write-Check {
    <#
    .SYNOPSIS Records one audit finding and prints a one-line status.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet('Pass', 'Warn', 'Fail', 'Info')][string]$Status = 'Info',
        [string]$Detail = '',
        [string]$Remediation = ''
    )
    $entry = [pscustomobject]@{
        Timestamp   = (Get-Date).ToString('s')
        Check       = $Name
        Status      = $Status
        Detail      = $Detail
        Remediation = $Remediation
    }
    $Script:Findings.Add($entry) | Out-Null
    $color = @{ Pass = 'Green'; Warn = 'Yellow'; Fail = 'Red'; Info = 'Cyan' }[$Status]
    $symbol = @{ Pass = '[PASS]'; Warn = '[WARN]'; Fail = '[FAIL]'; Info = '[INFO]' }[$Status]
    Write-Host ("{0} {1}" -f $symbol, $Name) -ForegroundColor $color
    if ($Detail) { Write-Host ("       {0}" -f $Detail) -ForegroundColor Gray }
    if ($Remediation -and ($Status -ne 'Pass')) {
        Write-Host ("       Fix: {0}" -f $Remediation) -ForegroundColor DarkYellow
    }
}

function Write-Change {
    param([string]$Area, [string]$Action, [string]$Result)
    $Script:Changes.Add([pscustomobject]@{
        Timestamp = (Get-Date).ToString('s')
        Area      = $Area
        Action    = $Action
        Result    = $Result
    }) | Out-Null
    Write-Host ("  -> {0}: {1}" -f $Action, $Result) -ForegroundColor Magenta
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegistryValue {
    param([string]$Path, [string]$Name, $Default = $null)
    try {
        $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $v.$Name
    } catch { return $Default }
}

function Set-RegistryValueSafe {
    <#
    .SYNOPSIS Idempotent registry write honoring -WhatIf.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Path, [string]$Name, [object]$Value, [string]$Kind = 'DWord')
    $old = Get-RegistryValue -Path $Path -Name $Name -Default '__MISSING__'
    if ("$old" -eq "$Value") { return "already set ($Value)" }
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set to $Value (was $old)")) {
        try {
            if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Kind -Force | Out-Null
            return "changed $old -> $Value"
        } catch { return "FAILED: $($_.Exception.Message)" }
    }
    return "whatif (would set $old -> $Value)"
}

# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------
Write-Host ''
Write-Host '=== Anti-Auto-Attack for Windows 11 | Audit + Harden ===' -ForegroundColor White
Write-Host ("Mode: {0}  |  Started: {1}" -f $Mode, $Script:StartTime) -ForegroundColor Gray
Write-Host 'Counters: nmap/masscan recon, nuclei/openvas vuln scans, metasploit,' -ForegroundColor Gray
Write-Host '          hydra/john brute force, WinRM/SSH lateral, LSASS theft, C2.' -ForegroundColor Gray
Write-Host ''

$Script:IsAdmin = Test-IsAdmin
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $Script:OsCaption = $os.Caption
    $build = [int]$os.BuildNumber
    $Script:IsWin11 = ($build -ge 22000)
    Write-Check -Name 'Operating system' `
        -Status $(if ($Script:IsWin11) { 'Pass' } else { 'Warn' }) `
        -Detail "$($os.Caption) build $build" `
        -Remediation 'This script is tuned for Windows 11 build 22000+. Results on other builds are best-effort.'
} catch {
    Write-Check -Name 'Operating system' -Status Warn -Detail "Could not query OS: $($_.Exception.Message)"
}

if ($Script:IsAdmin) {
    Write-Check -Name 'Elevation' -Status Pass -Detail 'Running as Administrator - full event-log and policy coverage.'
} else {
    Write-Check -Name 'Elevation' -Status Warn `
        -Detail 'Not elevated. Event-log brute-force, audit-policy and some Defender checks will be skipped.' `
        -Remediation 'Right-click PowerShell > Run as administrator and re-run.'
}

if ($Mode -eq 'Harden' -and -not $Script:IsAdmin) {
    Write-Host 'Harden mode requires Administrator. Re-run elevated.' -ForegroundColor Red
    exit 2
}

if ($Mode -eq 'Harden' -and -not $Force -and -not $WhatIfPreference) {
    Write-Host 'Harden mode will change system settings (all reversible, no reboot forced).' -ForegroundColor Yellow
    $ans = Read-Host 'Type HARDEN to continue'
    if ($ans -ne 'HARDEN') { Write-Host 'Aborted. No changes made.' -ForegroundColor Gray; exit 0 }
}

# --------------------------------------------------------------------------
# 1. Microsoft Defender antivirus
# --------------------------------------------------------------------------
function Audit-Defender {
    Write-Host ''; Write-Host '-- 1. Microsoft Defender --' -ForegroundColor White
    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
        $pref = Get-MpPreference -ErrorAction Stop
        if ($st.AntivirusEnabled) {
            Write-Check -Name 'Defender antivirus enabled' -Status Pass -Detail "Engine $($st.AntivirusSignatureVersion), $($st.AntispywareSignatureVersion)"
        } else {
            Write-Check -Name 'Defender antivirus enabled' -Status Fail -Detail 'Real-time antivirus is OFF' -Remediation 'Harden mode re-enables it, or run: Set-MpPreference -DisableRealtimeMonitoring $false'
        }
        $sigAge = ((Get-Date) - $st.AntivirusSignatureLastUpdated).TotalHours
        Write-Check -Name 'Defender signatures fresh (<24h)' `
            -Status $(if ($sigAge -lt 24) { 'Pass' } else { 'Warn' }) `
            -Detail ("Last update {0:0}h ago" -f $sigAge) `
            -Remediation 'Run: Update-MpSignature'
        foreach ($item in @(
            @{ N = 'Real-time monitoring'; V = (-not $pref.DisableRealtimeMonitoring); Fix = 'Set-MpPreference -DisableRealtimeMonitoring $false' }
            @{ N = 'Cloud-delivered protection'; V = ($pref.MAPSReporting -ne 0 -and -not $pref.DisableBlockAtFirstSeen); Fix = 'Set-MpPreference -MAPSReporting Advanced -DisableBlockAtFirstSeen $false' }
            @{ N = 'Behavior monitoring'; V = (-not $pref.DisableBehaviorMonitoring); Fix = 'Set-MpPreference -DisableBehaviorMonitoring $false' }
            @{ N = 'Network protection'; V = ($pref.EnableNetworkProtection -eq 1); Fix = 'Set-MpPreference -EnableNetworkProtection Enabled' }
        )) {
            Write-Check -Name ("Defender: {0}" -f $item.N) -Status $(if ($item.V) { 'Pass' } else { 'Warn' }) `
                -Detail $(if ($item.V) { 'on' } else { 'off or audit-only' }) -Remediation $item.Fix
        }
        try {
            $threats = Get-MpThreatDetection -ErrorAction Stop | Select-Object -First 5
            if ($threats) {
                $names = ($threats | ForEach-Object { $_.ThreatID }) -join ', '
                Write-Check -Name 'Defender recent detections' -Status Warn -Detail ("Recent threat IDs: {0} - review in Windows Security." -f $names) -Remediation 'Open Windows Security > Protection history.'
            } else {
                Write-Check -Name 'Defender recent detections' -Status Pass -Detail 'No active threat detections reported.'
            }
        } catch {
            Write-Check -Name 'Defender recent detections' -Status Info -Detail 'Threat history not readable in this session.'
        }
    } catch {
        Write-Check -Name 'Defender status' -Status Warn -Detail "Defender cmdlets unavailable: $($_.Exception.Message). Third-party AV may be in charge." -Remediation 'Verify your AV is active and up to date.'
    }
}

function Harden-Defender {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Host ''; Write-Host '-- Hardening: Defender --' -ForegroundColor White
    try {
        if ($PSCmdlet.ShouldProcess('Defender preferences', 'enable realtime+cloud+behavior+network protection')) {
            try {
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
                Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop
                Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
                Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction Stop
                Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
                Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction Stop
                Write-Change -Area 'Defender' -Action 'Enable realtime/cloud/behavior/network protection' -Result 'applied'
            } catch { Write-Change -Area 'Defender' -Action 'Enable protections' -Result ("FAILED: {0}" -f $_.Exception.Message) }
        }
        if ($EnableASRRules) { Harden-ASRRules } else {
            Write-Host '  (ASR rules audited only. Re-run with -EnableASRRules to enforce.)' -ForegroundColor Gray
            Audit-ASRRules
        }
    } catch { Write-Change -Area 'Defender' -Action 'Harden' -Result ("FAILED: {0}" -f $_.Exception.Message) }
}

function Audit-ASRRules {
    $desiredBlock = @(
        '9e6c4e1f-7d60-472d-ba7a-a39ef669e4b2', # Block credential stealing from LSASS
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4', # Block untrusted / unsigned processes from USB
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee4652'  # Block executable content from email / webmail
    )
    $desiredAudit = @(
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a', # Block Office apps from creating child processes
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84', # Block Office apps from injecting into other processes
        '92e97fa1-2edf-4476-bdd6-9dd0b0421018', # Block Office macros calling Win32 APIs
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c', # Block Adobe Reader child processes
        'd1e49aac-8f56-4280-b9ba-993a6d77406c', # Block persistence via WMI event subscription
        'd3e037e1-3eb8-44c8-a917-57927947596d'  # Block JS / VBS from launching executables
    )
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $ids = @($pref.AttackSurfaceReductionRules_Ids); $acts = @($pref.AttackSurfaceReductionRules_Actions)
        if (-not $ids -or $ids.Count -eq 0) {
            Write-Check -Name 'ASR rules configured' -Status Warn -Detail 'No ASR rules set.' -Remediation 'Re-run Harden with -EnableASRRules.'
            return
        }
        $map = @{}
        for ($i = 0; $i -lt $ids.Count; $i++) {
            $act = $null
            if ($i -lt $acts.Count) { $act = $acts[$i] }
            $map[$ids[$i]] = $act
        }
        $missing = @($desiredBlock + $desiredAudit | Where-Object { -not $map.ContainsKey($_) })
        if ($missing.Count -eq 0) {
            Write-Check -Name 'ASR rules configured' -Status Pass -Detail ("{0} rules present." -f $ids.Count)
        } else {
            Write-Check -Name 'ASR rules configured' -Status Warn -Detail ("{0} of 9 recommended rules missing." -f $missing.Count) -Remediation 'Re-run Harden with -EnableASRRules.'
        }
    } catch {
        Write-Check -Name 'ASR rules configured' -Status Info -Detail "Could not read ASR state: $($_.Exception.Message)"
    }
}

function Harden-ASRRules {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $ids = @(
        '9e6c4e1f-7d60-472d-ba7a-a39ef669e4b2',
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee4652',
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a',
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
        '92e97fa1-2edf-4476-bdd6-9dd0b0421018',
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c',
        'd1e49aac-8f56-4280-b9ba-993a6d77406c',
        'd3e037e1-3eb8-44c8-a917-57927947596d'
    )
    # 1 = Block, 2 = Audit. First three are safe to block; rest audit-only to avoid breaking Office macros.
    $actions = @(1, 1, 1, 2, 2, 2, 2, 2, 2)
    if ($PSCmdlet.ShouldProcess('ASR rules', 'set 9 recommended rules (3 block + 6 audit)')) {
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop
            Write-Change -Area 'Defender/ASR' -Action 'Set 9 ASR rules (3 block, 6 audit)' -Result 'applied'
        } catch { Write-Change -Area 'Defender/ASR' -Action 'Set ASR rules' -Result ("FAILED: {0}" -f $_.Exception.Message) }
    }
}

# --------------------------------------------------------------------------
# 2. Firewall (primary counter to nmap / masscan port sweeps)
# --------------------------------------------------------------------------
function Audit-Firewall {
    Write-Host ''; Write-Host '-- 2. Windows Firewall (scan shield) --' -ForegroundColor White
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $profiles) {
            $ok = ($p.Enabled -and $p.DefaultInboundAction -eq 'Block')
            Write-Check -Name ("Firewall profile: {0}" -f $p.Name) `
                -Status $(if ($ok) { 'Pass' } else { 'Fail' }) `
                -Detail ("Enabled={0} Inbound={1} Outbound={2}" -f $p.Enabled, $p.DefaultInboundAction, $p.DefaultOutboundAction) `
                -Remediation 'Harden mode sets every profile Enabled + Inbound Block.'
        }
        $log = Get-NetFirewallProfile -Name Public -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($log -and $log.LogBlocked) {
            Write-Check -Name 'Firewall dropped-packet logging' -Status Pass -Detail ("LogBlocked=on ({0}) - port sweeps leave evidence." -f $log.LogFileName)
        } else {
            Write-Check -Name 'Firewall dropped-packet logging' -Status Warn -Detail 'Blocked-packet logging is off; stealth scans leave no trace.' -Remediation 'Harden mode enables %systemroot%\system32\LogFiles\Firewall\pfirewall.log logging.'
        }
        # Overly permissive inbound allow rules are exactly what nuclei/metasploit probe.
        $wide = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
            Get-NetFirewallPortFilter -ErrorAction SilentlyContinue |
            Where-Object { $_.RemoteAddress -eq 'Any' -and $_.Protocol -in @('TCP', 'UDP') } |
            Select-Object -First 5
        if ($wide) {
            Write-Check -Name 'Inbound allow scope' -Status Warn -Detail 'Some inbound Allow rules accept RemoteAddress=Any. Review RDP/SSH/SMB/HTTP exposure.' -Remediation 'Scope rules to known subnets: Set-NetFirewallRule -RemoteAddress <subnet>.'
        } else {
            Write-Check -Name 'Inbound allow scope' -Status Pass -Detail 'No blanket inbound Allow rules found in quick check.'
        }
    } catch {
        Write-Check -Name 'Firewall status' -Status Warn -Detail "Could not query firewall: $($_.Exception.Message)"
    }
}

function Harden-Firewall {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Host ''; Write-Host '-- Hardening: Firewall --' -ForegroundColor White
    if ($PSCmdlet.ShouldProcess('Firewall profiles', 'enable all + block inbound + log drops')) {
        try {
            Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
            Set-NetFirewallProfile -All -LogBlocked True -LogAllowed False -LogIgnored True `
                -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' -LogMaxSizeKilobytes 16384 -ErrorAction Stop
            Write-Change -Area 'Firewall' -Action 'Profiles on, inbound block, drop-logging on' -Result 'applied'
        } catch { Write-Change -Area 'Firewall' -Action 'Harden profiles' -Result ("FAILED: {0}" -f $_.Exception.Message) }
    }
}

# --------------------------------------------------------------------------
# 3. Accounts, lockout, RDP, remote exec surface
# --------------------------------------------------------------------------
function Audit-Accounts {
    Write-Host ''; Write-Host '-- 3. Accounts & brute-force surface (hydra/john) --' -ForegroundColor White
    try {
        $acc = net accounts 2>$null | Out-String
        $thr = 'unknown'
        if ($acc -match 'Lockout threshold\s+(\d+|Never)') { $thr = $Matches[1] }
        $thrNum = 0
        [void][int]::TryParse("$thr", [ref]$thrNum)
        $thrOk = ($thrNum -ge 1 -and $thrNum -le 10)
        Write-Check -Name 'Account lockout threshold' `
            -Status $(if ($thrOk) { 'Pass' } else { 'Fail' }) `
            -Detail ("Threshold: {0}" -f $thr) `
            -Remediation 'Harden mode sets threshold 5, duration 15 min, window 15 min.'
    } catch {
        Write-Check -Name 'Account lockout threshold' -Status Info -Detail "net accounts unreadable: $($_.Exception.Message)"
    }
    try {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
        Write-Check -Name 'Guest account disabled' -Status $(if (-not $guest.Enabled) { 'Pass' } else { 'Fail' }) `
            -Detail ("Enabled={0}" -f $guest.Enabled) -Remediation 'Disable-LocalUser Guest'
    } catch { Write-Check -Name 'Guest account disabled' -Status Info -Detail 'Guest account not found or unreadable.' }
    try {
        $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Select-Object -ExpandProperty Name
        $n = @($admins).Count
        Write-Check -Name 'Local Administrators membership' -Status $(if ($n -le 2) { 'Pass' } else { 'Warn' }) `
            -Detail ("{0} member(s): {1}" -f $n, ($admins -join '; ')) -Remediation 'Remove stale admins: Remove-LocalGroupMember -Group Administrators -Member <name>.'
    } catch { Write-Check -Name 'Local Administrators membership' -Status Info -Detail "Could not enumerate admins: $($_.Exception.Message)" }
}

function Audit-RDP {
    Write-Host ''; Write-Host '-- 4. RDP / WinRM / SSH (lateral-movement doors) --' -ForegroundColor White
    $deny = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' -Default 1
    $nla   = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' -Default 1
    if ($deny -eq 1) {
        Write-Check -Name 'RDP exposed' -Status Pass -Detail 'Remote Desktop is disabled (fDenyTSConnections=1). Hydra/RDP and BlueKeep-style probes have no door.'
    } elseif ($nla -eq 1) {
        Write-Check -Name 'RDP exposed' -Status Warn -Detail 'RDP ON but NLA required. Brute force still possible.' -Remediation 'Disable RDP if unused (-DisableRDP), else enforce lockout + NLA + firewall scoping.'
    } else {
        Write-Check -Name 'RDP exposed' -Status Fail -Detail 'RDP ON without NLA - credential-guessing and pre-auth bugs are reachable.' -Remediation 'Enable NLA immediately or disable RDP.'
    }
    foreach ($svc in @('WinRM', 'sshd', 'ssh-agent')) {
        try {
            $s = Get-Service -Name $svc -ErrorAction Stop
            $risky = ($s.Status -eq 'Running' -and $svc -ne 'ssh-agent')
            Write-Check -Name ("Service: {0}" -f $svc) -Status $(if ($risky) { 'Warn' } else { 'Pass' }) `
                -Detail ("Status={0} StartType={1}" -f $s.Status, $s.StartType) `
                -Remediation $(if ($svc -eq 'WinRM') { 'Harden disables WinRM unless -KeepRemoteAccess.' } else { 'Disable if unused: Stop-Service + Set-Service -StartupType Disabled.' })
        } catch {
            Write-Check -Name ("Service: {0}" -f $svc) -Status Pass -Detail 'Not installed.'
        }
    }
    # PowerShell remoting doubles as the framework's paramiko/pywinrm equivalent on Windows.
    try {
        $rem = (Get-PSSessionConfiguration -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($rem) {
            Write-Check -Name 'PowerShell remoting' -Status Warn -Detail 'A PS remoting endpoint exists - the WinRM lateral path is live.' -Remediation 'Disable if unused: Disable-PSRemoting -Force.'
        } else {
            Write-Check -Name 'PowerShell remoting' -Status Pass -Detail 'No PS remoting endpoint advertised.'
        }
    } catch { Write-Check -Name 'PowerShell remoting' -Status Info -Detail 'Remoting state unreadable.' }
    # SMB: EternalBlue-style and PsExec-style movement ride on it.
    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        if ($smb1 -and $smb1.State -eq 'Enabled') {
            Write-Check -Name 'SMBv1 (legacy)' -Status Fail -Detail 'SMBv1 is ENABLED - unpatched-era exploits apply.' -Remediation 'Harden mode disables SMBv1.'
        } else {
            Write-Check -Name 'SMBv1 (legacy)' -Status Pass -Detail 'SMBv1 not enabled.'
        }
    } catch { Write-Check -Name 'SMBv1 (legacy)' -Status Info -Detail 'SMBv1 state unreadable.' }
    $sign = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' -Default 0
    Write-Check -Name 'SMB signing required' -Status $(if ($sign -eq 1) { 'Pass' } else { 'Warn' }) `
        -Detail ("RequireSecuritySignature={0}" -f $sign) -Remediation 'Harden mode requires SMB signing (breaks NTLM relay hardening gap).'
}

function Harden-AccountsAndRemote {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Host ''; Write-Host '-- Hardening: accounts & remote surface --' -ForegroundColor White
    if ($PSCmdlet.ShouldProcess('Account policy', 'lockout 5 / 15min + disable guest')) {
        try {
            net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 2>&1 | Out-Null
            Write-Change -Area 'Accounts' -Action 'Lockout policy 5/15/15' -Result 'applied'
        } catch { Write-Change -Area 'Accounts' -Action 'Lockout policy' -Result ("FAILED: {0}" -f $_.Exception.Message) }
        try { Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue; Write-Change -Area 'Accounts' -Action 'Disable Guest' -Result 'applied' }
        catch { Write-Change -Area 'Accounts' -Action 'Disable Guest' -Result ("skipped: {0}" -f $_.Exception.Message) }
    }
    if ($DisableRDP) {
        $r = Set-RegistryValueSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1
        Write-Change -Area 'RDP' -Action 'Disable RDP' -Result $r
    } else {
        $r = Set-RegistryValueSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1
        Write-Change -Area 'RDP' -Action 'Enforce NLA' -Result $r
    }
    if (-not $KeepRemoteAccess) {
        foreach ($svc in @('WinRM', 'sshd')) {
            try {
                $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
                if ($s -and $PSCmdlet.ShouldProcess("Service $svc", 'stop + disable')) {
                    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $svc -StartupType Disabled -ErrorAction Stop
                    Write-Change -Area 'RemoteSvc' -Action ("Disable {0}" -f $svc) -Result 'applied'
                } elseif ($s) { Write-Change -Area 'RemoteSvc' -Action ("Disable {0}" -f $svc) -Result 'whatif/skipped' }
            } catch { Write-Change -Area 'RemoteSvc' -Action ("Disable {0}" -f $svc) -Result ("FAILED: {0}" -f $_.Exception.Message) }
        }
        if ($PSCmdlet.ShouldProcess('PS remoting', 'Disable-PSRemoting')) {
            try { Disable-PSRemoting -Force -ErrorAction SilentlyContinue; Write-Change -Area 'RemoteSvc' -Action 'Disable PS remoting' -Result 'applied' }
            catch { Write-Change -Area 'RemoteSvc' -Action 'Disable PS remoting' -Result ("skipped: {0}" -f $_.Exception.Message) }
        }
    } else {
        Write-Host '  (Keeping WinRM/SSH per -KeepRemoteAccess. Ensure they require strong auth.)' -ForegroundColor Gray
    }
    if ($PSCmdlet.ShouldProcess('SMB', 'disable SMBv1 + require signing')) {
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
            $a = Set-RegistryValueSafe 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1
            $b = Set-RegistryValueSafe 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' 'RequireSecuritySignature' 1
            Write-Change -Area 'SMB' -Action 'SMBv1 off + signing required' -Result ("applied ($a / $b)")
        } catch { Write-Change -Area 'SMB' -Action 'Harden SMB' -Result ("FAILED: {0}" -f $_.Exception.Message) }
    }
}

# --------------------------------------------------------------------------
# 5. Name-resolution & recon leakage (LLMNR / NetBIOS / WPAD)
# --------------------------------------------------------------------------
function Audit-NameResolution {
    Write-Host ''; Write-Host '-- 5. Name-resolution poisoning surface --' -ForegroundColor White
    $llmnr = Get-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' -Default 1
    # 0 = disabled via policy; missing (default 1) = enabled and poisonable.
    Write-Check -Name 'LLMNR disabled' -Status $(if ($llmnr -eq 0) { 'Pass' } else { 'Warn' }) `
        -Detail ("EnableMulticast={0}" -f $llmnr) -Remediation 'Harden mode disables LLMNR via policy.'
    try {
        $nb = Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object { $_.IPEnabled } | Select-Object -First 1
        if ($nb) {
            $opt = $nb.TcpipNetbiosOptions
            Write-Check -Name 'NetBIOS disabled' -Status $(if ($opt -eq 2) { 'Pass' } else { 'Warn' }) `
                -Detail ("TcpipNetbiosOptions={0} (2=disable)" -f $opt) -Remediation 'Harden mode sets NetBIOS to Disable (2) on IP-enabled adapters.'
        }
    } catch { Write-Check -Name 'NetBIOS disabled' -Status Info -Detail "Unreadable: $($_.Exception.Message)" }
    $wpad = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc' 'Start' -Default 3
    Write-Check -Name 'WPAD / proxy auto-discovery' -Status Info `
        -Detail ("WinHttpAutoProxySvc Start={0} (2=auto,3=manual,4=disabled). Review if you pin proxies." -f $wpad)
}

function Harden-NameResolution {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Host ''; Write-Host '-- Hardening: LLMNR/NetBIOS --' -ForegroundColor White
    $r = Set-RegistryValueSafe 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
    Write-Change -Area 'LLMNR' -Action 'Disable LLMNR (EnableMulticast=0)' -Result $r
    if ($PSCmdlet.ShouldProcess('NetBIOS adapters', 'set TcpipNetbiosOptions=2')) {
        try {
            $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object { $_.IPEnabled }
            $done = 0
            foreach ($a in $adapters) {
                try { $a | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } -ErrorAction Stop | Out-Null; $done++ }
                catch { }
            }
            Write-Change -Area 'NetBIOS' -Action 'Disable NetBIOS on adapters' -Result ("applied to {0} adapter(s)" -f $done)
        } catch { Write-Change -Area 'NetBIOS' -Action 'Disable NetBIOS' -Result ("FAILED: {0}" -f $_.Exception.Message) }
    }
}

# --------------------------------------------------------------------------
# 6. Credential-theft & privilege guards (UAC / LSA / VBS)
# --------------------------------------------------------------------------
function Audit-CredentialGuards {
    Write-Host ''; Write-Host '-- 6. Credential theft & privilege guards --' -ForegroundColor White
    $lua = Get-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' -Default 1
    $consent = Get-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' -Default 5
    Write-Check -Name 'UAC enabled, prompt for consent' -Status $(if ($lua -eq 1 -and $consent -ge 2) { 'Pass' } else { 'Fail' }) `
        -Detail ("EnableLUA={0} ConsentAdmin={1}" -f $lua, $consent) -Remediation 'Harden mode sets EnableLUA=1, ConsentPromptBehaviorAdmin=5.'
    $ppl = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' -Default 0
    Write-Check -Name 'LSA Protection (PPL)' -Status $(if ($ppl -eq 1) { 'Pass' } else { 'Warn' }) `
        -Detail ("RunAsPPL={0}" -f $ppl) -Remediation 'Harden mode sets RunAsPPL=1 (needs reboot to take effect).'
    $cfg = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags' -Default 0
    Write-Check -Name 'Credential Guard (VBS)' -Status $(if ($cfg -eq 1 -or $cfg -eq 2) { 'Pass' } else { 'Info' }) `
        -Detail ("LsaCfgFlags={0} (1/2 = UEFI lock or on). Requires HVCI-capable hardware." -f $cfg) `
        -Remediation 'Enable via Group Policy or Windows Security > Device security > Core isolation.'
    try {
        $mem = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        $hvci = ($mem | Select-Object -First 1).VirtualizationBasedSecurityStatus
        Write-Check -Name 'Memory integrity (HVCI)' -Status $(if ($hvci -eq 2) { 'Pass' } else { 'Warn' }) `
            -Detail ("VBS status={0} (2=running)" -f $hvci) -Remediation 'Enable: Windows Security > Device security > Core isolation > Memory integrity.'
    } catch { Write-Check -Name 'Memory integrity (HVCI)' -Status Info -Detail 'VBS status unreadable on this machine.' }
    $autorun = Get-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' -Default 0
    Write-Check -Name 'AutoRun/AutoPlay disabled' -Status $(if ($autorun -eq 255) { 'Pass' } else { 'Warn' }) `
        -Detail ("NoDriveTypeAutoRun={0} (255=all off)" -f $autorun) -Remediation 'Harden mode sets NoDriveTypeAutoRun=255.'
}

function Harden-CredentialGuards {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Host ''; Write-Host '-- Hardening: UAC/LSA/AutoRun --' -ForegroundColor White
    $a = Set-RegistryValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1
    $b = Set-RegistryValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 5
    Write-Change -Area 'UAC' -Action 'EnableLUA=1, Consent=5' -Result ("$a / $b")
    $c = Set-RegistryValueSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 1
    Write-Change -Area 'LSA' -Action 'RunAsPPL=1 (reboot required)' -Result $c
    $d = Set-RegistryValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255
    Write-Change -Area 'AutoRun' -Action 'NoDriveTypeAutoRun=255' -Result $d
}

# --------------------------------------------------------------------------
# 7. Logging & audit policy (catch the robot: scriptblock, process, logon)
# --------------------------------------------------------------------------
function Audit-Logging {
    Write-Host ''; Write-Host '-- 7. Logging (catch living-off-the-land) --' -ForegroundColor White
    $sb = Get-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' -Default 0
    Write-Check -Name 'PowerShell ScriptBlock logging' -Status $(if ($sb -eq 1) { 'Pass' } else { 'Warn' }) `
        -Detail ("EnableScriptBlockLogging={0}" -f $sb) -Remediation 'Harden mode enables ScriptBlock + Module logging.'
    $mod = 0
    try { $mod = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -ErrorAction Stop | Out-Null; 1) } catch { $mod = 0 }
    Write-Check -Name 'PowerShell Module logging' -Status $(if ($mod -eq 1) { 'Pass' } else { 'Warn' }) `
        -Detail $(if ($mod -eq 1) { 'ModuleNames key present' } else { 'not configured' }) -Remediation 'Harden mode enables ModuleLogging for *.'
    try {
        $out = auditpol /get /category:'Logon/Logoff','Object Access','Privilege Use','Detailed Tracking' 2>$null | Out-String
        $need = @('Logon', 'Process Creation', 'Security Group Management')
        $missing = @($need | Where-Object { $out -notmatch [regex]::Escape($_) })
        if ($out -match 'Success and Failure' -or $out -match 'Success') {
            Write-Check -Name 'Advanced audit policy' -Status $(if ($missing.Count -eq 0) { 'Pass' } else { 'Warn' }) `
                -Detail 'auditpol categories readable; verify Logon + Process Creation are Success+Failure.' `
                -Remediation 'Harden mode sets Logon, Process Creation, Account Management to Success+Failure.'
        } else {
            Write-Check -Name 'Advanced audit policy' -Status Info -Detail 'auditpol output inconclusive.'
        }
    } catch { Write-Check -Name 'Advanced audit policy' -Status Info -Detail "auditpol unreadable: $($_.Exception.Message)" }
    # Sysmon is the single best upgrade for catching automated agents.
    if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue -or (Get-Command sysmon64.exe -ErrorAction SilentlyContinue)) {
        Write-Check -Name 'Sysmon installed' -Status Pass -Detail 'Sysmon present - process/network/image-load telemetry available.'
    } else {
        Write-Check -Name 'Sysmon installed' -Status Info -Detail 'Not found. Strongly recommended for detecting automated tooling.' -Remediation 'Install Sysmon with the SwiftOnSecurity config; this script does not install it automatically.'
    }
}

function Harden-Logging {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Host ''; Write-Host '-- Hardening: PowerShell + audit policy logging --' -ForegroundColor White
    $a = Set-RegistryValueSafe 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
    Write-Change -Area 'PSLogging' -Action 'ScriptBlockLogging=1' -Result $a
    if ($PSCmdlet.ShouldProcess('ModuleLogging', 'enable for *')) {
        try {
            if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames')) {
                New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Force | Out-Null
            }
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*' -Value '*' -PropertyType String -Force | Out-Null
            Set-RegistryValueSafe 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 1 | Out-Null
            Write-Change -Area 'PSLogging' -Action 'ModuleLogging=*' -Result 'applied'
        } catch { Write-Change -Area 'PSLogging' -Action 'ModuleLogging' -Result ("FAILED: {0}" -f $_.Exception.Message) }
    }
    if ($PSCmdlet.ShouldProcess('auditpol', 'logon + process creation + account mgmt success/failure')) {
        try {
            auditpol /set /subcategory:'Logon' /success:enable /failure:enable 2>&1 | Out-Null
            auditpol /set /subcategory:'Logoff' /success:enable /failure:enable 2>&1 | Out-Null
            auditpol /set /subcategory:'Process Creation' /success:enable /failure:enable 2>&1 | Out-Null
            auditpol /set /subcategory:'Security Group Management' /success:enable /failure:enable 2>&1 | Out-Null
            auditpol /set /subcategory:'User Account Management' /success:enable /failure:enable 2>&1 | Out-Null
            Write-Change -Area 'AuditPol' -Action 'Logon/Process/Account success+failure' -Result 'applied'
        } catch { Write-Change -Area 'AuditPol' -Action 'Set auditpol' -Result ("FAILED: {0}" -f $_.Exception.Message) }
    }
    # Include command line in process-creation events (4688) - critical for spotting tool flags.
    $r = Set-RegistryValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
    Write-Change -Area 'AuditPol' -Action 'Include command line in 4688' -Result $r
}

# --------------------------------------------------------------------------
# 8. Patching & SmartScreen
# --------------------------------------------------------------------------
function Audit-Patching {
    Write-Host ''; Write-Host '-- 8. Patching & SmartScreen --' -ForegroundColor White
    try {
        $hot = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 1
        $age = ((Get-Date) - $hot.InstalledOn).TotalDays
        Write-Check -Name 'Latest hotfix recency' -Status $(if ($age -lt 45) { 'Pass' } else { 'Warn' }) `
            -Detail ("Newest: {0} on {1:yyyy-MM-dd} ({2:0}d ago)" -f $hot.HotFixID, $hot.InstalledOn, $age) `
            -Remediation 'Settings > Windows Update > Check for updates. Nuclei/Metasploit feast on >45d-old hosts.'
    } catch { Write-Check -Name 'Latest hotfix recency' -Status Info -Detail "Hotfix list unreadable: $($_.Exception.Message)" }
    $smart = Get-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled' -Default 'unknown'
    Write-Check -Name 'SmartScreen' -Status $(if ($smart -eq 'RequireAdmin' -or $smart -eq 'Prompt') { 'Pass' } else { 'Warn' }) `
        -Detail ("SmartScreenEnabled={0}" -f $smart) -Remediation 'Enable: Windows Security > App & browser control > Reputation-based protection.'
}

# --------------------------------------------------------------------------
# 9. IoC hunt: processes, listeners, persistence, brute force
# --------------------------------------------------------------------------
$Script:SuspiciousProcessNames = @(
    'nmap', 'masscan', 'nuclei', 'sqlmap', 'hydra', 'john', 'medusa',
    'mimikatz', 'sekurlsa', 'psexec', 'psexesvc', 'meterpreter',
    'cobaltstrike', 'beacon', 'powersploit', 'krbrelay', 'responder',
    'bloodhound', 'sharphound', 'rubeus', 'certipy', 'impacket',
    'chisel', 'ligolo', 'ngrok', 'frpc', 'ew_', 'earthworm'
)
$Script:SuspiciousPortList = @(4444, 4443, 5555, 6666, 8081, 8444, 31337, 1337, 9001, 1080, 9050)

function Hunt-Processes {
    Write-Host ''; Write-Host '-- 9a. Suspicious processes --' -ForegroundColor White
    try {
        $procs = Get-CimInstance Win32_Process -ErrorAction Stop
        $hits = @($procs | Where-Object {
            $n = $_.Name.ToLower()
            ($Script:SuspiciousProcessNames | Where-Object { $n -like ("*{0}*" -f $_) }).Count -gt 0 -or
            ($_.CommandLine -and ($_.CommandLine -match '(?i)(nmap|masscan|nuclei|sqlmap|hydra|meterpreter|mimikatz|psexec|sekurlsa|bloodhound|rubeus|responder| -enc |FromBase64String|IEX |DownloadString|DownloadFile)'))
        } | Select-Object ProcessId, Name, @{ N = 'Cmd'; E = { ($_.CommandLine | Out-String).Substring(0, [Math]::Min(220, ($_.CommandLine | Out-String).Length)) } })
        if ($hits.Count -gt 0) {
            foreach ($h in ($hits | Select-Object -First 10)) {
                Write-Check -Name ("Suspicious process: {0} (PID {1})" -f $h.Name, $h.ProcessId) -Status Fail -Detail $h.Cmd -Remediation 'Isolate host, kill process tree after capturing command line, run full Defender scan.'
            }
        } else {
            Write-Check -Name 'Suspicious processes' -Status Pass -Detail 'No known attacker-tool names or LOLBins-with-encoded-payload patterns in process list.'
        }
    } catch {
        # Fallback without command lines.
        $names = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $Script:SuspiciousProcessNames -contains ($_.ProcessName.ToLower()) })
        if ($names.Count -gt 0) {
            Write-Check -Name 'Suspicious processes' -Status Fail -Detail (($names | ForEach-Object { $_.ProcessName }) -join ', ') -Remediation 'Investigate immediately.'
        } else {
            Write-Check -Name 'Suspicious processes' -Status Info -Detail "Process scan limited: $($_.Exception.Message)"
        }
    }
}

function Hunt-Listeners {
    Write-Host ''; Write-Host '-- 9b. Listening ports & established C2-shaped links --' -ForegroundColor White
    try {
        $list = Get-NetTCPConnection -State Listen -ErrorAction Stop
        $procs = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
        $flagged = @($list | Where-Object { $Script:SuspiciousPortList -contains $_.LocalPort })
        $rdpOpen = @($list | Where-Object { $_.LocalPort -eq 3389 })
        $winrmOpen = @($list | Where-Object { $_.LocalPort -in @(5985, 5986) })
        $sshOpen = @($list | Where-Object { $_.LocalPort -eq 22 })
        foreach ($g in @(
            @{ N = 'Known-C2 ports listening (4444/5555/6666/1337/...)'; Rows = $flagged; Level = 'Fail' }
            @{ N = 'RDP (3389) listening'; Rows = $rdpOpen; Level = 'Warn' }
            @{ N = 'WinRM (5985/5986) listening'; Rows = $winrmOpen; Level = 'Warn' }
            @{ N = 'SSH (22) listening'; Rows = $sshOpen; Level = 'Warn' }
        )) {
            if ($g.Rows.Count -gt 0) {
                $detail = (($g.Rows | Select-Object -First 5 | ForEach-Object {
                    $pn = $procs[[int]$_.OwningProcess]; "{0} pid={1}({2})" -f $_.LocalPort, $_.OwningProcess, $pn
                }) -join '; ')
                Write-Check -Name $g.N -Status $g.Level -Detail $detail -Remediation 'Verify the owning process is expected; firewall-scope or disable the service if not.'
            } else {
                Write-Check -Name $g.N -Status Pass -Detail 'none found.'
            }
        }
        # Established links TO suspicious ports (possible reverse shell / exfil).
        $est = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $Script:SuspiciousPortList -contains $_.RemotePort } | Select-Object -First 5)
        if ($est.Count -gt 0) {
            Write-Check -Name 'Established links to C2-shaped ports' -Status Fail -Detail (($est | ForEach-Object { "{0}->{1}:{2}" -f $_.LocalAddress, $_.RemoteAddress, $_.RemotePort }) -join '; ') -Remediation 'Treat as incident: capture netstat -ano, isolate host, hunt owning PID.'
        } else {
            Write-Check -Name 'Established links to C2-shaped ports' -Status Pass -Detail 'none found.'
        }
    } catch {
        Write-Check -Name 'Network listeners' -Status Info -Detail "Get-NetTCPConnection failed: $($_.Exception.Message)"
    }
}

function Hunt-Persistence {
    Write-Host ''; Write-Host '-- 9c. Persistence (Run keys, tasks, services, WMI) --' -ForegroundColor White
    $suspPattern = '(?i)(temp|appdata|programdata|users\\public|\\downloads\\|\.vbs|\.js|\.hta|powershell.*-e(nc)?\s|bitsadmin|certutil.*-urlcache|mshta|rundll32.*javascript|wmic.*process call create)'
    foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                       'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) {
        try {
            $vals = Get-ItemProperty -Path $key -ErrorAction Stop
            foreach ($prop in ($vals.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                $v = "$($prop.Value)"
                if ($v -match $suspPattern) {
                    Write-Check -Name ("Autorun suspicious: {0}\{1}" -f $key, $prop.Name) -Status Fail -Detail $v -Remediation 'Verify publisher; remove value if malicious and reboot.'
                }
            }
        } catch { }
    }
    Write-Check -Name 'Autorun registry sweep' -Status Info -Detail 'Run/RunOnce keys scanned; only matches printed above (silence = clean).'
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' } | Select-Object -First 400
        $flagged = @()
        foreach ($t in $tasks) {
            try {
                $xml = Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue | Out-String
                if ($xml -match $suspPattern) { $flagged += ("{0}{1}" -f $t.TaskPath, $t.TaskName) }
            } catch { }
            if ($flagged.Count -ge 8) { break }
        }
        if ($flagged.Count -gt 0) {
            Write-Check -Name 'Scheduled tasks with suspicious actions' -Status Fail -Detail ($flagged -join '; ') -Remediation 'Disable task, export XML for forensics, trace creator via Event 4698.'
        } else {
            Write-Check -Name 'Scheduled tasks with suspicious actions' -Status Pass -Detail 'No LOLBins-in-odd-paths patterns in enabled tasks (sampled).'
        }
    } catch { Write-Check -Name 'Scheduled tasks with suspicious actions' -Status Info -Detail "Task scan failed: $($_.Exception.Message)" }
    try {
        $svcs = Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.StartMode -eq 'Auto' -and $_.PathName -match $suspPattern
        } | Select-Object -First 5
        if ($svcs) {
            foreach ($s in $svcs) {
                Write-Check -Name ("Service with odd ImagePath: {0}" -f $s.Name) -Status Fail -Detail $s.PathName -Remediation 'Check Event 7045/4697 for installer; disable service after evidence capture.'
            }
        } else {
            Write-Check -Name 'Auto-start services with odd paths' -Status Pass -Detail 'none found.'
        }
    } catch { Write-Check -Name 'Auto-start services with odd paths' -Status Info -Detail "Service scan failed: $($_.Exception.Message)" }
    try {
        $filters = Get-CimInstance -Namespace root\subscription -Class __EventFilter -ErrorAction Stop
        if ($filters -and @($filters).Count -gt 0) {
            Write-Check -Name 'WMI event subscriptions' -Status Warn -Detail ("{0} __EventFilter(s) present - review for fileless persistence." -f @($filters).Count) -Remediation 'Get-CimInstance root/subscription __EventFilter/__EventConsumer/__FilterToConsumerBinding and remove unknown ones.'
        } else {
            Write-Check -Name 'WMI event subscriptions' -Status Pass -Detail 'none found.'
        }
    } catch { Write-Check -Name 'WMI event subscriptions' -Status Info -Detail 'WMI subscription namespace unreadable (normal when empty).' }
    foreach ($dir in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\StartUp") ) {
        try {
            $files = Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
            if ($files) {
                Write-Check -Name ("Startup folder: {0}" -f $dir) -Status Warn -Detail ($files -join ', ') -Remediation 'Remove unknown .lnk/.bat/.ps1 after verification.'
            }
        } catch { }
    }
}

function Hunt-BruteForce {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Host ''; Write-Host '-- 9d. Brute-force evidence (Event 4625, last 24h) --' -ForegroundColor White
    if (-not $Script:IsAdmin) {
        Write-Check -Name 'Failed-logon review' -Status Info -Detail 'Skipped: Security log needs Administrator.'
        return
    }
    try {
        $since = (Get-Date).AddHours(-24)
        $evts = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; ID = 4625; StartTime = $since } -ErrorAction Stop
        $total = @($evts).Count
        if ($total -eq 0) {
            Write-Check -Name 'Failed logons (24h)' -Status Pass -Detail 'Zero Event 4625 in last 24h.'
            return
        }
        $ips = @{}
        foreach ($e in $evts) {
            try {
                $x = [xml]$e.ToXml()
                $ip = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' } | Select-Object -First 1).'#text'
                if ($ip -and $ip -notin @('-', '127.0.0.1', '::1')) {
                    if (-not $ips.ContainsKey($ip)) { $ips[$ip] = 0 }
                    $ips[$ip]++
                }
            } catch { }
        }
        $top = ($ips.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3 | ForEach-Object { "{0} ({1}x)" -f $_.Key, $_.Value }) -join ', '
        $level = if ($total -ge 50) { 'Fail' } elseif ($total -ge 10) { 'Warn' } else { 'Info' }
        Write-Check -Name 'Failed logons (24h)' -Status $level -Detail ("{0} failures. Top sources: {1}" -f $total, $(if ($top) { $top } else { 'local/unknown' })) -Remediation 'Hydra-style guessing leaves exactly this trail. Block repeat IPs, enforce lockout, scope RDP.'
        if ($BlockBruteForcers -and $Mode -eq 'Harden' -and $ips.Count -gt 0) {
            $offenders = @($ips.GetEnumerator() | Where-Object { $_.Value -ge 10 } | ForEach-Object { $_.Key })
            if ($offenders.Count -gt 0 -and $PSCmdlet.ShouldProcess('Firewall', ("block {0} brute-force IP(s)" -f $offenders.Count))) {
                try {
                    $name = 'AntiAutoAttack-Block-BruteForce'
                    $old = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
                    if ($old) { Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue }
                    New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Block -RemoteAddress $offenders -Description 'Auto-blocked by Invoke-AntiAutoAttack (4625 surge)' | Out-Null
                    Write-Change -Area 'Firewall' -Action ("Block {0} brute-force IP(s)" -f $offenders.Count) -Result ($offenders -join ', ')
                } catch { Write-Change -Area 'Firewall' -Action 'Block brute-force IPs' -Result ("FAILED: {0}" -f $_.Exception.Message) }
            } elseif ($offenders.Count -eq 0) {
                Write-Host '  (No single IP hit 10+ failures; nothing to block.)' -ForegroundColor Gray
            }
        }
        # Successful RDP logons (4624 type 10) deserve a glance too.
        $ok = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; ID = 4624; StartTime = $since } -ErrorAction SilentlyContinue | Select-Object -First 400)
        $rdp = 0
        foreach ($e in $ok) {
            try { if (([xml]$e.ToXml()).OuterXml -match '<Data Name="LogonType">10</Data>') { $rdp++ } } catch { }
        }
        Write-Check -Name 'Successful RDP logons (24h, type 10)' -Status $(if ($rdp -eq 0) { 'Pass' } else { 'Info' }) -Detail ("{0} network-RDP logons sampled." -f $rdp)
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'No events were found|no events') {
            Write-Check -Name 'Failed logons (24h)' -Status Pass -Detail 'Zero Event 4625 in last 24h.'
        } else {
            Write-Check -Name 'Failed logons (24h)' -Status Info -Detail ("Security log unreadable: {0}" -f $msg)
        }
    }
}

function Hunt-DnsAndHosts {
    Write-Host ''; Write-Host '-- 9e. DNS / hosts-file tampering --' -ForegroundColor White
    try {
        $hosts = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction Stop | Where-Object { $_ -match '^\s*\d+\.\d+\.\d+\.\d+' -and $_ -notmatch '^\s*#' } | Select-Object -First 5
        if ($hosts) {
            Write-Check -Name 'hosts file entries' -Status Warn -Detail ($hosts -join ' | ') -Remediation 'Unknown entries can redirect auth traffic; remove bogus lines.'
        } else {
            Write-Check -Name 'hosts file entries' -Status Pass -Detail 'No active custom mappings (localhost defaults only).'
        }
    } catch { Write-Check -Name 'hosts file entries' -Status Info -Detail "hosts unreadable: $($_.Exception.Message)" }
    try {
        $dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.ServerAddresses } | ForEach-Object { "{0}: {1}" -f $_.InterfaceAlias, ($_.ServerAddresses -join ',') }
        Write-Check -Name 'DNS servers' -Status Info -Detail (($dns | Select-Object -First 4) -join ' | ')
    } catch { Write-Check -Name 'DNS servers' -Status Info -Detail "DNS config unreadable: $($_.Exception.Message)" }
}

# --------------------------------------------------------------------------
# Run audits
# --------------------------------------------------------------------------
Audit-Defender
Audit-Firewall
Audit-Accounts
Audit-RDP
Audit-NameResolution
Audit-CredentialGuards
Audit-Logging
Audit-Patching
Hunt-Processes
Hunt-Listeners
Hunt-Persistence
Hunt-BruteForce
Hunt-DnsAndHosts

if ($Mode -eq 'Harden') {
    Write-Host ''; Write-Host '================ HARDEN (reversible, no reboot forced) ================' -ForegroundColor Yellow
    Harden-Defender
    Harden-Firewall
    Harden-AccountsAndRemote
    Harden-NameResolution
    Harden-CredentialGuards
    Harden-Logging
    Write-Host 'Harden pass complete. A reboot is needed for LSA-PPL to take effect.' -ForegroundColor Yellow
}

# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------
if (-not $ReportPath) {
    $base = if (Test-Path "$env:USERPROFILE\Desktop") { "$env:USERPROFILE\Desktop" } else { $env:TEMP }
    $ReportPath = $base
}
try {
    if (-not (Test-Path $ReportPath)) { New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $jsonFile = Join-Path $ReportPath "AntiAutoAttack-Report-$stamp.json"
    $txtFile  = Join-Path $ReportPath "AntiAutoAttack-Report-$stamp.txt"
    $summary = [ordered]@{
        Tool      = 'Invoke-AntiAutoAttack.ps1'
        CounterTo = 'ai-auto-attack-framework (nmap/masscan/nuclei/openvas/metasploit/sqlmap/hydra/john/winrm/ssh)'
        Mode      = $Mode
        Machine   = $env:COMPUTERNAME
        User      = "$env:USERDOMAIN\$env:USERNAME"
        OS        = $Script:OsCaption
        Elevated  = $Script:IsAdmin
        Started   = "$Script:StartTime"
        Finished  = "$(Get-Date)"
        Totals    = @{
            Pass = @($Script:Findings | Where-Object { $_.Status -eq 'Pass' }).Count
            Warn = @($Script:Findings | Where-Object { $_.Status -eq 'Warn' }).Count
            Fail = @($Script:Findings | Where-Object { $_.Status -eq 'Fail' }).Count
            Info = @($Script:Findings | Where-Object { $_.Status -eq 'Info' }).Count
        }
        Findings = $Script:Findings
        Changes  = $Script:Changes
    }
    $summary | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonFile -Encoding UTF8
    $lines = @()
    $lines += 'Anti-Auto-Attack report'
    $lines += ("Mode={0} Machine={1} OS={2} Elevated={3} Time={4}" -f $Mode, $env:COMPUTERNAME, $Script:OsCaption, $Script:IsAdmin, (Get-Date))
    $lines += ("Totals: Pass={0} Warn={1} Fail={2} Info={3}" -f $summary.Totals.Pass, $summary.Totals.Warn, $summary.Totals.Fail, $summary.Totals.Info)
    $lines += ''
    foreach ($f in $Script:Findings) { $lines += ("[{0}] {1} -- {2}" -f $f.Status, $f.Check, $f.Detail) }
    if ($Script:Changes.Count -gt 0) {
        $lines += ''; $lines += 'Changes applied:'
        foreach ($c in $Script:Changes) { $lines += ("- [{0}] {1}: {2}" -f $c.Area, $c.Action, $c.Result) }
    }
    $lines | Out-File -FilePath $txtFile -Encoding UTF8
    Write-Host ''
    Write-Host ("Report JSON: {0}" -f $jsonFile) -ForegroundColor Green
    Write-Host ("Report TXT : {0}" -f $txtFile) -ForegroundColor Green
} catch {
    Write-Host ("Could not write report to {0}: {1}" -f $ReportPath, $_.Exception.Message) -ForegroundColor Red
}

$fails = @($Script:Findings | Where-Object { $_.Status -eq 'Fail' }).Count
$warns = @($Script:Findings | Where-Object { $_.Status -eq 'Warn' }).Count
Write-Host ''
if ($fails -gt 0) {
    Write-Host ("Result: {0} FAIL + {1} WARN - act on red items above, then re-run Audit." -f $fails, $warns) -ForegroundColor Red
    exit 1
} elseif ($warns -gt 0) {
    Write-Host ("Result: {0} warnings, 0 failures - review yellow items, consider Harden mode." -f $warns) -ForegroundColor Yellow
    exit 0
} else {
    Write-Host 'Result: clean - no FAIL/WARN findings. Re-run after Patch Tuesday or any remote-access change.' -ForegroundColor Green
    exit 0
}
