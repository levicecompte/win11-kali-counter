<#
.SYNOPSIS
    Citadel - a Windows 11 hardening, detection and rollback framework built against the attack
    techniques catalogued in blaCCkHatHacEEkr/PENTESTING-BIBLE.

.DESCRIPTION
    Four modes:
      Audit    (default) Read-only. Grades the machine against every control and writes a report.
      Apply    Enforces every failing control, backing up each value it changes first.
      Scan     Threat-hunts for the artefacts those attacks leave behind (UAC-bypass registry
               hijacks, persistence, WMI subscriptions, LSA/IFEO/AppInit backdoors, DNS tunnelling,
               LOLBin C2 connections, offensive tooling in command lines and script-block logs...).
      Rollback Restores the pre-Apply state from a backup file.

    Levels:
      Standard Low-breakage controls suitable for a normal workstation.
      Strict   Adds controls that can break workflows (RDP off, USB storage off, Print Spooler off,
               Windows Script Host off, Credential Guard/HVCI, Kerberos AES-only, etc.).

    -InstallSentinel registers an hourly SYSTEM scheduled task that runs `-Mode Scan`, writes the
    findings to the Application event log (source "Citadel") and to JSON reports, and (with
    -Remediate) removes UAC-bypass hijack keys and malicious WMI subscriptions.

.PARAMETER Mode           Audit | Apply | Scan | Rollback
.PARAMETER Level          Standard | Strict
.PARAMETER AppLocker      Off | Audit | Enforce. Deploys a default-deny-from-user-writable-paths policy.
.PARAMETER SkipModule     Module names to skip. Modules: Credentials, Relay, Lateral, Privesc,
                          Scripting, Phishing, Defender, LOLBins, Memory, Network, Wireless,
                          Physical, Logging, Web, Services, Accounts, Posture
.PARAMETER InstallSentinel / RemoveSentinel   Manage the hourly hunting task.
.PARAMETER Remediate      In Scan mode, auto-remove UAC hijack keys and malicious WMI persistence.
.PARAMETER PurgeOpenWifi  Delete (rather than set to manual) open Wi-Fi profiles.
.PARAMETER BackupFile     Backup JSON to use with -Mode Rollback (default: newest).

.EXAMPLE
    .\Win11-Citadel.ps1                                  # grade the machine, change nothing
.EXAMPLE
    .\Win11-Citadel.ps1 -Mode Apply -InstallSentinel     # harden + hourly threat hunting
.EXAMPLE
    .\Win11-Citadel.ps1 -Mode Apply -Level Strict -AppLocker Audit
.EXAMPLE
    .\Win11-Citadel.ps1 -Mode Scan -Remediate
.EXAMPLE
    .\Win11-Citadel.ps1 -Mode Rollback
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Audit', 'Apply', 'Scan', 'Rollback')][string]$Mode = 'Audit',
    [ValidateSet('Standard', 'Strict')][string]$Level = 'Standard',
    [ValidateSet('Off', 'Audit', 'Enforce')][string]$AppLocker = 'Off',
    [string[]]$SkipModule = @(),
    [switch]$InstallSentinel,
    [switch]$RemoveSentinel,
    [switch]$Remediate,
    [switch]$PurgeOpenWifi,
    [string]$BackupFile,
    [string]$OutDir = (Join-Path $env:ProgramData 'Citadel'),
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:WhatIf = [bool]$WhatIfPreference
$WhatIfPreference = $false
$script:Version = '1.0.0'
$script:IsStrict = ($Level -eq 'Strict')
$script:Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:FwPrefix = 'Citadel-'
$script:Dirs = @{
    Root    = $OutDir
    Reports = Join-Path $OutDir 'reports'
    Backup  = Join-Path $OutDir 'backup'
    Bin     = Join-Path $OutDir 'bin'
    PSLogs  = Join-Path $OutDir 'pstranscripts'
}
$script:Controls = New-Object System.Collections.Generic.List[object]
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Backup = New-Object System.Collections.Generic.List[object]
$script:BackupIndex = @{}
$script:RebootNeeded = $false
$script:DomainJoined = $null
$script:FeatureCache = $null

$CCS = 'HKLM\SYSTEM\CurrentControlSet\Control'
$SVC = 'HKLM\SYSTEM\CurrentControlSet\Services'
$POLSYS = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$WINPOL = 'HKLM\SOFTWARE\Policies\Microsoft\Windows'

# ----------------------------------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------------------------------
function Write-Info {
    param([string]$Message, [ConsoleColor]$Color = [ConsoleColor]::Gray)
    if (-not $Quiet) { Write-Host $Message -ForegroundColor $Color }
}

function Initialize-Workspace {
    foreach ($d in $script:Dirs.Values) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
    Set-AdminOnlyAcl -Path $script:Dirs.Root
}

function Set-AdminOnlyAcl {
    param([string]$Path)
    Invoke-Native -File "$env:windir\System32\icacls.exe" -Arguments @(
        $Path, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F') | Out-Null
}

function Invoke-Native {
    param([string]$File, [string[]]$Arguments = @())
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $File @Arguments 2>&1 | Out-String
        [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $out.Trim() }
    }
    finally { $ErrorActionPreference = $prev }
}

# ----------------------------------------------------------------------------------------------
# Registry layer (uses .NET so value names containing * \ / are handled literally)
# ----------------------------------------------------------------------------------------------
function Open-HiveKey {
    param([string]$Path, [ValidateSet('Read', 'Write', 'Create')][string]$Access = 'Read')
    $m = [regex]::Match($Path, '^(HKLM|HKCU)\\(.+)$')
    if (-not $m.Success) { throw "Unsupported registry path: $Path" }
    if ($m.Groups[1].Value -eq 'HKLM') { $root = [Microsoft.Win32.Registry]::LocalMachine }
    else { $root = [Microsoft.Win32.Registry]::CurrentUser }
    $sub = $m.Groups[2].Value
    switch ($Access) {
        'Create' { return $root.CreateSubKey($sub) }
        'Write' { return $root.OpenSubKey($sub, $true) }
        default { return $root.OpenSubKey($sub) }
    }
}

function Get-RegState {
    param([string]$Path, [string]$Name)
    $none = [pscustomobject]@{ Exists = $false; Value = $null; Kind = $null }
    $k = Open-HiveKey -Path $Path
    if ($null -eq $k) { return $none }
    try {
        if (@($k.GetValueNames()) -contains $Name) {
            return [pscustomobject]@{
                Exists = $true
                Value  = $k.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                Kind   = [string]$k.GetValueKind($Name)
            }
        }
        return $none
    }
    finally { $k.Close() }
}

function Test-RegKey {
    param([string]$Path)
    $k = Open-HiveKey -Path $Path
    if ($null -eq $k) { return $false }
    $k.Close()
    $true
}

function Get-RegSubKeyNames {
    param([string]$Path)
    $k = Open-HiveKey -Path $Path
    if ($null -eq $k) { return @() }
    try { return @($k.GetSubKeyNames()) } finally { $k.Close() }
}

function Get-RegValueMap {
    param([string]$Path)
    $map = [ordered]@{}
    $k = Open-HiveKey -Path $Path
    if ($null -eq $k) { return $map }
    try {
        foreach ($n in $k.GetValueNames()) {
            $map[$n] = $k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }
    }
    finally { $k.Close() }
    $map
}

function Save-RegBackup {
    param([string]$Path, [string]$Name)
    $id = ("$Path|$Name").ToLowerInvariant()
    if ($script:BackupIndex.ContainsKey($id)) { return }
    $script:BackupIndex[$id] = $true
    $st = Get-RegState -Path $Path -Name $Name
    $val = $st.Value
    if ($st.Exists -and $st.Kind -eq 'Binary') { $val = [Convert]::ToBase64String([byte[]]$val) }
    $script:Backup.Add([pscustomobject]@{
            Type = 'Reg'; Path = $Path; Name = $Name; Existed = $st.Exists; Kind = $st.Kind; Value = $val
        })
}

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    Save-RegBackup -Path $Path -Name $Name
    $k = Open-HiveKey -Path $Path -Access Create
    try {
        switch ($Type) {
            'DWord' { $v = [int]$Value }
            'QWord' { $v = [long]$Value }
            'MultiString' { $v = [string[]]@($Value) }
            default { $v = [string]$Value }
        }
        $k.SetValue($Name, $v, [Microsoft.Win32.RegistryValueKind]$Type)
    }
    finally { $k.Close() }
}

function Remove-Reg {
    param([string]$Path, [string]$Name, [switch]$NoBackup)
    if (-not $NoBackup) { Save-RegBackup -Path $Path -Name $Name }
    $k = Open-HiveKey -Path $Path -Access Write
    if ($null -eq $k) { return }
    try { $k.DeleteValue($Name, $false) } finally { $k.Close() }
}

function Compare-RegValue {
    param($Actual, $Desired, [string]$Type)
    if ($Desired -is [array]) { return ((@($Actual) -join '|') -eq (@($Desired) -join '|')) }
    if ($Type -in 'DWord', 'QWord') {
        try { return ([int64]$Actual -eq [int64]$Desired) } catch { return $false }
    }
    return ([string]$Actual -eq [string]$Desired)
}

function New-Reg { param($P, $N, $V, $T = 'DWord') @{ P = $P; N = $N; V = $V; T = $T } }
function New-RegAbsent { param($P, $N) @{ P = $P; N = $N; Absent = $true } }
function New-RegAny { param($P, $N, $V, $Any, $T = 'DWord') @{ P = $P; N = $N; V = $V; T = $T; AnyOf = $Any } }

function Test-RegSettings {
    param([object[]]$Settings)
    foreach ($s in $Settings) {
        $st = Get-RegState -Path $s.P -Name $s.N
        if ($s.ContainsKey('Absent')) {
            if ($st.Exists) { return $false }
            continue
        }
        if (-not $st.Exists) { return $false }
        if ($s.ContainsKey('AnyOf')) {
            $hit = $false
            foreach ($a in $s.AnyOf) { if (Compare-RegValue $st.Value $a $s.T) { $hit = $true } }
            if (-not $hit) { return $false }
            continue
        }
        if (-not (Compare-RegValue $st.Value $s.V $s.T)) { return $false }
    }
    $true
}

function Set-RegSettings {
    param([object[]]$Settings)
    foreach ($s in $Settings) {
        if (Test-RegSettings -Settings @($s)) { continue }
        if ($s.ContainsKey('Absent')) { Remove-Reg -Path $s.P -Name $s.N }
        else { Set-Reg -Path $s.P -Name $s.N -Value $s.V -Type $s.T }
    }
}

# ----------------------------------------------------------------------------------------------
# Control registry
# ----------------------------------------------------------------------------------------------
function Add-Control {
    param(
        [Parameter(Mandatory)][string]$Module,
        [Parameter(Mandatory)][string]$Title,
        [string]$Counters = '',
        [ValidateSet('Standard', 'Strict')][string]$Level = 'Standard',
        [Parameter(Mandatory)][scriptblock]$Test,
        [scriptblock]$Apply,
        [scriptblock]$When,
        [hashtable]$Data = @{},
        [string]$Remedy = '',
        [switch]$Reboot,
        [switch]$Manual
    )
    $script:Controls.Add([pscustomobject]@{
            Id       = 'C{0:000}' -f ($script:Controls.Count + 1)
            Module   = $Module
            Title    = $Title
            Counters = $Counters
            Level    = $Level
            Test     = $Test
            Apply    = $Apply
            When     = $When
            Data     = $Data
            Remedy   = $Remedy
            Reboot   = [bool]$Reboot
            Manual   = [bool]$Manual
        })
}

function Add-RegControl {
    param(
        [string]$Module, [string]$Title, [string]$Counters = '',
        [ValidateSet('Standard', 'Strict')][string]$Level = 'Standard',
        [Parameter(Mandatory)][object[]]$Settings,
        [scriptblock]$When, [switch]$Reboot
    )
    Add-Control -Module $Module -Title $Title -Counters $Counters -Level $Level -When $When -Reboot:$Reboot `
        -Data @{ Settings = $Settings } `
        -Test { param($c) Test-RegSettings -Settings $c.Data.Settings } `
        -Apply { param($c) Set-RegSettings -Settings $c.Data.Settings }
}

function Add-ServiceDisableControl {
    param(
        [string]$Module, [string]$Title, [string]$Counters = '',
        [ValidateSet('Standard', 'Strict')][string]$Level = 'Standard',
        [string[]]$Services
    )
    Add-Control -Module $Module -Title $Title -Counters $Counters -Level $Level -Data @{ Services = $Services } `
        -Test {
        param($c)
        foreach ($s in $c.Data.Services) {
            $p = "$SVC\$s"
            if (Test-RegKey -Path $p) {
                $st = Get-RegState -Path $p -Name 'Start'
                if (-not $st.Exists -or [int]$st.Value -ne 4) { return $false }
            }
        }
        $true
    } `
        -Apply {
        param($c)
        foreach ($s in $c.Data.Services) {
            $p = "$SVC\$s"
            if (Test-RegKey -Path $p) {
                Set-Reg -Path $p -Name 'Start' -Value 4
                Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Test-DomainJoined {
    if ($null -eq $script:DomainJoined) {
        try { $script:DomainJoined = [bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain }
        catch { $script:DomainJoined = $false }
    }
    $script:DomainJoined
}

function Test-OfficeInstalled {
    (Test-RegKey 'HKLM\SOFTWARE\Microsoft\Office\ClickToRun') -or
    (Test-RegKey 'HKLM\SOFTWARE\Microsoft\Office\16.0') -or
    (Test-RegKey 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Office\16.0')
}

function Test-DefenderActive {
    try {
        if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { return $false }
        [bool](Get-MpComputerStatus).AMServiceEnabled
    }
    catch { $false }
}

# ----------------------------------------------------------------------------------------------
# Firewall helpers
# ----------------------------------------------------------------------------------------------
function Test-FwRule {
    param([string]$Name)
    [bool](Get-NetFirewallRule -Name ($script:FwPrefix + $Name) -ErrorAction SilentlyContinue)
}

function New-CitadelBlockRule {
    param(
        [string]$Name, [ValidateSet('Inbound', 'Outbound')][string]$Direction,
        [string]$Protocol, [string[]]$LocalPort, [string[]]$RemotePort,
        [string]$RemoteAddress, [string]$Program, [string]$FwProfile = 'Any', [string]$Description = ''
    )
    if (Test-FwRule -Name $Name) { return }
    $p = @{
        Name        = $script:FwPrefix + $Name
        DisplayName = "Citadel: $Name"
        Direction   = $Direction
        Action      = 'Block'
        Profile     = $FwProfile
        Enabled     = 'True'
        Description = $Description
    }
    if ($Protocol) { $p.Protocol = $Protocol }
    if ($LocalPort) { $p.LocalPort = $LocalPort }
    if ($RemotePort) { $p.RemotePort = $RemotePort }
    if ($RemoteAddress) { $p.RemoteAddress = $RemoteAddress }
    if ($Program) { $p.Program = $Program }
    New-NetFirewallRule @p | Out-Null
    $script:Backup.Add([pscustomobject]@{ Type = 'Firewall'; Name = $p.Name })
}

function Invoke-Appcmd {
    param([string]$Exe, [string[]]$ArgList)
    Invoke-Native -File $Exe -Arguments $ArgList | Out-Null
}

function Get-LolbinPaths {
    $sys = "$env:windir\System32"
    $wow = "$env:windir\SysWOW64"
    $names = 'mshta.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'cmstp.exe', 'odbcconf.exe',
    'hh.exe', 'presentationhost.exe', 'wscript.exe', 'cscript.exe', 'esentutl.exe', 'expand.exe',
    'extrac32.exe', 'replace.exe', 'ftp.exe', 'pcalua.exe', 'infdefaultinstall.exe', 'ieexec.exe',
    'wmic.exe', 'syncappvpublishingserver.exe', 'scriptrunner.exe', 'makecab.exe', 'finger.exe'
    $paths = New-Object System.Collections.Generic.List[string]
    foreach ($n in $names) {
        foreach ($d in $sys, $wow) {
            $p = Join-Path $d $n
            if (Test-Path -LiteralPath $p) { $paths.Add($p) }
        }
    }
    foreach ($fw in 'Framework', 'Framework64') {
        foreach ($v in 'v4.0.30319', 'v2.0.50727') {
            foreach ($n in 'msbuild.exe', 'installutil.exe', 'regasm.exe', 'regsvcs.exe', 'jsc.exe') {
                $p = "$env:windir\Microsoft.NET\$fw\$v\$n"
                if (Test-Path -LiteralPath $p) { $paths.Add($p) }
            }
        }
    }
    $paths
}

function Get-LolbinRuleName {
    param([string]$Path)
    $rel = $Path.Substring($env:windir.Length + 1) -replace '[\\/ ]', '_'
    "Out-LOLBin-$rel"
}

# ----------------------------------------------------------------------------------------------
# Misc helpers used by controls
# ----------------------------------------------------------------------------------------------
function Get-FeatureState {
    param([string]$Name)
    if ($null -eq $script:FeatureCache) {
        $script:FeatureCache = @{}
        foreach ($f in (Get-WindowsOptionalFeature -Online)) { $script:FeatureCache[$f.FeatureName] = [string]$f.State }
    }
    if ($script:FeatureCache.ContainsKey($Name)) { return $script:FeatureCache[$Name] }
    'Absent'
}

function Get-SecPolValue {
    param([string]$Key)
    $tmp = Join-Path $env:TEMP ("citadel-sec-{0}.inf" -f ([guid]::NewGuid().ToString('N')))
    try {
        Invoke-Native -File "$env:windir\System32\secedit.exe" -Arguments @('/export', '/cfg', $tmp, '/areas', 'SECURITYPOLICY') | Out-Null
        foreach ($line in (Get-Content -LiteralPath $tmp -ErrorAction Stop)) {
            if ($line -match ('^\s*{0}\s*=\s*(.+?)\s*$' -f [regex]::Escape($Key))) { return $Matches[1] }
        }
        $null
    }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}

function Get-AuditSetting {
    param([string]$Guid)
    $r = Invoke-Native -File "$env:windir\System32\auditpol.exe" -Arguments @('/get', "/subcategory:$Guid", '/r')
    $row = ($r.Output -split "`r?`n" | Where-Object { $_ -match '\{' } | Select-Object -Last 1)
    if (-not $row) { return '' }
    $f = $row -split ','
    if ($f.Count -ge 5) { return $f[4] }
    ''
}

function Test-UserWritable {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        foreach ($r in $acl.Access) {
            if ($r.AccessControlType -ne 'Allow') { continue }
            try { $sid = $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
            if ($sid -notin 'S-1-1-0', 'S-1-5-32-545', 'S-1-5-11') { continue }
            $rights = [string]$r.FileSystemRights
            if ($rights -match 'FullControl|Modify|Write|CreateFiles|AppendData|ChangePermissions|TakeOwnership') { return $true }
        }
    }
    catch { }
    $false
}

function Get-UnquotedServiceImagePaths {
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($name in (Get-RegSubKeyNames -Path $SVC)) {
        $p = "$SVC\$name"
        $st = Get-RegState -Path $p -Name 'ImagePath'
        if (-not $st.Exists -or $st.Value -isnot [string]) { continue }
        $raw = ([string]$st.Value).Trim()
        if ($raw.StartsWith('"')) { continue }
        $m = [regex]::Match($raw, '^(?<exe>(?:[A-Za-z]:|%[^%]+%)\\.+?\.exe)(?<args>\s.*)?$', 'IgnoreCase')
        if (-not $m.Success) { continue }
        $expanded = [Environment]::ExpandEnvironmentVariables($m.Groups['exe'].Value)
        if ($expanded -notmatch '\s') { continue }
        $found.Add([pscustomobject]@{
                Service = $name; Path = $p; Raw = $raw; Kind = $st.Kind
                Fixed   = ('"' + $m.Groups['exe'].Value + '"' + $m.Groups['args'].Value)
            })
    }
    $found
}

function Get-WlanOpenProfiles {
    $dir = Join-Path $env:TEMP ("citadel-wlan-{0}" -f ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $result = New-Object System.Collections.Generic.List[object]
    try {
        Invoke-Native -File "$env:windir\System32\netsh.exe" -Arguments @('wlan', 'export', 'profile', "folder=$dir") | Out-Null
        foreach ($f in (Get-ChildItem -LiteralPath $dir -Filter '*.xml' -ErrorAction SilentlyContinue)) {
            try {
                $x = [xml](Get-Content -LiteralPath $f.FullName -Raw)
                $auth = [string]$x.WLANProfile.MSM.security.authEncryption.authentication
                $mode = [string]$x.WLANProfile.connectionMode
                if ($auth -ieq 'open') {
                    $result.Add([pscustomobject]@{ Name = [string]$x.WLANProfile.name; Mode = $mode })
                }
            }
            catch { }
        }
    }
    finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    $result
}

function New-AppLockerXml {
    param([ValidateSet('AuditOnly', 'Enabled')][string]$EnforcementMode)
    $everyone = 'S-1-1-0'
    $admins = 'S-1-5-32-544'
    $rule = {
        param($Name, $Sid, $Path, $Except)
        $id = [guid]::NewGuid().ToString()
        $ex = ''
        if ($Except) {
            $ex = '<Exceptions>' + (($Except | ForEach-Object { "<FilePathCondition Path=`"$_`" />" }) -join '') + '</Exceptions>'
        }
        "<FilePathRule Id=`"$id`" Name=`"Citadel: $Name`" Description=`"Managed by Citadel`" UserOrGroupSid=`"$Sid`" Action=`"Allow`"><Conditions><FilePathCondition Path=`"$Path`" /></Conditions>$ex</FilePathRule>"
    }
    $winEx = @('%WINDIR%\Temp\*', '%WINDIR%\Tasks\*', '%WINDIR%\tracing\*')
    $exe = (& $rule 'Windows' $everyone '%WINDIR%\*' $winEx) + (& $rule 'Program Files' $everyone '%PROGRAMFILES%\*' $null) + (& $rule 'Administrators' $admins '*' $null)
    $scr = (& $rule 'Windows' $everyone '%WINDIR%\*' $winEx) + (& $rule 'Program Files' $everyone '%PROGRAMFILES%\*' $null) +
    (& $rule 'Citadel sentinel' $everyone '%OSDRIVE%\ProgramData\Citadel\bin\*' $null) + (& $rule 'Administrators' $admins '*' $null)
    $msi = (& $rule 'Installer cache' $everyone '%WINDIR%\Installer\*' $null) + (& $rule 'Administrators' $admins '*' $null)
    $m = $EnforcementMode
    '<AppLockerPolicy Version="1">' +
    "<RuleCollection Type=`"Exe`" EnforcementMode=`"$m`">$exe</RuleCollection>" +
    "<RuleCollection Type=`"Script`" EnforcementMode=`"$m`">$scr</RuleCollection>" +
    "<RuleCollection Type=`"Msi`" EnforcementMode=`"$m`">$msi</RuleCollection>" +
    '</AppLockerPolicy>'
}

# ----------------------------------------------------------------------------------------------
# Control catalogue
# ----------------------------------------------------------------------------------------------
function Initialize-Controls {
    $strictValue = { param($std, $strict) if ($script:IsStrict) { $strict } else { $std } }

    # ---- Credentials ------------------------------------------------------------------------
    Add-RegControl -Module Credentials -Title 'WDigest clear-text credential caching disabled' `
        -Counters 'Mimikatz / WDigest plaintext dump (#386, #479)' -Settings @(
        New-Reg "$CCS\SecurityProviders\WDigest" 'UseLogonCredential' 0)

    Add-RegControl -Module Credentials -Title 'LSASS runs as Protected Process Light' `
        -Counters 'Mimikatz sekurlsa::logonpasswords, LSASS dumps (#386)' -Reboot -Settings @(
        New-RegAny "$CCS\Lsa" 'RunAsPPL' 2 @(1, 2))

    Add-RegControl -Module Credentials -Title 'NTLMv2 only, LM hashes never stored, blank-password network logon denied' `
        -Counters 'NTLMv1 cracking (crack.sh #392), Responder hash cracking (#391), pass-the-hash downgrade' -Settings @(
        New-Reg "$CCS\Lsa" 'LmCompatibilityLevel' 5
        New-Reg "$CCS\Lsa" 'NoLMHash' 1
        New-Reg "$CCS\Lsa" 'LimitBlankPasswordUse' 1
        New-Reg "$CCS\Lsa" 'ForceGuest' 0
        New-Reg "$CCS\Lsa\MSV1_0" 'NtlmMinClientSec' 537395200
        New-Reg "$CCS\Lsa\MSV1_0" 'NtlmMinServerSec' 537395200)

    Add-RegControl -Module Credentials -Title 'NTLM usage audited (outgoing and incoming)' `
        -Counters 'NTLM relay / hash capture visibility (SCF, Bad-PDF, Responder)' -Settings @(
        New-Reg "$CCS\Lsa\MSV1_0" 'RestrictSendingNTLMTraffic' 1
        New-Reg "$CCS\Lsa\MSV1_0" 'AuditReceivingNTLMTraffic' 2)

    Add-RegControl -Module Credentials -Title 'Anonymous SAM/share/pipe enumeration blocked; remote SAM queries admin-only' `
        -Counters 'BloodHound/CrackMapExec/SAMR enumeration (#430, #460), null sessions' -Settings @(
        New-Reg "$CCS\Lsa" 'RestrictAnonymous' 1
        New-Reg "$CCS\Lsa" 'RestrictAnonymousSAM' 1
        New-Reg "$CCS\Lsa" 'EveryoneIncludesAnonymous' 0
        New-Reg "$CCS\Lsa" 'RestrictRemoteSam' 'O:BAG:BAD:(A;;RC;;;BA)' 'String'
        New-Reg "$SVC\LanmanServer\Parameters" 'RestrictNullSessAccess' 1)

    Add-RegControl -Module Credentials -Title 'Cached domain logons minimised' `
        -Counters 'Offline MSCache2 hash cracking, credential dumping' `
        -When { param($c) Test-DomainJoined } -Settings @(
        New-Reg 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount' (& $strictValue '2' '1') 'String')

    Add-Control -Module Credentials -Title 'No auto-logon password stored in the registry' `
        -Counters 'Registry credential harvesting (Windows privesc cheat-sheets #78, #297)' `
        -Test {
        param($c)
        $w = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $dp = Get-RegState -Path $w -Name 'DefaultPassword'
        $al = Get-RegState -Path $w -Name 'AutoAdminLogon'
        (-not $dp.Exists) -and (-not ($al.Exists -and [string]$al.Value -eq '1'))
    } `
        -Apply {
        param($c)
        $w = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Set-Reg -Path $w -Name 'AutoAdminLogon' -Value '0' -Type String
        Remove-Reg -Path $w -Name 'DefaultPassword' -NoBackup
    }

    Add-RegControl -Module Credentials -Title 'Credential Guard + VBS enabled (no UEFI lock)' -Level Strict -Reboot `
        -Counters 'Pass-the-hash / pass-the-ticket, LSASS secrets theft' -Settings @(
        New-Reg "$CCS\DeviceGuard" 'EnableVirtualizationBasedSecurity' 1
        New-Reg "$CCS\DeviceGuard" 'RequirePlatformSecurityFeatures' 1
        New-Reg "$CCS\Lsa" 'LsaCfgFlags' 2)

    # ---- Relay: name resolution poisoning, SMB/LDAP relay ----------------------------------------
    Add-RegControl -Module Relay -Title 'LLMNR and mDNS responders disabled; smart multi-homed name resolution off' `
        -Counters 'Responder / LLMNR-NBT-NS poisoning (#391), Inveigh' -Settings @(
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'DisableSmartNameResolution' 1
        New-Reg "$SVC\Dnscache\Parameters" 'EnableMDNS' 0)

    Add-Control -Module Relay -Title 'NetBIOS over TCP/IP disabled on every interface' `
        -Counters 'NBT-NS poisoning, NetBIOS name-release attacks, NetBIOS enumeration (#181)' `
        -Test {
        param($c)
        $base = "$SVC\NetBT\Parameters\Interfaces"
        foreach ($i in (Get-RegSubKeyNames -Path $base | Where-Object { $_ -like 'Tcpip_*' })) {
            $st = Get-RegState -Path "$base\$i" -Name 'NetbiosOptions'
            if (-not $st.Exists -or [int]$st.Value -ne 2) { return $false }
        }
        $nr = Get-RegState -Path "$SVC\NetBT\Parameters" -Name 'NoNameReleaseOnDemand'
        $nr.Exists -and [int]$nr.Value -eq 1
    } `
        -Apply {
        param($c)
        $base = "$SVC\NetBT\Parameters\Interfaces"
        foreach ($i in (Get-RegSubKeyNames -Path $base | Where-Object { $_ -like 'Tcpip_*' })) {
            Set-Reg -Path "$base\$i" -Name 'NetbiosOptions' -Value 2
        }
        Set-Reg -Path "$SVC\NetBT\Parameters" -Name 'NoNameReleaseOnDemand' -Value 1
    }

    Add-RegControl -Module Relay -Title 'WPAD auto-discovery disabled' `
        -Counters 'WPAD hijack / proxy-poisoning credential capture' -Settings @(
        New-Reg 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DisableWpad' 1)

    Add-RegControl -Module Relay -Title 'SMB signing required (client + server); insecure guest logons blocked' `
        -Counters 'SMB/NTLM relay (#391), MITM on SMB, rogue share guest access' -Settings @(
        New-Reg "$SVC\LanmanServer\Parameters" 'RequireSecuritySignature' 1
        New-Reg "$SVC\LanmanServer\Parameters" 'EnableSecuritySignature' 1
        New-Reg "$SVC\LanmanWorkstation\Parameters" 'RequireSecuritySignature' 1
        New-Reg "$SVC\LanmanWorkstation\Parameters" 'EnableSecuritySignature' 1
        New-Reg "$WINPOL\LanmanWorkstation" 'AllowInsecureGuestAuth' 0
        New-Reg "$SVC\LanmanServer\Parameters" 'SMB1' 0)

    Add-RegControl -Module Relay -Title 'UNC hardening for NETLOGON/SYSVOL (mutual auth + integrity)' `
        -Counters 'GPO / logon-script poisoning via rogue SMB (MS15-011)' -Settings @(
        New-Reg "$WINPOL\NetworkProvider\HardenedPaths" '\\*\NETLOGON' 'RequireMutualAuthentication=1,RequireIntegrity=1' 'String'
        New-Reg "$WINPOL\NetworkProvider\HardenedPaths" '\\*\SYSVOL' 'RequireMutualAuthentication=1,RequireIntegrity=1' 'String')

    Add-RegControl -Module Relay -Title 'LDAP client signing' `
        -Counters 'LDAP relay (NTLM -> LDAP), AD ACL abuse (#432)' `
        -When { param($c) Test-DomainJoined } -Settings @(
        New-Reg "$SVC\LDAP" 'LDAPClientIntegrity' (& $strictValue 1 2))

    Add-RegControl -Module Relay -Title 'Kerberos limited to AES (no RC4/DES)' -Level Strict `
        -Counters 'Kerberoasting / AS-REP roasting offline cracking' `
        -When { param($c) Test-DomainJoined } -Settings @(
        New-Reg 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'SupportedEncryptionTypes' 2147483640)

    Add-RegControl -Module Relay -Title 'IP stack: source routing, ICMP redirects and router discovery off' `
        -Counters 'ARP/ICMP-redirect MITM, HTTP password sniffing (#2), CoffeeMiner (#371)' -Settings @(
        New-Reg "$SVC\Tcpip\Parameters" 'DisableIPSourceRouting' 2
        New-Reg "$SVC\Tcpip6\Parameters" 'DisableIPSourceRouting' 2
        New-Reg "$SVC\Tcpip\Parameters" 'EnableICMPRedirect' 0
        New-Reg "$SVC\Tcpip\Parameters" 'PerformRouterDiscovery' 0)

    Add-Control -Module Relay -Title 'Firewall: inbound DHCPv6 blocked (rogue DHCPv6 / mitm6)' -Level Strict `
        -Counters 'mitm6 IPv6 takeover -> NTLM relay' `
        -Test { param($c) Test-FwRule 'In-DHCPv6' } `
        -Apply {
        param($c)
        New-CitadelBlockRule -Name 'In-DHCPv6' -Direction Inbound -Protocol UDP -LocalPort 546 -RemotePort 547 `
            -Description 'mitm6 mitigation'
    }

    # ---- Lateral movement ------------------------------------------------------------------
    Add-RegControl -Module Lateral -Title 'Local-account remote token filtering on; built-in admin in Admin Approval Mode' `
        -Counters 'Pass-the-hash with local admin, remote UAC bypass (#336), PsExec' -Settings @(
        New-Reg $POLSYS 'LocalAccountTokenFilterPolicy' 0
        New-Reg $POLSYS 'FilterAdministratorToken' 1)

    Add-RegControl -Module Lateral -Title 'Admin shares (C$, ADMIN$) not auto-created on workstation' -Level Strict -Reboot `
        -Counters 'PsExec / SMB delivery (#106), remote file ops' -Settings @(
        New-Reg "$SVC\LanmanServer\Parameters" 'AutoShareWks' 0)

    Add-RegControl -Module Lateral -Title 'RDP requires NLA, TLS, high encryption; no passwords saved; no unsolicited assistance' `
        -Counters 'RDP brute force / pivoting (#465), MITM downgrade, Remote Assistance abuse' -Settings @(
        New-Reg "$CCS\Terminal Server\WinStations\RDP-Tcp" 'UserAuthentication' 1
        New-Reg "$CCS\Terminal Server\WinStations\RDP-Tcp" 'SecurityLayer' 2
        New-Reg "$CCS\Terminal Server\WinStations\RDP-Tcp" 'MinEncryptionLevel' 3
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'UserAuthentication' 1
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'SecurityLayer' 2
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'MinEncryptionLevel' 3
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'DisablePasswordSaving' 1
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowUnsolicited' 0
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowToGetHelp' 0)

    Add-RegControl -Module Lateral -Title 'Remote Desktop listener disabled' -Level Strict `
        -Counters 'RDP exposure / pivoting (#465)' -Settings @(
        New-Reg "$CCS\Terminal Server" 'fDenyTSConnections' 1)

    Add-RegControl -Module Lateral -Title 'WinRM: no Basic/Digest/unencrypted traffic, no RunAs credentials' `
        -Counters 'WinRM credential relay / downgrade, evil-winrm' -Settings @(
        New-Reg "$WINPOL\WinRM\Client" 'AllowBasic' 0
        New-Reg "$WINPOL\WinRM\Client" 'AllowUnencryptedTraffic' 0
        New-Reg "$WINPOL\WinRM\Client" 'AllowDigest' 0
        New-Reg "$WINPOL\WinRM\Service" 'AllowBasic' 0
        New-Reg "$WINPOL\WinRM\Service" 'AllowUnencryptedTraffic' 0
        New-Reg "$WINPOL\WinRM\Service" 'DisableRunAs' 1)

    Add-RegControl -Module Lateral -Title 'DCOM activation hardening (integrity + raised auth level)' `
        -Counters 'DCOM lateral movement via Excel.Application / MMC20 (#150, #530, #532)' -Settings @(
        New-Reg 'HKLM\SOFTWARE\Microsoft\Ole\AppCompat' 'RequireIntegrityActivationAuthenticationLevel' 1
        New-Reg 'HKLM\SOFTWARE\Microsoft\Ole\AppCompat' 'RaiseActivationAuthenticationLevel' 2)

    Add-RegControl -Module Lateral -Title 'Distributed COM disabled' -Level Strict -Reboot `
        -Counters 'DCOM lateral movement, Potato-family DCOM relay (#193)' -Settings @(
        New-Reg 'HKLM\SOFTWARE\Microsoft\Ole' 'EnableDCOM' 'N' 'String')

    Add-Control -Module Lateral -Title 'Firewall: all profiles on, inbound default Block, dropped packets logged' `
        -Counters 'Firewall monitoring (#137, #343), port scans, reverse shells' `
        -Test {
        param($c)
        foreach ($p in (Get-NetFirewallProfile)) {
            if ([string]$p.Enabled -ne 'True') { return $false }
            if ([string]$p.DefaultInboundAction -ne 'Block') { return $false }
            if ([string]$p.LogBlocked -ne 'True') { return $false }
            if ([int]$p.LogMaxSizeKilobytes -lt 16384) { return $false }
        }
        $true
    } `
        -Apply {
        param($c)
        Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -LogBlocked True -LogMaxSizeKilobytes 32767 -NotifyOnListen True
    }

    Add-Control -Module Lateral -Title 'Firewall: lateral-movement ports blocked inbound on Public networks' `
        -Counters 'SMB/RPC/WinRM/RDP exposure on hostile networks (#181, #465)' `
        -Test { param($c) Test-FwRule 'In-Lateral-Public' } `
        -Apply {
        param($c)
        New-CitadelBlockRule -Name 'In-Lateral-Public' -Direction Inbound -Protocol TCP `
            -LocalPort 135, 139, 445, 593, 3389, 5985, 5986 -FwProfile Public -Description 'Lateral movement ports on Public profile'
    }

    Add-Control -Module Lateral -Title 'Firewall: lateral-movement ports blocked inbound on every profile' -Level Strict `
        -Counters 'PsExec, WMI/DCOM, WinRM, RDP pivoting' `
        -Test { param($c) Test-FwRule 'In-Lateral-All' } `
        -Apply {
        param($c)
        New-CitadelBlockRule -Name 'In-Lateral-All' -Direction Inbound -Protocol TCP `
            -LocalPort 135, 139, 445, 593, 3389, 5985, 5986 -FwProfile Any -Description 'Lateral movement ports'
    }

    Add-Control -Module Lateral -Title 'Firewall: SMB/NetBIOS/RPC to the Internet blocked outbound' `
        -Counters 'SCF / Bad-PDF / Office-doc NTLM hash theft (#105, #339, #475), SMB delivery (#106)' `
        -Test { (Test-FwRule 'Out-SMB-Internet-TCP') -and (Test-FwRule 'Out-NetBIOS-Internet-UDP') } `
        -Apply {
        param($c)
        New-CitadelBlockRule -Name 'Out-SMB-Internet-TCP' -Direction Outbound -Protocol TCP -RemotePort 135, 139, 445 `
            -RemoteAddress Internet -Description 'Stop NTLM hash leakage to external hosts'
        New-CitadelBlockRule -Name 'Out-NetBIOS-Internet-UDP' -Direction Outbound -Protocol UDP -RemotePort 137, 138 `
            -RemoteAddress Internet -Description 'Stop NetBIOS leakage to external hosts'
    }

    # ---- Privilege escalation / UAC ---------------------------------------------------------
    Add-RegControl -Module Privesc -Title 'UAC at maximum: secure desktop, always notify, installer detection' `
        -Counters 'Fileless UAC bypass: eventvwr, sdclt, fodhelper, slui, disk-cleanup, COM hijack (#99, #147, #148, #165, #272, #336, #337)' -Settings @(
        New-Reg $POLSYS 'EnableLUA' 1
        New-Reg $POLSYS 'ConsentPromptBehaviorAdmin' 2
        New-Reg $POLSYS 'ConsentPromptBehaviorUser' 1
        New-Reg $POLSYS 'PromptOnSecureDesktop' 1
        New-Reg $POLSYS 'EnableInstallerDetection' 1
        New-Reg $POLSYS 'EnableSecureUIAPaths' 1
        New-Reg $POLSYS 'EnableVirtualization' 1)

    Add-RegControl -Module Privesc -Title 'AlwaysInstallElevated disabled (machine + user)' `
        -Counters 'MSI privilege escalation (#78, #79, #297)' -Settings @(
        New-Reg "$WINPOL\Installer" 'AlwaysInstallElevated' 0
        New-Reg 'HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0)

    Add-RegControl -Module Privesc -Title 'Print Spooler: no remote RPC endpoint, admin-only driver install, RPC privacy' `
        -Counters 'PrintNightmare, Potato/spooler coercion (#193)' -Settings @(
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers' 'RegisterSpoolerRemoteRpcEndPoint' 2
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'RestrictDriverInstallationToAdministrators' 1
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'NoWarningNoElevationOnInstall' 0
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'UpdatePromptSettings' 0
        New-Reg "$CCS\Print" 'RpcAuthnLevelPrivacyEnabled' 1)

    Add-Control -Module Privesc -Title 'No unquoted service paths' `
        -Counters 'Unquoted service path privesc (#78, #79, #299, #395)' `
        -Test { param($c) @(Get-UnquotedServiceImagePaths).Count -eq 0 } `
        -Apply {
        param($c)
        foreach ($u in (Get-UnquotedServiceImagePaths)) {
            $type = if ($u.Kind -eq 'ExpandString') { 'ExpandString' } else { 'String' }
            Set-Reg -Path $u.Path -Name 'ImagePath' -Value $u.Fixed -Type $type
        }
    }

    Add-RegControl -Module Privesc -Title 'DLL search order hardened (SafeDllSearch, no CWD from network, protected symlinks)' `
        -Counters 'DLL hijacking / planting (#60, #61, #435), WebDAV DLL load' -Settings @(
        New-Reg "$CCS\Session Manager" 'SafeDllSearchMode' 1
        New-Reg "$CCS\Session Manager" 'CWDIllegalInDllSearch' 2
        New-Reg "$CCS\Session Manager" 'ProtectionMode' 1)

    Add-RegControl -Module Privesc -Title 'AppInit_DLLs loading disabled (64 and 32 bit)' `
        -Counters 'DLL injection persistence (#60, #207, #215)' -Settings @(
        New-Reg 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'LoadAppInit_DLLs' 0
        New-Reg 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'RequireSignedAppInit_DLLs' 1
        New-Reg 'HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows' 'LoadAppInit_DLLs' 0
        New-Reg 'HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows' 'RequireSignedAppInit_DLLs' 1)

    # ---- Scripting / PowerShell ------------------------------------------------------------
    Add-RegControl -Module Scripting -Title 'PowerShell script-block, module and invocation logging' `
        -Counters 'Empire / PowerShell payloads / Invoke-PowerCloud (#19, #144, #146, #446)' -Settings @(
        New-Reg "$WINPOL\PowerShell\ScriptBlockLogging" 'EnableScriptBlockLogging' 1
        New-Reg "$WINPOL\PowerShell\ScriptBlockLogging" 'EnableScriptBlockInvocationLogging' 1
        New-Reg "$WINPOL\PowerShell\ModuleLogging" 'EnableModuleLogging' 1
        New-Reg "$WINPOL\PowerShell\ModuleLogging\ModuleNames" '*' '*' 'String')

    Add-Control -Module Scripting -Title 'PowerShell transcription to a write-only directory' -Level Strict `
        -Counters 'Post-exploitation shell forensics (#76, #375, #473)' `
        -Data @{ Dir = $script:Dirs.PSLogs } `
        -Test {
        param($c)
        Test-RegSettings -Settings @(
            (New-Reg "$WINPOL\PowerShell\Transcription" 'EnableTranscripting' 1)
            (New-Reg "$WINPOL\PowerShell\Transcription" 'EnableInvocationHeader' 1)
            (New-Reg "$WINPOL\PowerShell\Transcription" 'OutputDirectory' $c.Data.Dir 'String'))
    } `
        -Apply {
        param($c)
        if (-not (Test-Path -LiteralPath $c.Data.Dir)) { New-Item -ItemType Directory -Path $c.Data.Dir -Force | Out-Null }
        Invoke-Native -File "$env:windir\System32\icacls.exe" -Arguments @($c.Data.Dir, '/grant', '*S-1-5-32-545:(OI)(CI)(WD,AD,X)') | Out-Null
        Set-RegSettings -Settings @(
            (New-Reg "$WINPOL\PowerShell\Transcription" 'EnableTranscripting' 1)
            (New-Reg "$WINPOL\PowerShell\Transcription" 'EnableInvocationHeader' 1)
            (New-Reg "$WINPOL\PowerShell\Transcription" 'OutputDirectory' $c.Data.Dir 'String'))
    }

    Add-RegControl -Module Scripting -Title 'Windows Script Host disabled (VBS/JS/WSF/HTA launchers)' -Level Strict `
        -Counters 'Macro/phishing droppers, JScript/VBScript stagers (#171, #234)' -Settings @(
        New-Reg 'HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled' 0
        New-Reg 'HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows Script Host\Settings' 'Enabled' 0)

    $notepad = '%SystemRoot%\system32\NOTEPAD.EXE "%1"'
    $assoc = @()
    foreach ($progId in 'JSFile', 'JSEFile', 'VBSFile', 'VBEFile', 'WSFFile', 'WSHFile', 'htafile') {
        $assoc += , (New-Reg "HKLM\SOFTWARE\Classes\$progId\Shell\Open\Command" '' $notepad 'ExpandString')
    }
    Add-RegControl -Module Scripting -Title 'Double-click on script types opens Notepad instead of executing' -Level Strict `
        -Counters 'Phishing attachments with .js/.vbs/.wsf/.hta (#127, #172)' -Settings $assoc

    # ---- Office / phishing / browsers ------------------------------------------------------
    $officeSettings = @()
    foreach ($app in 'word', 'excel', 'powerpoint') {
        $sec = "HKLM\SOFTWARE\Policies\Microsoft\Office\16.0\$app\Security"
        $officeSettings += , (New-Reg $sec 'blockcontentexecutionfrominternet' 1)
        $officeSettings += , (New-Reg $sec 'VBAWarnings' (& $strictValue 3 4))
        $officeSettings += , (New-Reg $sec 'AccessVBOM' 0)
        $officeSettings += , (New-Reg "$sec\ProtectedView" 'DisableInternetFilesInPV' 0)
        $officeSettings += , (New-Reg "$sec\ProtectedView" 'DisableAttachmentsInPV' 0)
        $officeSettings += , (New-Reg "$sec\ProtectedView" 'DisableUnsafeLocationsInPV' 0)
    }
    $xlSec = 'HKLM\SOFTWARE\Policies\Microsoft\Office\16.0\excel\Security\ExternalContent'
    $officeSettings += , (New-Reg $xlSec 'DisableDDEServerLaunch' 1)
    $officeSettings += , (New-Reg $xlSec 'DisableDDEServerLookup' 1)
    $officeSettings += , (New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Office\Common\Security' 'DisableAllActiveX' 1)
    Add-RegControl -Module Phishing -Title 'Office: internet macros blocked, Protected View on, DDE and ActiveX disabled' `
        -Counters 'Malicious macros, DDE attacks, ActiveX macros, Protected View bypass (#149, #172, #366, #424, #527, #536)' `
        -When { param($c) Test-OfficeInstalled } -Settings $officeSettings

    Add-RegControl -Module Phishing -Title 'Office (current user): Word DDE disabled, unsafe Outlook rules blocked' `
        -Counters 'DDE auto-exec (#424), Outlook rule/home-page RCE' `
        -When { param($c) Test-OfficeInstalled } -Settings @(
        New-Reg 'HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Security' 'AllowDDE' 0
        New-Reg 'HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\Outlook\Security' 'EnableUnsafeClientMailRules' 0
        New-Reg 'HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\Outlook\Security' 'ShowLevel1Attach' 0)

    Add-RegControl -Module Phishing -Title 'Enhanced Phishing Protection and SmartScreen enforced' `
        -Counters 'Credential phishing, Evilginx 2FA proxy (#524), spear phishing (#127), malicious downloads' -Settings @(
        New-Reg "$WINPOL\WTDS\Components" 'ServiceEnabled' 1
        New-Reg "$WINPOL\WTDS\Components" 'NotifyMalicious' 1
        New-Reg "$WINPOL\WTDS\Components" 'NotifyPasswordReuse' 1
        New-Reg "$WINPOL\WTDS\Components" 'NotifyUnsafeApp' 1
        New-Reg "$WINPOL\System" 'EnableSmartScreen' 1
        New-Reg "$WINPOL\System" 'ShellSmartScreenLevel' (& $strictValue 'Warn' 'Block') 'String')

    Add-RegControl -Module Phishing -Title 'Edge and Chrome hardening policies' `
        -Counters 'Drive-by downloads, TLS-stripping, typosquatting, credential theft in browser (#26, #27, #524)' -Settings @(
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled' 1
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenPuaEnabled' 1
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Edge' 'PreventSmartScreenPromptOverride' 1
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Edge' 'PreventSmartScreenPromptOverrideForFiles' 1
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Edge' 'SSLErrorOverrideAllowed' 0
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Edge' 'SitePerProcess' 1
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Edge' 'TyposquattingCheckerEnabled' 1
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Edge' 'BasicAuthOverHttpEnabled' 0
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Edge' 'DnsOverHttpsMode' 'automatic' 'String'
        New-Reg 'HKLM\SOFTWARE\Policies\Google\Chrome' 'SafeBrowsingProtectionLevel' 1
        New-Reg 'HKLM\SOFTWARE\Policies\Google\Chrome' 'SitePerProcess' 1
        New-Reg 'HKLM\SOFTWARE\Policies\Google\Chrome' 'SSLErrorOverrideAllowed' 0
        New-Reg 'HKLM\SOFTWARE\Policies\Google\Chrome' 'BasicAuthOverHttpEnabled' 0)

    Add-RegControl -Module Phishing -Title 'Lock screen leaks closed (Cortana, clipboard, notifications, account details)' `
        -Counters 'Clipboard access from lock screen (#362), shoulder-surf / physical recon' -Settings @(
        New-Reg "$WINPOL\Windows Search" 'AllowCortanaAboveLock' 0
        New-Reg "$WINPOL\System" 'AllowClipboardHistory' 0
        New-Reg "$WINPOL\System" 'AllowCrossDeviceClipboard' 0
        New-Reg "$WINPOL\System" 'DisableLockScreenAppNotifications' 1
        New-Reg $POLSYS 'DontDisplayLockedUserId' 3
        New-Reg $POLSYS 'DisableAutomaticRestartSignOn' 1
        New-Reg $POLSYS 'InactivityTimeoutSecs' 900)

    # ---- Defender / ASR ---------------------------------------------------------------------
    $defenderWhen = { param($c) Test-DefenderActive }

    Add-Control -Module Defender -Title 'Defender: real-time, behaviour, script/AMSI scanning, cloud protection, PUA, Network Protection' `
        -Counters 'Empire, Meterpreter, TheFatRat, miners, C2 beacons (#144, #480, #371, #556)' -When $defenderWhen `
        -Data @{ Prefs = [ordered]@{
                DisableRealtimeMonitoring       = $false
                DisableBehaviorMonitoring       = $false
                DisableIOAVProtection           = $false
                DisableScriptScanning           = $false
                DisableBlockAtFirstSeen         = $false
                DisableArchiveScanning          = $false
                DisableEmailScanning            = $false
                DisableRemovableDriveScanning   = $false
                MAPSReporting                   = 2
                SubmitSamplesConsent            = 1
                CloudBlockLevel                 = 2
                CloudExtendedTimeout            = 50
                PUAProtection                   = 1
                EnableNetworkProtection         = 1
            }
        } `
        -Test {
        param($c)
        $p = Get-MpPreference
        foreach ($k in $c.Data.Prefs.Keys) {
            if ([string]$p.$k -ne [string]$c.Data.Prefs[$k]) { return $false }
        }
        $true
    } `
        -Apply {
        param($c)
        $splat = @{}
        foreach ($k in $c.Data.Prefs.Keys) { $splat[$k] = $c.Data.Prefs[$k] }
        Set-MpPreference @splat
    }

    Add-Control -Module Defender -Title 'Defender: Controlled Folder Access' `
        -Counters 'Ransomware, wipers (#155, #483, #548)' -When $defenderWhen `
        -Test {
        param($c)
        $v = [int](Get-MpPreference).EnableControlledFolderAccess
        if ($script:IsStrict) { $v -eq 1 } else { $v -in 1, 2 }
    } `
        -Apply {
        param($c)
        $mode = if ($script:IsStrict) { 1 } else { 2 }
        Set-MpPreference -EnableControlledFolderAccess $mode
    }

    $asr = @(
        @{ G = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'; N = 'Office apps spawning child processes'; Std = 1 }
        @{ G = '3b576869-a4ec-4529-8536-b80a7769e899'; N = 'Office creating executable content'; Std = 1 }
        @{ G = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'; N = 'Office injecting code into processes'; Std = 1 }
        @{ G = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'; N = 'Win32 API calls from Office macros'; Std = 1 }
        @{ G = '26190899-1602-49e8-8b27-eb1d0a1ce869'; N = 'Office communication apps spawning children'; Std = 1 }
        @{ G = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; N = 'Credential stealing from LSASS'; Std = 1 }
        @{ G = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'; N = 'Executable content from email'; Std = 1 }
        @{ G = 'd3e037e1-3eb8-44c8-a917-57927947596d'; N = 'JS/VBS launching downloaded executables'; Std = 1 }
        @{ G = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'; N = 'Obfuscated scripts'; Std = 1 }
        @{ G = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'; N = 'Adobe Reader spawning children'; Std = 1 }
        @{ G = 'c1db55ab-c21a-4637-bb3f-a12568109d35'; N = 'Advanced ransomware protection'; Std = 1 }
        @{ G = '56a863a9-875e-4185-98a7-b882c64b5ce5'; N = 'Abuse of vulnerable signed drivers'; Std = 1 }
        @{ G = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'; N = 'WMI event-subscription persistence'; Std = 1 }
        @{ G = 'a8f5898e-1dc8-49a9-9878-85004b8a61e6'; N = 'Webshell creation'; Std = 1 }
        @{ G = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'; N = 'Process creation from PSExec/WMI'; Std = 2 }
        @{ G = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'; N = 'Untrusted/unsigned processes from USB'; Std = 2 }
        @{ G = '01443614-cd74-433a-b99e-2ecdc07bfc25'; N = 'Executables failing prevalence/age/trust'; Std = 2 }
        @{ G = 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb'; N = 'Copied or impersonated system tools'; Std = 2 }
    )
    Add-Control -Module Defender -Title 'Defender Attack Surface Reduction rules' `
        -Counters 'Macro/Office payloads, LSASS theft, WMI/PsExec persistence & lateral movement, script droppers, USB droppers (#76, #150, #172, #386, #477)' `
        -When $defenderWhen -Data @{ Rules = $asr } `
        -Test {
        param($c)
        $p = Get-MpPreference
        $ids = @($p.AttackSurfaceReductionRules_Ids)
        $act = @($p.AttackSurfaceReductionRules_Actions)
        $cur = @{}
        for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i]) { $cur[([string]$ids[$i]).ToLowerInvariant()] = [int]$act[$i] } }
        foreach ($r in $c.Data.Rules) {
            $want = if ($script:IsStrict) { 1 } else { $r.Std }
            $have = $cur[$r.G]
            if ($null -eq $have) { return $false }
            if ($have -eq $want) { continue }
            if ($want -eq 2 -and $have -eq 1) { continue }
            return $false
        }
        $true
    } `
        -Apply {
        param($c)
        $ids = @(); $acts = @()
        foreach ($r in $c.Data.Rules) {
            $ids += $r.G
            $acts += $(if ($script:IsStrict) { 1 } else { $r.Std })
        }
        Add-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $acts
    }

    # ---- LOLBins / application control -----------------------------------------------------
    Add-Control -Module LOLBins -Title 'Firewall: living-off-the-land binaries cannot talk to the network' `
        -Counters 'regsvr32/mshta/certutil/bitsadmin/msbuild/wmic download-and-execute (#75, #171, #241, #361, #453, #529)' `
        -Test {
        param($c)
        foreach ($p in (Get-LolbinPaths)) { if (-not (Test-FwRule (Get-LolbinRuleName $p))) { return $false } }
        $true
    } `
        -Apply {
        param($c)
        foreach ($p in (Get-LolbinPaths)) {
            New-CitadelBlockRule -Name (Get-LolbinRuleName $p) -Direction Outbound -Program $p `
                -Description "Block outbound traffic from $p"
        }
    }

    if ($AppLocker -ne 'Off') {
        Add-Control -Module LOLBins -Title "AppLocker: default-deny outside Windows/Program Files ($AppLocker)" `
            -Counters 'Execution from %TEMP%/Downloads/AppData: droppers, Metasploit/Empire stagers, AppLocker abuse baseline (#241, #452)' `
            -When { param($c) [bool](Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue) } `
            -Data @{ Mode = $(if ($AppLocker -eq 'Enforce') { 'Enabled' } else { 'AuditOnly' }) } `
            -Test {
            param($c)
            $xml = [string](Get-AppLockerPolicy -Effective -Xml)
            ($xml -match 'Citadel:') -and ($xml -match ('EnforcementMode="{0}"' -f $c.Data.Mode))
        } `
            -Apply {
            param($c)
            $orig = Join-Path $script:Dirs.Backup ("applocker-original-{0}.xml" -f $script:Stamp)
            [string](Get-AppLockerPolicy -Local -Xml) | Set-Content -LiteralPath $orig -Encoding UTF8
            $script:Backup.Add([pscustomobject]@{ Type = 'AppLocker'; File = $orig })
            $tmp = Join-Path $env:TEMP ("citadel-al-{0}.xml" -f ([guid]::NewGuid().ToString('N')))
            New-AppLockerXml -EnforcementMode $c.Data.Mode | Set-Content -LiteralPath $tmp -Encoding UTF8
            try { Set-AppLockerPolicy -XmlPolicy $tmp } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
            Invoke-Native -File "$env:windir\System32\sc.exe" -Arguments @('config', 'appidsvc', 'start=', 'auto') | Out-Null
            Invoke-Native -File "$env:windir\System32\sc.exe" -Arguments @('start', 'appidsvc') | Out-Null
        }
    }

    # ---- Memory / kernel / exploit mitigations ---------------------------------------------
    Add-Control -Module Memory -Title 'System-wide exploit mitigations: DEP, SEHOP, bottom-up and high-entropy ASLR' `
        -Counters 'ASLR bypass / ROP / SEH overwrite exploit dev (#415), memory hacking (#260), kernel exploits (#74)' `
        -Test {
        param($c)
        $m = Get-ProcessMitigation -System
        ([string]$m.Dep.Enable -eq 'ON') -and ([string]$m.Sehop.Enable -eq 'ON') -and
        ([string]$m.Aslr.BottomUp -eq 'ON') -and ([string]$m.Aslr.HighEntropy -eq 'ON')
    } `
        -Apply {
        param($c)
        Set-ProcessMitigation -System -Enable DEP, SEHOP, BottomUp, HighEntropy
    }

    Add-Control -Module Memory -Title 'Mandatory ASLR (ForceRelocateImages) system-wide' -Level Strict `
        -Counters 'Non-ASLR module ROP gadgets (#415)' `
        -Test { param($c) [string](Get-ProcessMitigation -System).Aslr.ForceRelocateImages -eq 'ON' } `
        -Apply { param($c) Set-ProcessMitigation -System -Enable ForceRelocateImages }

    Add-RegControl -Module Memory -Title 'Microsoft vulnerable-driver blocklist enabled' `
        -Counters 'BYOVD kernel exploitation (#74, #422)' -Reboot -Settings @(
        New-Reg "$CCS\CI\Config" 'VulnerableDriverBlocklistEnable' 1)

    Add-RegControl -Module Memory -Title 'Memory integrity (HVCI) enabled' -Level Strict -Reboot `
        -Counters 'Kernel code injection, unsigned driver loading (#74, #422, #423)' -Settings @(
        New-Reg "$CCS\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" 'Enabled' 1)

    Add-RegControl -Module Memory -Title 'Kernel DMA / BitLocker DMA-under-lock protections' `
        -Counters 'DMA attacks (PCILeech, Thunderbolt), cold-boot style memory theft' -Settings @(
        New-Reg "$WINPOL\Kernel DMA Protection" 'DeviceEnumerationPolicy' (& $strictValue 1 0)
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\FVE' 'DisableExternalDMAUnderLock' 1)

    Add-Control -Module Memory -Title 'Hibernation off and pagefile wiped at shutdown (secrets in swap/hiberfil)' -Level Strict `
        -Counters 'Offline memory forensics: hiberfil.sys / pagefile.sys credential extraction' -Reboot `
        -Test {
        param($c)
        (Test-RegSettings -Settings @(
                (New-Reg "$CCS\Power" 'HibernateEnabled' 0)
                (New-Reg "$CCS\Session Manager\Memory Management" 'ClearPageFileAtShutdown' 1)))
    } `
        -Apply {
        param($c)
        Set-Reg -Path "$CCS\Session Manager\Memory Management" -Name 'ClearPageFileAtShutdown' -Value 1
        Set-Reg -Path "$CCS\Power" -Name 'HibernateEnabled' -Value 0
        Invoke-Native -File "$env:windir\System32\powercfg.exe" -Arguments @('/hibernate', 'off') | Out-Null
    }

    Add-RegControl -Module Memory -Title 'Windows Update not disabled by policy; Microsoft Update enabled' `
        -Counters 'Unpatched kernel/userland exploits (#74, #214, #266)' -Settings @(
        New-Reg "$WINPOL\WindowsUpdate\AU" 'NoAutoUpdate' 0
        New-Reg 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'AllowMUUpdateService' 1)

    # ---- Network / C2 / crypto -------------------------------------------------------------
    Add-ServiceDisableControl -Module Network -Title 'WebClient (WebDAV redirector) service disabled' `
        -Counters 'WebDAV C2 (#46), WebDAV NTLM relay, WebDAV DLL/SCF payload delivery' -Services 'WebClient'

    Add-RegControl -Module Network -Title 'Legacy SSL 2.0/3.0 disabled; TLS 1.2 on; .NET strong crypto; DH >= 2048-bit' `
        -Counters 'Protocol downgrade / MITM credential capture (#2, #371)' -Settings (@(
            foreach ($p in 'SSL 2.0', 'SSL 3.0') {
                foreach ($s in 'Client', 'Server') {
                    New-Reg "$CCS\SecurityProviders\SCHANNEL\Protocols\$p\$s" 'Enabled' 0
                    New-Reg "$CCS\SecurityProviders\SCHANNEL\Protocols\$p\$s" 'DisabledByDefault' 1
                }
            }
            foreach ($s in 'Client', 'Server') {
                New-Reg "$CCS\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\$s" 'Enabled' 1
                New-Reg "$CCS\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\$s" 'DisabledByDefault' 0
            }
            foreach ($n in 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319', 'HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319') {
                New-Reg $n 'SchUseStrongCrypto' 1
                New-Reg $n 'SystemDefaultTlsVersions' 1
            }
            New-Reg "$CCS\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" 'ServerMinKeyBitLength' 2048
            New-Reg "$CCS\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" 'ClientMinKeyBitLength' 2048
        ))

    Add-RegControl -Module Network -Title 'TLS 1.0/1.1 and weak ciphers (RC4, DES, 3DES, NULL) disabled' -Level Strict `
        -Counters 'BEAST/SWEET32/RC4 downgrade and sniffing' -Reboot -Settings (@(
            foreach ($p in 'TLS 1.0', 'TLS 1.1') {
                foreach ($s in 'Client', 'Server') {
                    New-Reg "$CCS\SecurityProviders\SCHANNEL\Protocols\$p\$s" 'Enabled' 0
                    New-Reg "$CCS\SecurityProviders\SCHANNEL\Protocols\$p\$s" 'DisabledByDefault' 1
                }
            }
            foreach ($cph in 'NULL', 'DES 56/56', 'RC4 128/128', 'RC4 64/128', 'RC4 56/128', 'RC4 40/128', 'Triple DES 168') {
                New-Reg "$CCS\SecurityProviders\SCHANNEL\Ciphers\$cph" 'Enabled' 0
            }
        ))

    Add-Control -Module Network -Title 'DNS-Client operational logging enabled (feeds DNS-tunnel hunting)' `
        -Counters 'DNS C2 / DNS payload delivery (#19, #45)' `
        -Test { param($c) [bool](Get-WinEvent -ListLog 'Microsoft-Windows-DNS-Client/Operational').IsEnabled } `
        -Apply { param($c) Invoke-Native -File "$env:windir\System32\wevtutil.exe" -Arguments @('sl', 'Microsoft-Windows-DNS-Client/Operational', '/e:true', '/ms:67108864') | Out-Null }

    # ---- Wireless --------------------------------------------------------------------------
    Add-RegControl -Module Wireless -Title 'Wi-Fi Sense / automatic hotspot connection disabled' `
        -Counters 'Rogue AP / evil twin (#477), Wi-Fi Pumpkin, CoffeeMiner (#371)' -Settings @(
        New-Reg 'HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' 'AutoConnectAllowedOEM' 0
        New-Reg 'HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' 'WiFiSenseAllowed' 0)

    Add-Control -Module Wireless -Title 'No open (unencrypted) Wi-Fi profile auto-connects' `
        -Counters 'Rogue open AP capture, post-exploitation Wi-Fi profiles (#344), sniffing (#2)' `
        -Test { param($c) @(Get-WlanOpenProfiles | Where-Object { $_.Mode -ieq 'auto' }).Count -eq 0 } `
        -Apply {
        param($c)
        foreach ($p in (Get-WlanOpenProfiles | Where-Object { $_.Mode -ieq 'auto' -or $PurgeOpenWifi })) {
            if ($PurgeOpenWifi) {
                Invoke-Native -File "$env:windir\System32\netsh.exe" -Arguments @('wlan', 'delete', 'profile', "name=$($p.Name)") | Out-Null
            }
            else {
                $script:Backup.Add([pscustomobject]@{ Type = 'Wlan'; Name = $p.Name; Mode = $p.Mode })
                Invoke-Native -File "$env:windir\System32\netsh.exe" -Arguments @('wlan', 'set', 'profileparameter', "name=$($p.Name)", 'connectionmode=manual') | Out-Null
            }
        }
    }

    # ---- Physical / USB --------------------------------------------------------------------
    Add-RegControl -Module Physical -Title 'AutoRun / AutoPlay disabled for all drives' `
        -Counters 'USB droppers, Rubber Ducky payload follow-ups (#389), USBStealer (#221)' -Settings @(
        New-Reg 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255
        New-Reg 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 1
        New-Reg "$WINPOL\Explorer" 'NoAutoplayfornonVolume' 1
        New-Reg "$SVC\cdrom" 'AutoRun' 0)

    Add-RegControl -Module Physical -Title 'USB mass storage blocked' -Level Strict -Reboot `
        -Counters 'USBStealer / data exfiltration / malicious USB drives (#221)' -Settings @(
        New-Reg "$SVC\USBSTOR" 'Start' 4
        New-Reg "$CCS\StorageDevicePolicies" 'WriteProtect' 1)

    # ---- Logging / detection ---------------------------------------------------------------
    Add-RegControl -Module Logging -Title 'Process-creation auditing includes full command line; advanced audit policy forced' `
        -Counters 'Command-line forensics for every technique in this bible (#375, #421, #473)' -Settings @(
        New-Reg "$POLSYS\Audit" 'ProcessCreationIncludeCmdLine_Enabled' 1
        New-Reg "$CCS\Lsa" 'SCENoApplyLegacyAuditPolicy' 1)

    $audit = @(
        @{ G = '{0CCE922B-69AE-11D9-BED3-505054503030}'; N = 'Process Creation'; S = 1; F = 0 }
        @{ G = '{0CCE9215-69AE-11D9-BED3-505054503030}'; N = 'Logon'; S = 1; F = 1 }
        @{ G = '{0CCE9217-69AE-11D9-BED3-505054503030}'; N = 'Account Lockout'; S = 0; F = 1 }
        @{ G = '{0CCE921B-69AE-11D9-BED3-505054503030}'; N = 'Special Logon'; S = 1; F = 0 }
        @{ G = '{0CCE923F-69AE-11D9-BED3-505054503030}'; N = 'Credential Validation'; S = 1; F = 1 }
        @{ G = '{0CCE9235-69AE-11D9-BED3-505054503030}'; N = 'User Account Management'; S = 1; F = 1 }
        @{ G = '{0CCE9237-69AE-11D9-BED3-505054503030}'; N = 'Security Group Management'; S = 1; F = 1 }
        @{ G = '{0CCE921E-69AE-11D9-BED3-505054503030}'; N = 'Registry'; S = 1; F = 0 }
        @{ G = '{0CCE9227-69AE-11D9-BED3-505054503030}'; N = 'Other Object Access Events'; S = 1; F = 1 }
        @{ G = '{0CCE9228-69AE-11D9-BED3-505054503030}'; N = 'Sensitive Privilege Use'; S = 1; F = 1 }
        @{ G = '{0CCE9211-69AE-11D9-BED3-505054503030}'; N = 'Security System Extension'; S = 1; F = 1 }
        @{ G = '{0CCE9212-69AE-11D9-BED3-505054503030}'; N = 'System Integrity'; S = 1; F = 1 }
        @{ G = '{0CCE922F-69AE-11D9-BED3-505054503030}'; N = 'Audit Policy Change'; S = 1; F = 1 }
        @{ G = '{0CCE9230-69AE-11D9-BED3-505054503030}'; N = 'Authentication Policy Change'; S = 1; F = 0 }
        @{ G = '{0CCE9248-69AE-11D9-BED3-505054503030}'; N = 'Plug and Play Events'; S = 1; F = 0 }
        @{ G = '{0CCE9245-69AE-11D9-BED3-505054503030}'; N = 'Removable Storage'; S = 1; F = 1 }
    )
    Add-Control -Module Logging -Title 'Advanced audit policy for logon, process, account, task/service, registry, USB events' `
        -Counters 'Detection of brute force, new admins, persistence, lateral movement (#80, #421)' `
        -Data @{ Subs = $audit } `
        -Test {
        param($c)
        foreach ($s in $c.Data.Subs) {
            $cur = Get-AuditSetting -Guid $s.G
            if ($s.S -and $cur -notmatch 'Success') { return $false }
            if ($s.F -and $cur -notmatch 'Failure') { return $false }
        }
        $true
    } `
        -Apply {
        param($c)
        $bk = Join-Path $script:Dirs.Backup ("auditpol-{0}.csv" -f $script:Stamp)
        Invoke-Native -File "$env:windir\System32\auditpol.exe" -Arguments @('/backup', "/file:$bk") | Out-Null
        if (Test-Path -LiteralPath $bk) { $script:Backup.Add([pscustomobject]@{ Type = 'AuditPol'; File = $bk }) }
        foreach ($s in $c.Data.Subs) {
            $sw = if ($s.S) { '/success:enable' } else { '/success:disable' }
            $fw = if ($s.F) { '/failure:enable' } else { '/failure:disable' }
            if ($s.S -eq 0 -and $s.F -eq 0) { continue }
            Invoke-Native -File "$env:windir\System32\auditpol.exe" -Arguments @('/set', "/subcategory:$($s.G)", $sw, $fw) | Out-Null
        }
    }

    $logs = @(
        @{ Name = 'Security'; Size = 268435456 }
        @{ Name = 'Microsoft-Windows-PowerShell/Operational'; Size = 134217728 }
        @{ Name = 'Microsoft-Windows-TaskScheduler/Operational'; Size = 67108864 }
        @{ Name = 'Microsoft-Windows-WMI-Activity/Operational'; Size = 67108864 }
        @{ Name = 'Microsoft-Windows-Bits-Client/Operational'; Size = 33554432 }
        @{ Name = 'Microsoft-Windows-DNS-Client/Operational'; Size = 67108864 }
    )
    Add-Control -Module Logging -Title 'Event logs enabled and sized for forensics (Security 256MB, PowerShell, Task Scheduler, WMI, BITS, DNS)' `
        -Counters 'Log-clearing anti-forensics, WMI/BITS/task persistence (#154, #207)' -Data @{ Logs = $logs } `
        -Test {
        param($c)
        foreach ($l in $c.Data.Logs) {
            $i = Get-WinEvent -ListLog $l.Name -ErrorAction SilentlyContinue
            if (-not $i) { continue }
            if (-not $i.IsEnabled -or $i.MaximumSizeInBytes -lt $l.Size) { return $false }
        }
        $true
    } `
        -Apply {
        param($c)
        foreach ($l in $c.Data.Logs) {
            if (Get-WinEvent -ListLog $l.Name -ErrorAction SilentlyContinue) {
                Invoke-Native -File "$env:windir\System32\wevtutil.exe" -Arguments @('sl', $l.Name, '/e:true', "/ms:$($l.Size)") | Out-Null
            }
        }
    }

    # ---- Web (IIS host) --------------------------------------------------------------------
    $appcmd = "$env:windir\System32\inetsrv\appcmd.exe"
    Add-Control -Module Web -Title 'IIS: request filtering, hidden .git/.svn/.env, TRACE off, no dir browsing, security headers' `
        -Counters 'Exposed .git source disclosure (#49), XSS/clickjacking/MIME-sniff (#26, #27), info leak, TRACE, double-escape WAF bypass (#29)' `
        -When { param($c) Test-Path -LiteralPath "$env:windir\System32\inetsrv\appcmd.exe" } `
        -Data @{ Appcmd = $appcmd } `
        -Test {
        param($c)
        $rf = (Invoke-Native -File $c.Data.Appcmd -Arguments @('list', 'config', '/section:system.webServer/security/requestFiltering')).Output
        $hp = (Invoke-Native -File $c.Data.Appcmd -Arguments @('list', 'config', '/section:system.webServer/httpProtocol')).Output
        $db = (Invoke-Native -File $c.Data.Appcmd -Arguments @('list', 'config', '/section:system.webServer/directoryBrowse')).Output
        ($rf -match 'removeServerHeader="true"') -and ($rf -match 'segment="\.git"') -and ($rf -match 'verb="TRACE"') -and
        ($rf -match 'allowDoubleEscaping="false"') -and ($hp -match 'X-Content-Type-Options') -and ($db -match 'enabled="false"')
    } `
        -Apply {
        param($c)
        $a = $c.Data.Appcmd
        $rfSec = '/section:system.webServer/security/requestFiltering'
        Invoke-Appcmd -Exe $a -ArgList @('set', 'config', $rfSec, '/removeServerHeader:true', '/allowDoubleEscaping:false', '/commit:apphost')
        foreach ($seg in '.git', '.svn', '.hg', '.env', '.vscode', '.idea') {
            Invoke-Appcmd -Exe $a -ArgList @('set', 'config', $rfSec, "/+hiddenSegments.[segment='$seg']", '/commit:apphost')
        }
        foreach ($ext in '.bak', '.old', '.sql', '.swp', '.orig') {
            Invoke-Appcmd -Exe $a -ArgList @('set', 'config', $rfSec, "/+fileExtensions.[fileExtension='$ext',allowed='false']", '/commit:apphost')
        }
        foreach ($v in 'TRACE', 'TRACK') {
            Invoke-Appcmd -Exe $a -ArgList @('set', 'config', $rfSec, "/+verbs.[verb='$v',allowed='false']", '/commit:apphost')
        }
        Invoke-Appcmd -Exe $a -ArgList @('set', 'config', '/section:system.webServer/directoryBrowse', '/enabled:false', '/commit:apphost')
        Invoke-Appcmd -Exe $a -ArgList @('set', 'config', '/section:system.webServer/httpErrors', '/errorMode:DetailedLocalOnly', '/commit:apphost')
        $hdr = '/section:system.webServer/httpProtocol'
        Invoke-Appcmd -Exe $a -ArgList @('set', 'config', $hdr, "/-customHeaders.[name='X-Powered-By']", '/commit:apphost')
        $headers = [ordered]@{
            'X-Content-Type-Options' = 'nosniff'
            'X-Frame-Options'        = 'SAMEORIGIN'
            'Referrer-Policy'        = 'strict-origin-when-cross-origin'
        }
        if ($script:IsStrict) {
            $headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        }
        foreach ($k in $headers.Keys) {
            Invoke-Appcmd -Exe $a -ArgList @('set', 'config', $hdr, "/+customHeaders.[name='$k',value='$($headers[$k])']", '/commit:apphost')
        }
    }

    # ---- Services / optional features ------------------------------------------------------
    Add-ServiceDisableControl -Module Services -Title 'Recon/relay-friendly services disabled (Remote Registry, SSDP, UPnP, Telnet, LLTD, RPC Locator, SNMP, SimpleTCP)' `
        -Counters 'Network recon, remote registry persistence/backdooring (#185, #215)' `
        -Services 'RemoteRegistry', 'SSDPSRV', 'upnphost', 'TlntSvr', 'lltdsvc', 'RpcLocator', 'SNMP', 'simptcp'

    Add-ServiceDisableControl -Module Services -Title 'Print Spooler, WinRM, WPAD proxy service, FTP service disabled' -Level Strict `
        -Counters 'PrintNightmare/Potato (#193), evil-winrm, WPAD, FTP pentesting (#15)' `
        -Services 'Spooler', 'WinRM', 'WinHttpAutoProxySvc', 'FTPSVC'

    $stdFeatures = 'SMB1Protocol', 'SMB1Protocol-Client', 'SMB1Protocol-Server', 'MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2', 'TelnetClient', 'TFTP'
    Add-Control -Module Services -Title 'Legacy features removed: SMBv1, PowerShell 2.0, Telnet client, TFTP' `
        -Counters 'EternalBlue-class SMB exploits, PowerShell downgrade attacks to dodge AMSI/logging (#144, #171)' `
        -Data @{ Features = $stdFeatures } `
        -Test {
        param($c)
        foreach ($f in $c.Data.Features) { if ((Get-FeatureState $f) -eq 'Enabled') { return $false } }
        $true
    } `
        -Apply {
        param($c)
        foreach ($f in $c.Data.Features) {
            if ((Get-FeatureState $f) -eq 'Enabled') {
                $script:Backup.Add([pscustomobject]@{ Type = 'Feature'; Name = $f })
                Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart | Out-Null
                $script:FeatureCache[$f] = 'Disabled'
            }
        }
    }

    Add-Control -Module Services -Title 'Internet Explorer / MSHTML optional feature removed' -Level Strict `
        -Counters 'MSHTML / CHM / legacy IE engine exploits (#363)' `
        -Test { param($c) (Get-FeatureState 'Internet-Explorer-Optional-amd64') -ne 'Enabled' } `
        -Apply {
        param($c)
        $script:Backup.Add([pscustomobject]@{ Type = 'Feature'; Name = 'Internet-Explorer-Optional-amd64' })
        Disable-WindowsOptionalFeature -Online -FeatureName 'Internet-Explorer-Optional-amd64' -NoRestart | Out-Null
    }

    # ---- Accounts --------------------------------------------------------------------------
    Add-Control -Module Accounts -Title 'Guest account disabled' `
        -Counters 'Guest-account access bypass (#333)' `
        -Test {
        param($c)
        $g = Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-21-*-501' }
        (-not $g) -or (-not $g.Enabled)
    } `
        -Apply {
        param($c)
        $g = Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-21-*-501' }
        $script:Backup.Add([pscustomobject]@{ Type = 'Account'; Sid = $g.SID.Value })
        Disable-LocalUser -SID $g.SID
    }

    Add-Control -Module Accounts -Title 'Built-in Administrator (RID 500) disabled while another admin exists' -Level Strict `
        -Counters 'Well-known RID-500 brute force / pass-the-hash target' `
        -Test {
        param($c)
        $a = Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-21-*-500' }
        (-not $a) -or (-not $a.Enabled)
    } `
        -Apply {
        param($c)
        $a = Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-21-*-500' }
        $others = 0
        foreach ($m in (Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue)) {
            if ($m.ObjectClass -ne 'User' -or $m.SID.Value -like 'S-1-5-21-*-500') { continue }
            try { if ((Get-LocalUser -SID $m.SID -ErrorAction Stop).Enabled) { $others++ } } catch { $others++ }
        }
        if ($others -lt 1) { throw 'Refusing to disable the built-in Administrator: no other enabled administrator found.' }
        $script:Backup.Add([pscustomobject]@{ Type = 'Account'; Sid = $a.SID.Value })
        Disable-LocalUser -SID $a.SID
    }

    $minLen = if ($script:IsStrict) { 14 } else { 12 }
    Add-Control -Module Accounts -Title "Local password length >= $minLen and account lockout (5 tries / 15 min)" `
        -Counters 'Password spraying, brute force vs RDP/SMB/WinRM, hash cracking (#3, #59, #460)' `
        -Data @{ MinLen = $minLen } `
        -Test {
        param($c)
        $len = Get-SecPolValue 'MinimumPasswordLength'
        $bad = Get-SecPolValue 'LockoutBadCount'
        $dur = Get-SecPolValue 'LockoutDuration'
        $rst = Get-SecPolValue 'ResetLockoutCount'
        if ($null -eq $len -or $null -eq $bad) { return $false }
        ([int]$len -ge $c.Data.MinLen) -and ([int]$bad -ge 1) -and ([int]$bad -le 5) -and ([int]$dur -ge 15 -or [int]$dur -eq -1) -and ([int]$rst -ge 15)
    } `
        -Apply {
        param($c)
        Invoke-Native -File "$env:windir\System32\net.exe" -Arguments @('accounts', "/minpwlen:$($c.Data.MinLen)", '/lockoutthreshold:5', '/lockoutduration:15', '/lockoutwindow:15') | Out-Null
    }

    # ---- Posture (read-only checks that need hardware / human action) ---------------------
    Add-Control -Module Posture -Title 'Secure Boot enabled' -Manual -Remedy 'Enable Secure Boot in UEFI firmware.' `
        -Counters 'Bootkits, kernel persistence (#48)' `
        -Test { param($c) try { [bool](Confirm-SecureBootUEFI) } catch { $false } }

    Add-Control -Module Posture -Title 'TPM present and ready' -Manual -Remedy 'Enable the TPM / PTT in firmware, then run tpm.msc.' `
        -Counters 'Offline attacks on credentials and disks' `
        -Test { param($c) try { $t = Get-Tpm; [bool]($t.TpmPresent -and $t.TpmReady) } catch { $false } }

    Add-Control -Module Posture -Title 'BitLocker protecting the OS drive' -Manual `
        -Remedy 'Run: Enable-BitLocker -MountPoint C: -TpmProtector (or enable Device Encryption), and store the recovery key safely.' `
        -Counters 'Offline NTDS/SAM/SYSTEM hive theft (#1, #141), lost-device data theft' `
        -Test {
        param($c)
        try { [string](Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -eq 'On' } catch { $false }
    }

    Add-Control -Module Posture -Title 'Defender tamper protection on and signatures < 7 days old' -Manual `
        -Remedy 'Windows Security > Virus & threat protection > Manage settings > Tamper Protection (cannot be set by script); then run Update-MpSignature.' `
        -Counters 'Defender disabling by post-exploitation scripts' -When $defenderWhen `
        -Test {
        param($c)
        $s = Get-MpComputerStatus
        ($s.IsTamperProtected -eq $true) -and ($s.AntivirusSignatureAge -lt 7)
    }

    Add-Control -Module Posture -Title 'VBS services running (Credential Guard / HVCI)' -Manual -Level Strict `
        -Remedy 'Reboot after applying Strict mode; requires virtualization support and Secure Boot.' `
        -Counters 'LSASS and kernel exploit resilience' `
        -Test {
        param($c)
        try {
            $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'
            $run = @($dg.SecurityServicesRunning)
            ($run -contains 1) -and ($run -contains 2)
        }
        catch { $false }
    }

    Add-Control -Module Posture -Title 'Latest quality update installed within 45 days' -Manual `
        -Remedy 'Run Windows Update (Settings > Windows Update > Check for updates).' `
        -Counters 'Windows kernel exploits and exploit suggester hits (#74, #214)' `
        -Test {
        param($c)
        $latest = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        $latest -and (((Get-Date) - $latest.InstalledOn).TotalDays -le 45)
    }
}

# ----------------------------------------------------------------------------------------------
# Control engine
# ----------------------------------------------------------------------------------------------
function Invoke-ControlEngine {
    param([bool]$ApplyChanges)
    $results = New-Object System.Collections.Generic.List[object]
    $total = $script:Controls.Count
    $i = 0
    foreach ($c in $script:Controls) {
        $i++
        if ($c.Level -eq 'Strict' -and -not $script:IsStrict) { continue }
        if ($SkipModule -contains $c.Module) { continue }
        $status = 'PASS'
        $detail = ''
        try {
            if ($c.When -and -not [bool](& $c.When $c)) { $status = 'N/A' }
            elseif ([bool](& $c.Test $c)) { $status = 'PASS' }
            elseif (-not $ApplyChanges) {
                $status = 'FAIL'
                if ($c.Manual) { $detail = $c.Remedy }
            }
            elseif ($c.Manual -or -not $c.Apply) { $status = 'MANUAL'; $detail = $c.Remedy }
            elseif (-not $script:WhatIf) {
                & $c.Apply $c | Out-Null
                if ([bool](& $c.Test $c)) {
                    $status = 'APPLIED'
                    if ($c.Reboot) { $script:RebootNeeded = $true }
                }
                else {
                    $status = 'FAILED'
                    $detail = 'Applied but verification failed (reboot may be required, or a policy/MDM is overriding it).'
                    if ($c.Reboot) { $script:RebootNeeded = $true }
                }
            }
            else { $status = 'WHATIF' }
        }
        catch {
            $status = 'ERROR'
            $detail = $_.Exception.Message
        }
        $results.Add([pscustomobject]@{
                Id = $c.Id; Module = $c.Module; Status = $status; Level = $c.Level
                Title = $c.Title; Counters = $c.Counters; Detail = $detail
            })
        $color = switch ($status) {
            'PASS' { 'Green' } 'APPLIED' { 'Cyan' } 'FAIL' { 'Red' } 'FAILED' { 'Red' } 'ERROR' { 'Magenta' }
            'MANUAL' { 'Yellow' } default { 'DarkGray' }
        }
        Write-Info ('[{0,-7}] {1} {2,-11} {3}' -f $status, $c.Id, $c.Module, $c.Title) $color
        if ($detail) { Write-Info ('           -> {0}' -f $detail) DarkYellow }
    }
    $results
}

function Write-ControlSummary {
    param($Results, [string]$Label)
    $count = @{}
    foreach ($r in $Results) { $count[$r.Status] = 1 + [int]$count[$r.Status] }
    $good = [int]$count['PASS'] + [int]$count['APPLIED']
    $bad = [int]$count['FAIL'] + [int]$count['FAILED'] + [int]$count['ERROR'] + [int]$count['MANUAL']
    $score = if (($good + $bad) -gt 0) { [math]::Round(100 * $good / ($good + $bad)) } else { 100 }
    Write-Info ''
    Write-Info ('== {0}: score {1}% ({2} compliant, {3} outstanding) ==' -f $Label, $score, $good, $bad) White
    foreach ($k in $count.Keys | Sort-Object) { Write-Info ('   {0,-8} {1}' -f $k, $count[$k]) }
    $score
}

function Save-Report {
    param($Results, [string]$Kind)
    $base = Join-Path $script:Dirs.Reports ("{0}-{1}" -f $Kind, $script:Stamp)
    $Results | Export-Csv -LiteralPath "$base.csv" -NoTypeInformation -Encoding UTF8
    ConvertTo-Json -InputObject @($Results) -Depth 4 | Set-Content -LiteralPath "$base.json" -Encoding UTF8
    Write-Info "Report: $base.csv / .json" DarkGray
}

function Save-BackupFile {
    if ($script:Backup.Count -eq 0) { return $null }
    $file = Join-Path $script:Dirs.Backup ("backup-{0}.json" -f $script:Stamp)
    $doc = [pscustomobject]@{
        Tool = 'Citadel'; Version = $script:Version; Created = (Get-Date).ToString('o'); Level = $Level
        Computer = $env:COMPUTERNAME; Entries = $script:Backup.ToArray()
    }
    ConvertTo-Json -InputObject $doc -Depth 5 | Set-Content -LiteralPath $file -Encoding UTF8
    $file
}

function Invoke-Rollback {
    $file = $BackupFile
    if (-not $file) {
        $latest = Get-ChildItem -LiteralPath $script:Dirs.Backup -Filter 'backup-*.json' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $latest) { throw "No backup files found in $($script:Dirs.Backup)." }
        $file = $latest.FullName
    }
    Write-Info "Rolling back using $file" White
    $doc = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
    $entries = @($doc.Entries)
    [array]::Reverse($entries)
    $ok = 0; $fail = 0
    foreach ($e in $entries) {
        try {
            switch ($e.Type) {
                'Reg' {
                    if ($e.Existed) {
                        $v = $e.Value
                        $kind = [string]$e.Kind
                        if ($kind -eq 'Binary') {
                            $k = Open-HiveKey -Path $e.Path -Access Create
                            try { $k.SetValue($e.Name, [Convert]::FromBase64String([string]$v), [Microsoft.Win32.RegistryValueKind]::Binary) } finally { $k.Close() }
                        }
                        else { Set-Reg -Path $e.Path -Name $e.Name -Value $v -Type $kind }
                    }
                    else { Remove-Reg -Path $e.Path -Name $e.Name -NoBackup }
                }
                'Firewall' { Remove-NetFirewallRule -Name $e.Name -ErrorAction SilentlyContinue }
                'Feature' { Enable-WindowsOptionalFeature -Online -FeatureName $e.Name -NoRestart -All | Out-Null }
                'Account' { Enable-LocalUser -SID $e.Sid }
                'AuditPol' { Invoke-Native -File "$env:windir\System32\auditpol.exe" -Arguments @('/restore', "/file:$($e.File)") | Out-Null }
                'AppLocker' { Set-AppLockerPolicy -XmlPolicy $e.File }
                'Wlan' { Invoke-Native -File "$env:windir\System32\netsh.exe" -Arguments @('wlan', 'set', 'profileparameter', "name=$($e.Name)", "connectionmode=$($e.Mode)") | Out-Null }
            }
            $ok++
        }
        catch {
            $fail++
            Write-Info ("  rollback failed for {0} {1}: {2}" -f $e.Type, $e.Name, $_.Exception.Message) Red
        }
    }
    Write-Info ("Rollback complete: {0} restored, {1} failed. Reboot recommended." -f $ok, $fail) Cyan
    Write-Info 'Not rolled back by design: Defender settings, event-log sizing, net accounts policy, exploit-mitigation defaults, removed autologon password.' DarkGray
}

# ----------------------------------------------------------------------------------------------
# Threat hunting
# ----------------------------------------------------------------------------------------------
function Add-Finding {
    param(
        [ValidateSet('High', 'Medium', 'Low', 'Info')][string]$Severity,
        [string]$Category, [string]$Title, [string]$Detail = '', [scriptblock]$Fix, [hashtable]$FixData = @{}
    )
    $script:Findings.Add([pscustomobject]@{
            Severity = $Severity; Category = $Category; Title = $Title; Detail = $Detail; Fix = $Fix; FixData = $FixData
        })
}

$script:SuspiciousCmd = '(?i)(powershell|pwsh|cmd(\.exe)?|mshta|wscript|cscript|regsvr32|rundll32|certutil|bitsadmin|msbuild|cmstp).*((\s-(e|ec|enc|encodedcommand)\s)|-w(indowstyle)?\s+hidden|downloadstring|downloadfile|\biex\b|invoke-expression|frombase64string|https?://|\\\\[A-Za-z0-9._-]+\\|scrobj|javascript:|vbscript:|\.hta\b|/i:)'
$script:UserWritablePath = '(?i)\\(Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents)|ProgramData|Windows\\Temp|Users\\Public|Temp)\\.*\.(exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|hta|scr|wsf|lnk)'

$script:CmdPatterns = @(
    @{ S = 'High'; T = 'Credential-theft tooling'; R = '(?i)sekurlsa|mimikatz|lsadump::|kerberos::(ptt|golden)|privilege::debug|invoke-mimikatz' }
    @{ S = 'High'; T = 'LSASS memory dump'; R = '(?i)procdump.*lsass|comsvcs\.dll.*(minidump|#24)|rundll32.*comsvcs' }
    @{ S = 'High'; T = 'NTDS.dit / SAM / SYSTEM extraction'; R = '(?i)ntdsutil.*(ifm|snapshot)|vssadmin.*create\s+shadow|reg(\.exe)?\s+save\s+hklm\\(sam|system|security)' }
    @{ S = 'High'; T = 'Ransomware preparation'; R = '(?i)vssadmin.*delete\s+shadows|wbadmin.*delete\s+(catalog|backup)|bcdedit.*recoveryenabled\s+no' }
    @{ S = 'High'; T = 'Encoded PowerShell'; R = '(?i)powershell.*\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}' }
    @{ S = 'High'; T = 'PowerShell download cradle'; R = '(?i)(iex|invoke-expression).*(downloadstring|net\.webclient|invoke-webrequest|\biwr\b)|downloadstring\(' }
    @{ S = 'High'; T = 'Signed-binary proxy execution'; R = '(?i)mshta(\.exe)?\s+(https?:|vbscript:|javascript:)|regsvr32.*(/i:https?:|scrobj\.dll)|rundll32.*javascript:' }
    @{ S = 'Medium'; T = 'LOLBin download'; R = '(?i)certutil.*(-urlcache|-verifyctl).*http|bitsadmin.*/transfer' }
    @{ S = 'Medium'; T = 'Remote / persistent execution'; R = '(?i)wmic.*(process\s+call\s+create|/node:)|schtasks.*/create.*(/ru\s+system|powershell|cmd)|sc(\.exe)?\s+\\\\\S+\s+create' }
    @{ S = 'Medium'; T = 'Account / pivot changes'; R = '(?i)net1?\s+(user|localgroup)\s+.*\s/add|netsh.*portproxy' }
    @{ S = 'Medium'; T = 'Persistence / UAC-bypass registry write'; R = '(?i)reg(\.exe)?\s+add.*(\\Run(Once)?\b|Image File Execution Options|Winlogon|ms-settings|mscfile)' }
    @{ S = 'Medium'; T = 'Defender tampering'; R = '(?i)Set-MpPreference.*(DisableRealtimeMonitoring|ExclusionPath)|Add-MpPreference.*Exclusion' }
)

function ConvertFrom-EventData {
    param($WinEvent)
    $x = [xml]$WinEvent.ToXml()
    $h = @{}
    foreach ($d in $x.Event.EventData.Data) {
        $n = $d.GetAttribute('Name')
        if ($n) { $h[$n] = [string]$d.InnerText }
    }
    $h
}

function Find-UacHijack {
    $targets = @(
        @{ Check = 'HKCU\Software\Classes\ms-settings\Shell\Open\command'; Remove = 'HKCU\Software\Classes\ms-settings\Shell'; Tech = 'fodhelper / computerdefaults UAC bypass' }
        @{ Check = 'HKCU\Software\Classes\mscfile\shell\open\command'; Remove = 'HKCU\Software\Classes\mscfile\shell'; Tech = 'eventvwr / compmgmt UAC bypass' }
        @{ Check = 'HKCU\Software\Classes\exefile\shell\open\command'; Remove = 'HKCU\Software\Classes\exefile\shell\open'; Tech = 'exefile handler hijack' }
        @{ Check = 'HKCU\Software\Classes\Folder\shell\open\command'; Remove = 'HKCU\Software\Classes\Folder\shell\open'; Tech = 'sdclt / Folder handler UAC bypass' }
        @{ Check = 'HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command'; Remove = 'HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell'; Tech = 'slui/AppX handler UAC bypass' }
        @{ Check = 'HKCU\Software\Classes\ms-windows-store\Shell\Open\command'; Remove = 'HKCU\Software\Classes\ms-windows-store\Shell'; Tech = 'Windows Store handler UAC bypass' }
        @{ Check = 'HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe'; Remove = 'HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe'; Tech = 'sdclt App Paths UAC bypass' }
    )
    foreach ($t in $targets) {
        if (Test-RegKey -Path $t.Check) {
            $vals = Get-RegValueMap -Path $t.Check
            $detail = (($vals.Keys | ForEach-Object { "'$_'='$($vals[$_])'" }) -join '; ')
            Add-Finding High 'UAC bypass' "Registry hijack present: $($t.Tech)" "$($t.Check) => $detail" `
                { param($f) Remove-RegKeyQuarantined -Path $f.FixData.Path } @{ Path = $t.Remove }
        }
    }
    foreach ($n in 'windir', 'SystemRoot', 'systemroot') {
        $st = Get-RegState -Path 'HKCU\Environment' -Name $n
        if ($st.Exists) {
            Add-Finding High 'UAC bypass' "User environment override of %$n% (SilentCleanup / scheduled-task UAC bypass)" "HKCU\Environment\$n = $($st.Value)" `
                { param($f) Remove-Reg -Path 'HKCU\Environment' -Name $f.FixData.Name } @{ Name = $n }
        }
    }
    $clsidBase = 'HKCU\Software\Classes\CLSID'
    foreach ($g in (Get-RegSubKeyNames -Path $clsidBase)) {
        foreach ($sub in 'InprocServer32', 'LocalServer32', 'TreatAs', 'ScriptletURL') {
            $p = "$clsidBase\$g\$sub"
            if (Test-RegKey -Path $p) {
                $vals = Get-RegValueMap -Path $p
                $val = [string]($vals[''])
                Add-Finding Medium 'COM hijack' "Per-user COM registration $g\$sub" "$p => $val (verify - legitimate apps also register here)"
            }
        }
    }
}

function Remove-RegKeyQuarantined {
    param([string]$Path)
    $dump = [ordered]@{ Path = $Path; Removed = (Get-Date).ToString('o'); Values = (Get-RegValueMap -Path $Path) }
    $file = Join-Path $script:Dirs.Reports ("quarantine-{0}-{1}.json" -f $script:Stamp, ([guid]::NewGuid().ToString('N').Substring(0, 6)))
    ConvertTo-Json -InputObject $dump -Depth 4 | Set-Content -LiteralPath $file -Encoding UTF8
    $m = [regex]::Match($Path, '^(HKLM|HKCU)\\(.+)$')
    $root = if ($m.Groups[1].Value -eq 'HKLM') { [Microsoft.Win32.Registry]::LocalMachine } else { [Microsoft.Win32.Registry]::CurrentUser }
    $root.DeleteSubKeyTree($m.Groups[2].Value, $false)
}

function Find-Persistence {
    $runKeys = @(
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    foreach ($rk in $runKeys) {
        $map = Get-RegValueMap -Path $rk
        foreach ($n in $map.Keys) {
            $v = [string]$map[$n]
            if ($v -match $script:SuspiciousCmd) { Add-Finding High 'Persistence' "Suspicious autorun command ($n)" "$rk => $v" }
            elseif ($v -match $script:UserWritablePath) { Add-Finding Medium 'Persistence' "Autorun launches from a user-writable path ($n)" "$rk => $v" }
        }
    }
    $folders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    foreach ($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $folders += Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    }
    foreach ($f in $folders) {
        foreach ($i in (Get-ChildItem -LiteralPath $f -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $sev = if ($i.Extension -match '(?i)\.(ps1|vbs|js|hta|bat|cmd|exe|scr|wsf)$') { 'Medium' } else { 'Low' }
            Add-Finding $sev 'Persistence' "Startup folder item: $($i.Name)" $i.FullName
        }
    }
    $winlogon = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $shell = Get-RegState -Path $winlogon -Name 'Shell'
    if ($shell.Exists -and [string]$shell.Value -ne 'explorer.exe') { Add-Finding High 'Persistence' 'Winlogon Shell modified' "Shell = $($shell.Value)" }
    $ui = Get-RegState -Path $winlogon -Name 'Userinit'
    if ($ui.Exists -and ([string]$ui.Value).TrimEnd(',') -notmatch '(?i)^[a-z]:\\windows\\system32\\userinit\.exe$') {
        Add-Finding High 'Persistence' 'Winlogon Userinit modified' "Userinit = $($ui.Value)"
    }
    foreach ($n in 'Taskman', 'AppSetup') {
        $st = Get-RegState -Path $winlogon -Name $n
        if ($st.Exists) { Add-Finding High 'Persistence' "Winlogon $n value present" "$n = $($st.Value)" }
    }
    foreach ($k in 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $st = Get-RegState -Path $k -Name 'AppInit_DLLs'
        if ($st.Exists -and [string]$st.Value) { Add-Finding High 'Persistence' 'AppInit_DLLs populated (DLL injection into every GUI process)' "$k => $($st.Value)" }
    }
    $ac = Get-RegValueMap -Path "$CCS\Session Manager\AppCertDlls"
    foreach ($n in $ac.Keys) { Add-Finding High 'Persistence' "AppCertDlls entry $n" ([string]$ac[$n]) }
    $ifeo = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    foreach ($img in (Get-RegSubKeyNames -Path $ifeo)) {
        foreach ($val in 'Debugger', 'GlobalFlag') {
            $st = Get-RegState -Path "$ifeo\$img" -Name $val
            if ($st.Exists -and -not ($val -eq 'GlobalFlag' -and [int]$st.Value -eq 0)) {
                Add-Finding High 'Persistence' "IFEO $val set on $img (debugger hijack / sticky-keys backdoor)" "$ifeo\$img\$val = $($st.Value)"
            }
        }
    }
    $spe = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    foreach ($img in (Get-RegSubKeyNames -Path $spe)) {
        $st = Get-RegState -Path "$spe\$img" -Name 'MonitorProcess'
        if ($st.Exists) { Add-Finding High 'Persistence' "SilentProcessExit MonitorProcess on $img" ([string]$st.Value) }
    }
    $scr = Get-RegState -Path 'HKCU\Control Panel\Desktop' -Name 'SCRNSAVE.EXE'
    if ($scr.Exists -and [string]$scr.Value -and [string]$scr.Value -notmatch '(?i)^([a-z]:\\windows\\system32\\|%systemroot%\\system32\\)') {
        Add-Finding Medium 'Persistence' 'Screensaver executable outside System32' ([string]$scr.Value)
    }
    $netsh = Get-RegValueMap -Path 'HKLM\SOFTWARE\Microsoft\NetSh'
    foreach ($n in $netsh.Keys) {
        $dll = [string]$netsh[$n]
        if ($dll -match '[\\/]' -or -not (Test-Path -LiteralPath (Join-Path "$env:windir\System32" $dll))) {
            Add-Finding Medium 'Persistence' "Netsh helper DLL not in System32: $n" $dll
        }
    }
    $allowed = 'msv1_0', 'kerberos', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'livessp', 'scecli', 'rassfm', 'negoextender', 'wsauth', 'aadcloudap', 'msapsspc', 'schannel.dll'
    foreach ($n in 'Security Packages', 'Authentication Packages', 'Notification Packages') {
        $st = Get-RegState -Path "$CCS\Lsa" -Name $n
        if (-not $st.Exists) { continue }
        foreach ($p in @($st.Value) | ForEach-Object { ([string]$_) -split '[\s,]+' } | Where-Object { $_ -and $_ -ne '""' }) {
            if ($allowed -notcontains $p.ToLowerInvariant()) {
                Add-Finding High 'Credential theft' "Unexpected LSA $n entry '$p' (mimilib / memssp-style credential logger)" "$CCS\Lsa\$n"
            }
        }
    }
    foreach ($bin in 'sethc', 'utilman', 'osk', 'narrator', 'magnify', 'displayswitch', 'atbroker') {
        $path = "$env:windir\System32\$bin.exe"
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $sig = Get-AuthenticodeSignature -LiteralPath $path
        if ($sig.Status -ne 'Valid') {
            Add-Finding High 'Persistence' "Accessibility binary $bin.exe is not validly signed (replaced backdoor?)" "$path signature status: $($sig.Status)"
        }
    }
    foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })) {
        foreach ($a in $t.Actions) {
            $cmd = ("{0} {1}" -f $a.Execute, $a.Arguments)
            if ($t.TaskPath -eq '\Citadel\' -and $cmd.IndexOf($script:Dirs.Bin, [StringComparison]::OrdinalIgnoreCase) -ge 0) { continue }
            if ($cmd -match $script:SuspiciousCmd) { Add-Finding High 'Persistence' "Suspicious scheduled task: $($t.TaskPath)$($t.TaskName)" $cmd }
            elseif ($cmd -match $script:UserWritablePath) { Add-Finding Medium 'Persistence' "Scheduled task runs from user-writable path: $($t.TaskPath)$($t.TaskName)" $cmd }
        }
    }
    try {
        $ns = 'root\subscription'
        $consumers = @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction Stop |
            Where-Object { $_.Name -ne 'SCM Event Log Consumer' })
        foreach ($c in $consumers) {
            $cls = $c.CimClass.CimClassName
            $detail = switch ($cls) {
                'CommandLineEventConsumer' { $c.CommandLineTemplate }
                'ActiveScriptEventConsumer' { $c.ScriptText }
                default { $cls }
            }
            Add-Finding High 'WMI persistence' "Permanent WMI event consumer '$($c.Name)' ($cls)" ([string]$detail) {
                param($f)
                $cn = $f.FixData.Name
                Get-CimInstance -Namespace 'root\subscription' -ClassName __FilterToConsumerBinding | Where-Object { $_.Consumer -match [regex]::Escape("Name=`"$cn`"") } | Remove-CimInstance
                Get-CimInstance -Namespace 'root\subscription' -ClassName __EventConsumer | Where-Object { $_.Name -eq $cn } | Remove-CimInstance
            } @{ Name = $c.Name }
        }
        foreach ($f in @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'SCM Event Log Filter' })) {
            Add-Finding Medium 'WMI persistence' "WMI event filter '$($f.Name)'" ([string]$f.Query)
        }
    }
    catch { }
    try {
        foreach ($j in (Get-BitsTransfer -AllUsers -ErrorAction Stop)) {
            Add-Finding Medium 'C2 / persistence' "BITS job '$($j.DisplayName)' ($($j.JobState))" "Owner: $($j.OwnerAccount)"
        }
    }
    catch { }
}

function Find-ServiceWeakness {
    foreach ($u in (Get-UnquotedServiceImagePaths)) {
        Add-Finding Medium 'Privilege escalation' "Unquoted service path: $($u.Service)" $u.Raw
    }
    foreach ($name in (Get-RegSubKeyNames -Path $SVC)) {
        $st = Get-RegState -Path "$SVC\$name" -Name 'ImagePath'
        if (-not $st.Exists -or $st.Value -isnot [string]) { continue }
        $m = [regex]::Match([string]$st.Value, '^"?(?<exe>(?:[A-Za-z]:|%[^%]+%)\\[^"]+?\.(exe|sys))', 'IgnoreCase')
        if (-not $m.Success) { continue }
        $exe = [Environment]::ExpandEnvironmentVariables($m.Groups['exe'].Value)
        if (Test-UserWritable -Path $exe) {
            Add-Finding High 'Privilege escalation' "Service binary writable by non-admins: $name" $exe
        }
        elseif (Test-UserWritable -Path (Split-Path -Parent $exe)) {
            Add-Finding Medium 'Privilege escalation' "Service binary directory writable by non-admins: $name" (Split-Path -Parent $exe)
        }
    }
    $sysPath = [Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' | Where-Object { $_ }
    foreach ($d in $sysPath) {
        $dd = [Environment]::ExpandEnvironmentVariables($d)
        if (Test-UserWritable -Path $dd) { Add-Finding Medium 'Privilege escalation' 'System PATH directory writable by non-admins (DLL/EXE planting)' $dd }
    }
    foreach ($f in 'C:\unattend.xml', 'C:\Windows\Panther\Unattend.xml', 'C:\Windows\Panther\Unattend\Unattend.xml', 'C:\Windows\System32\sysprep\sysprep.xml', 'C:\Windows\System32\sysprep\unattend.xml') {
        if ((Test-Path -LiteralPath $f) -and ((Get-Content -LiteralPath $f -Raw -ErrorAction SilentlyContinue) -match '(?i)<(Password|AutoLogon)>')) {
            Add-Finding Medium 'Credential theft' 'Unattend/sysprep file with embedded credentials' $f
        }
    }
    $hosts = "$env:windir\System32\drivers\etc\hosts"
    if (Test-Path -LiteralPath $hosts) {
        foreach ($line in (Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue)) {
            $l = $line.Trim()
            if (-not $l -or $l.StartsWith('#')) { continue }
            if ($l -match '(?i)microsoft|windows|defender|symantec|kaspersky|avast|eset|mcafee|sophos|crowdstrike|sentinelone|malwarebytes') {
                Add-Finding High 'Defence evasion' 'Hosts file entry redirecting a security/update domain' $l
            }
            elseif ($l -match '(?i)\bwpad\b') { Add-Finding Medium 'Relay' 'Hosts file contains a WPAD entry' $l }
            else { Add-Finding Low 'Hosts file' 'Custom hosts entry' $l }
        }
    }
}

function Find-AccountAnomaly {
    try {
        foreach ($u in (Get-LocalUser)) {
            if ($u.Name.EndsWith('$')) { Add-Finding High 'Accounts' "Local account name ends with '$' (hidden backdoor account trick): $($u.Name)" "Enabled=$($u.Enabled)" }
            if ($u.Enabled -and -not $u.PasswordRequired -and $u.SID.Value -notlike '*-501') {
                Add-Finding Medium 'Accounts' "Enabled local account without required password: $($u.Name)" ''
            }
            if ($u.Enabled -and $u.SID.Value -like 'S-1-5-21-*-501') { Add-Finding Medium 'Accounts' 'Guest account is enabled' $u.Name }
        }
        $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [string]$_.Name })
        Add-Finding Info 'Accounts' "Local Administrators ($($admins.Count))" ($admins -join ', ')
    }
    catch { }
    try {
        $s = Get-MpPreference
        foreach ($pair in @(@('ExclusionPath', $s.ExclusionPath), @('ExclusionProcess', $s.ExclusionProcess), @('ExclusionExtension', $s.ExclusionExtension))) {
            foreach ($v in @($pair[1]) | Where-Object { $_ }) { Add-Finding Medium 'Defence evasion' "Defender $($pair[0])" ([string]$v) }
        }
        $st = Get-MpComputerStatus
        if (-not $st.RealTimeProtectionEnabled) { Add-Finding High 'Defence evasion' 'Defender real-time protection is OFF' '' }
        if (-not $st.AMServiceEnabled) { Add-Finding High 'Defence evasion' 'Defender service is not running' '' }
    }
    catch { }
}

function Find-NetworkAnomaly {
    $procs = @{}
    foreach ($p in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) { $procs[[int]$p.ProcessId] = $p }
    $lolbin = '^(mshta|regsvr32|rundll32|wscript|cscript|msbuild|certutil|bitsadmin|installutil|regasm|regsvcs|cmstp|odbcconf|wmic|hh|powershell|pwsh|cmd)\.exe$'
    $private = '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fe80|fc|fd|0\.0\.0\.0|::$)'
    $badPorts = 4444, 4443, 1337, 31337, 5555, 6666, 9001, 2323
    foreach ($c in (Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        $p = $procs[[int]$c.OwningProcess]
        if (-not $p) { continue }
        if ($c.State -eq 'Listen') {
            if ($p.ExecutablePath -and $p.ExecutablePath -match $script:UserWritablePath) {
                Add-Finding Medium 'Network' "Listener from user-writable path: $($p.Name) on port $($c.LocalPort)" $p.ExecutablePath
            }
            if ($badPorts -contains [int]$c.LocalPort) {
                Add-Finding Medium 'Network' "Listening on a common attack-framework port $($c.LocalPort)" "$($p.Name) (PID $($p.ProcessId))"
            }
            if ($c.LocalPort -in 21, 23, 69 -and $c.LocalAddress -notmatch '^(127\.|::1)') {
                Add-Finding Medium 'Network' "Cleartext service listening on port $($c.LocalPort)" "$($p.Name) (PID $($p.ProcessId))"
            }
        }
        elseif ($c.State -eq 'Established' -and $c.RemoteAddress -notmatch $private) {
            if ($p.Name -match $lolbin) {
                $sev = if ($p.Name -match '^(powershell|pwsh|cmd)\.exe$') { 'Medium' } else { 'High' }
                Add-Finding $sev 'C2' "$($p.Name) has an outbound connection to $($c.RemoteAddress):$($c.RemotePort)" ([string]$p.CommandLine)
            }
            elseif ($p.ExecutablePath -and $p.ExecutablePath -match $script:UserWritablePath -and ($badPorts -contains [int]$c.RemotePort)) {
                Add-Finding High 'C2' "User-path process connected to attack-framework port $($c.RemotePort)" "$($p.ExecutablePath) -> $($c.RemoteAddress)"
            }
        }
    }
}

function Find-EventAnomaly {
    $since7 = (Get-Date).AddDays(-7)
    $since1 = (Get-Date).AddDays(-1)

    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102; StartTime = $since7 } -ErrorAction SilentlyContinue)) {
        Add-Finding High 'Anti-forensics' 'Security event log was cleared' ("{0}" -f $e.TimeCreated)
    }
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104; StartTime = $since7 } -ErrorAction SilentlyContinue)) {
        Add-Finding High 'Anti-forensics' 'An event log was cleared (System 104)' ("{0}" -f $e.TimeCreated)
    }

    $failed = @{}
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since1 } -MaxEvents 3000 -ErrorAction SilentlyContinue)) {
        $d = ConvertFrom-EventData $e
        $ip = $d['IpAddress']
        if ($ip -and $ip -notin '-', '::1', '127.0.0.1') { $failed[$ip] = 1 + [int]$failed[$ip] }
    }
    foreach ($ip in $failed.Keys) {
        if ($failed[$ip] -ge 20) {
            $sev = if ($failed[$ip] -ge 100) { 'High' } else { 'Medium' }
            Add-Finding $sev 'Brute force' "$($failed[$ip]) failed logons from $ip in 24h (password spraying / RDP / SMB brute force)" ''
        }
    }

    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720; StartTime = $since7 } -ErrorAction SilentlyContinue)) {
        $d = ConvertFrom-EventData $e
        Add-Finding Medium 'Accounts' "Local account created: $($d['TargetUserName'])" ("by {0} at {1}" -f $d['SubjectUserName'], $e.TimeCreated)
    }
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4732; StartTime = $since7 } -ErrorAction SilentlyContinue)) {
        $d = ConvertFrom-EventData $e
        if ($d['TargetSid'] -eq 'S-1-5-32-544') {
            Add-Finding High 'Accounts' "Member added to local Administrators: $($d['MemberSid'])" ("by {0} at {1}" -f $d['SubjectUserName'], $e.TimeCreated)
        }
    }
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $since7 } -ErrorAction SilentlyContinue)) {
        $d = ConvertFrom-EventData $e
        $img = [string]$d['ImagePath']
        if ($img -match '(?i)%comspec%|powershell|cmd(\.exe)?\s+/c|\\\\|ADMIN\$|psexe|\\Temp\\|\\Users\\|-enc') {
            Add-Finding High 'Lateral movement' "Suspicious service installed: $($d['ServiceName'])" "$img at $($e.TimeCreated) (PsExec/Impacket/Metasploit psexec pattern)"
        }
    }
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4698; StartTime = $since7 } -ErrorAction SilentlyContinue)) {
        $d = ConvertFrom-EventData $e
        if (([string]$d['TaskName']) -notlike '\Citadel\*' -and ([string]$d['TaskContent']) -match $script:SuspiciousCmd) {
            Add-Finding High 'Persistence' "Suspicious scheduled task created: $($d['TaskName'])" "by $($d['SubjectUserName']) at $($e.TimeCreated)"
        }
    }

    $seen = @{}
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $since1 } -MaxEvents 8000 -ErrorAction SilentlyContinue)) {
        $d = ConvertFrom-EventData $e
        $cl = [string]$d['CommandLine']
        if (-not $cl) { continue }
        foreach ($pat in $script:CmdPatterns) {
            if ($cl -match $pat.R) {
                $key = "$($pat.T)|$cl"
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true
                $short = if ($cl.Length -gt 300) { $cl.Substring(0, 300) + '...' } else { $cl }
                Add-Finding $pat.S 'Command line' "$($pat.T)" ("{0} | {1}" -f $e.TimeCreated, $short)
                break
            }
        }
    }

    $psPat = '(?i)Invoke-Mimikatz|Invoke-Shellcode|Invoke-ReflectivePEInjection|Invoke-Kerberoast|Invoke-BloodHound|SharpHound|Invoke-DCSync|PowerView|Get-GPPPassword|amsiInitFailed|AmsiUtils|Invoke-PowerShellTcp|Invoke-TokenManipulation|Out-Minidump|Invoke-WMIExec|Invoke-SMBExec|Invoke-Inveigh|Invoke-Portscan'
    $psSeen = @{}
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $since1 } -MaxEvents 3000 -ErrorAction SilentlyContinue)) {
        $m = [regex]::Match([string]$e.Message, $psPat)
        if ($m.Success -and -not $psSeen.ContainsKey($m.Value.ToLowerInvariant())) {
            $psSeen[$m.Value.ToLowerInvariant()] = $true
            Add-Finding High 'PowerShell' "Offensive PowerShell content in script block log: $($m.Value)" ("at {0}" -f $e.TimeCreated)
        }
    }

    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117, 5001, 5007; StartTime = $since7 } -ErrorAction SilentlyContinue)) {
        switch ($e.Id) {
            1116 { Add-Finding High 'Malware' 'Defender detected malware' ("{0}" -f $e.TimeCreated) }
            5001 { Add-Finding High 'Defence evasion' 'Defender real-time protection was disabled' ("{0}" -f $e.TimeCreated) }
            5007 { if ([string]$e.Message -match '(?i)exclusion') { Add-Finding Medium 'Defence evasion' 'Defender exclusion configuration changed' ("{0}" -f $e.TimeCreated) } }
        }
    }

    $dns = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-DNS-Client/Operational'; Id = 3006; StartTime = (Get-Date).AddHours(-2) } -MaxEvents 20000 -ErrorAction SilentlyContinue)
    if ($dns.Count -gt 0) {
        $groups = @{}
        foreach ($e in $dns) {
            $q = [string]$e.Properties[0].Value
            if (-not $q) { continue }
            $q = $q.TrimEnd('.').ToLowerInvariant()
            $labels = $q -split '\.'
            if ($labels.Count -lt 3 -or $q -match '\.(local|arpa|lan|home)$') { continue }
            $parent = ($labels[-2..-1]) -join '.'
            if (-not $groups.ContainsKey($parent)) { $groups[$parent] = @{ Names = @{}; Max = 0; Sum = 0; N = 0 } }
            $g = $groups[$parent]
            $g.Names[$q] = 1
            $g.N++
            $g.Sum += $q.Length
            if ($q.Length -gt $g.Max) { $g.Max = $q.Length }
        }
        foreach ($k in $groups.Keys) {
            $g = $groups[$k]
            $avg = if ($g.N) { $g.Sum / $g.N } else { 0 }
            if (($g.Names.Count -ge 40 -and $avg -ge 35) -or $g.Max -ge 120) {
                Add-Finding Medium 'DNS tunnelling' "Possible DNS tunnel / DNS C2 via $k" ("{0} unique names, avg length {1:N0}, max {2} in 2h" -f $g.Names.Count, $avg, $g.Max)
            }
        }
    }
}

function Invoke-Hunt {
    $steps = @(
        @{ N = 'UAC bypass artefacts'; F = { Find-UacHijack } }
        @{ N = 'Persistence'; F = { Find-Persistence } }
        @{ N = 'Service / path weaknesses'; F = { Find-ServiceWeakness } }
        @{ N = 'Accounts and Defender state'; F = { Find-AccountAnomaly } }
        @{ N = 'Network'; F = { Find-NetworkAnomaly } }
        @{ N = 'Event logs'; F = { Find-EventAnomaly } }
    )
    foreach ($s in $steps) {
        Write-Info "Hunting: $($s.N)" DarkGray
        try { & $s.F } catch { Add-Finding Info 'Scanner' "Step '$($s.N)' failed" $_.Exception.Message }
    }
    $order = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
    $sorted = @($script:Findings | Sort-Object { $order[$_.Severity] }, Category)
    foreach ($f in $sorted) {
        $color = switch ($f.Severity) { 'High' { 'Red' } 'Medium' { 'Yellow' } 'Low' { 'Gray' } default { 'DarkGray' } }
        Write-Info ('[{0,-6}] {1,-20} {2}' -f $f.Severity, $f.Category, $f.Title) $color
        if ($f.Detail) { Write-Info ('         {0}' -f $f.Detail) DarkGray }
    }
    $high = @($sorted | Where-Object Severity -eq 'High').Count
    $med = @($sorted | Where-Object Severity -eq 'Medium').Count
    Write-Info ''
    Write-Info ('== Scan complete: {0} high, {1} medium, {2} total findings ==' -f $high, $med, $sorted.Count) White

    if ($Remediate) {
        foreach ($f in ($sorted | Where-Object { $_.Fix })) {
            try {
                & $f.Fix $f | Out-Null
                Write-Info ("Remediated: {0}" -f $f.Title) Cyan
            }
            catch { Write-Info ("Remediation failed for '{0}': {1}" -f $f.Title, $_.Exception.Message) Red }
        }
    }

    $export = $sorted | Select-Object Severity, Category, Title, Detail, @{ N = 'Remediable'; E = { [bool]$_.Fix } }
    Save-Report -Results $export -Kind 'scan'
    Write-CitadelEvent -High $high -Medium $med -Findings ($sorted | Where-Object { $_.Severity -in 'High', 'Medium' })
    Remove-OldReports
    [pscustomobject]@{ High = $high; Medium = $med; Total = $sorted.Count }
}

function Write-CitadelEvent {
    param([int]$High, [int]$Medium, $Findings)
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists('Citadel')) {
            [System.Diagnostics.EventLog]::CreateEventSource('Citadel', 'Application')
        }
        $type = if ($High -gt 0) { 'Error' } elseif ($Medium -gt 0) { 'Warning' } else { 'Information' }
        $id = if ($High -gt 0) { 4100 } elseif ($Medium -gt 0) { 4101 } else { 4102 }
        $lines = @($Findings | Select-Object -First 25 | ForEach-Object { "[{0}] {1}: {2} {3}" -f $_.Severity, $_.Category, $_.Title, $_.Detail })
        $msg = "Citadel scan on $env:COMPUTERNAME: $High high, $Medium medium findings.`r`n" + ($lines -join "`r`n")
        if ($msg.Length -gt 30000) { $msg = $msg.Substring(0, 30000) }
        [System.Diagnostics.EventLog]::WriteEntry('Citadel', $msg, [System.Diagnostics.EventLogEntryType]$type, $id)
    }
    catch { }
}

function Remove-OldReports {
    Get-ChildItem -LiteralPath $script:Dirs.Reports -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force -ErrorAction SilentlyContinue
}

# ----------------------------------------------------------------------------------------------
# Sentinel (scheduled hunting)
# ----------------------------------------------------------------------------------------------
function Install-Sentinel {
    if (-not $PSCommandPath) { throw 'Run this script from a file to install the sentinel.' }
    $dest = Join-Path $script:Dirs.Bin 'Win11-Citadel.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $dest -Force
    Unblock-File -LiteralPath $dest -ErrorAction SilentlyContinue
    Set-AdminOnlyAcl -Path $script:Dirs.Bin
    $argLine = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -Mode Scan -Quiet' -f $dest
    if ($Remediate) { $argLine += ' -Remediate' }
    $action = New-ScheduledTaskAction -Execute "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $argLine
    $hourly = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(5)) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 3650)
    $boot = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName 'Citadel Sentinel' -TaskPath '\Citadel\' -Action $action -Trigger @($hourly, $boot) `
        -Principal $principal -Settings $settings -Description 'Hourly threat hunt (UAC hijacks, persistence, WMI, C2, DNS tunnelling). Findings go to Application log, source Citadel.' -Force | Out-Null
    if (-not [System.Diagnostics.EventLog]::SourceExists('Citadel')) { [System.Diagnostics.EventLog]::CreateEventSource('Citadel', 'Application') }
    Write-Info "Sentinel installed: \Citadel\Citadel Sentinel (hourly + at startup). Script: $dest" Cyan
}

function Uninstall-Sentinel {
    Unregister-ScheduledTask -TaskName 'Citadel Sentinel' -TaskPath '\Citadel\' -Confirm:$false -ErrorAction SilentlyContinue
    Write-Info 'Sentinel task removed.' Cyan
}

# ----------------------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------------------
function Start-Citadel {
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        throw 'Run this script from 64-bit PowerShell (not the x86 shell) so registry and System32 paths are not redirected.'
    }
    Initialize-Workspace
    Write-Info ("Citadel {0} | Mode={1} Level={2} | {3}" -f $script:Version, $Mode, $Level, (Get-CimInstance Win32_OperatingSystem).Caption) White

    $exit = 0
    switch ($Mode) {
        'Rollback' { Invoke-Rollback }
        'Scan' {
            $r = @(Invoke-Hunt) | Select-Object -Last 1
            if ($r.High -gt 0) { $exit = 2 }
        }
        default {
            Initialize-Controls
            $apply = ($Mode -eq 'Apply')
            if ($apply -and -not $script:WhatIf) {
                try { Checkpoint-Computer -Description 'Citadel pre-hardening' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop }
                catch { Write-Info "Restore point skipped: $($_.Exception.Message)" DarkYellow }
            }
            try { $results = @(Invoke-ControlEngine -ApplyChanges $apply) }
            finally {
                if ($apply) {
                    $bf = Save-BackupFile
                    if ($bf) { Write-Info "Rollback data: $bf  (undo with -Mode Rollback)" DarkGray }
                }
            }
            $score = Write-ControlSummary -Results $results -Label $(if ($apply) { 'Post-apply' } else { 'Audit' })
            Save-Report -Results $results -Kind $(if ($apply) { 'apply' } else { 'audit' })
            if ($script:RebootNeeded) { Write-Info 'Reboot required for some controls to take effect.' Yellow }
            if ($apply -and (@($results | Where-Object { $_.Status -in 'FAILED', 'ERROR' }).Count -gt 0)) { $exit = 1 }
            if (-not $apply -and $score -lt 100) { $exit = 3 }
        }
    }

    if ($InstallSentinel -and $Mode -ne 'Rollback') { Install-Sentinel }
    if ($RemoveSentinel) { Uninstall-Sentinel }
    return $exit
}

if ($MyInvocation.InvocationName -ne '.') {
    $code = @(Start-Citadel) | Select-Object -Last 1
    exit ([int]$code)
}