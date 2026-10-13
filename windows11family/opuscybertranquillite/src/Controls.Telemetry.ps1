<#
    Controls.Telemetry.ps1 - Detection and evidence.

    Blocking an attack you cannot see is luck. These controls make sure the host records
    the command lines, logon failures and service installs that an intrusion produces,
    and that the logs are large enough to still hold them when you go looking.

    Audit policy is read back through "auditpol /backup", which emits a numeric setting
    column. The alternative ("auditpol /get") only prints localised text such as
    "Success and Failure", which cannot be parsed reliably on a non-English host.
#>

$script:AuditGuidSuffix = '-69AE-11D9-BED3-505054503030'

function Get-AuditSubcategoryDefinition {
    <#
        .SYNOPSIS
        Audit subcategories this toolkit enables, grouped by control.
        Setting values: 0 = none, 1 = success, 2 = failure, 3 = success and failure.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $defs = @(
        @{ ControlId = 'LOG-001'; Short = '0CCE922B'; Name = 'Process Creation'; Setting = 1 }
        @{ ControlId = 'LOG-001'; Short = '0CCE922C'; Name = 'Process Termination'; Setting = 1 }

        @{ ControlId = 'LOG-002'; Short = '0CCE9215'; Name = 'Logon'; Setting = 3 }
        @{ ControlId = 'LOG-002'; Short = '0CCE9216'; Name = 'Logoff'; Setting = 1 }
        @{ ControlId = 'LOG-002'; Short = '0CCE9217'; Name = 'Account Lockout'; Setting = 3 }
        @{ ControlId = 'LOG-002'; Short = '0CCE921B'; Name = 'Special Logon'; Setting = 3 }
        @{ ControlId = 'LOG-002'; Short = '0CCE921C'; Name = 'Other Logon/Logoff Events'; Setting = 3 }
        @{ ControlId = 'LOG-002'; Short = '0CCE923F'; Name = 'Credential Validation'; Setting = 3 }
        @{ ControlId = 'LOG-002'; Short = '0CCE9242'; Name = 'Kerberos Authentication Service'; Setting = 3 }

        @{ ControlId = 'LOG-003'; Short = '0CCE9211'; Name = 'Security System Extension'; Setting = 3 }
        @{ ControlId = 'LOG-003'; Short = '0CCE922F'; Name = 'Audit Policy Change'; Setting = 3 }
        @{ ControlId = 'LOG-003'; Short = '0CCE9230'; Name = 'Authentication Policy Change'; Setting = 3 }
        @{ ControlId = 'LOG-003'; Short = '0CCE9232'; Name = 'MPSSVC Rule-Level Policy Change'; Setting = 3 }
        @{ ControlId = 'LOG-003'; Short = '0CCE9235'; Name = 'User Account Management'; Setting = 3 }
        @{ ControlId = 'LOG-003'; Short = '0CCE9237'; Name = 'Security Group Management'; Setting = 3 }
        @{ ControlId = 'LOG-003'; Short = '0CCE9212'; Name = 'System Integrity'; Setting = 3 }

        @{ ControlId = 'LOG-004'; Short = '0CCE9224'; Name = 'File Share'; Setting = 3 }
        @{ ControlId = 'LOG-004'; Short = '0CCE9244'; Name = 'Detailed File Share'; Setting = 2 }
        @{ ControlId = 'LOG-004'; Short = '0CCE9220'; Name = 'SAM'; Setting = 2 }
        @{ ControlId = 'LOG-004'; Short = '0CCE9228'; Name = 'Sensitive Privilege Use'; Setting = 2 }
        @{ ControlId = 'LOG-004'; Short = '0CCE9245'; Name = 'Removable Storage'; Setting = 3 }
    )

    foreach ($d in $defs) {
        [pscustomobject]@{
            ControlId = $d.ControlId
            Guid      = "{$($d.Short)$($script:AuditGuidSuffix)}"
            Name      = $d.Name
            Setting   = [int]$d.Setting
        }
    }
}

function ConvertFrom-AuditPolBackup {
    <#
        .SYNOPSIS
        Pure parser for "auditpol /backup" CSV output.

        .DESCRIPTION
        Returns a hashtable of lowercase subcategory GUID -> numeric setting value.
        Columns are addressed by position because the header row is localised:
        0 Machine Name, 1 Policy Target, 2 Subcategory, 3 Subcategory GUID,
        4 Inclusion Setting, 5 Exclusion Setting, 6 Setting Value.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Line
    )

    $map = @{}

    foreach ($l in $Line) {
        if ([string]::IsNullOrWhiteSpace($l)) { continue }

        $fields = $l -split ',(?=(?:[^"]*"[^"]*")*[^"]*$)' | ForEach-Object { $_.Trim().Trim('"') }
        if ($fields.Count -lt 7) { continue }

        $guid = $fields[3]
        if ($guid -notmatch '^\{[0-9a-fA-F-]{36}\}$') { continue }

        $value = 0
        if ([int]::TryParse($fields[6], [ref]$value)) {
            $map[$guid.ToLowerInvariant()] = $value
        }
    }

    $map
}

function Get-AuditPolicySnapshot {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("auditpol-{0}.csv" -f [guid]::NewGuid())
    try {
        $null = & auditpol.exe /backup /file:$tmp 2>&1
        $raw = if (Test-Path -LiteralPath $tmp) { Get-Content -LiteralPath $tmp -ErrorAction Stop } else { @() }
        ConvertFrom-AuditPolBackup -Line $raw
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function New-AuditPolicyControl {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Rationale,
        [Parameter(Mandatory)][string]$Impact,
        [string[]]$Counters = @(),
        [string]$Tier = 'Standard'
    )

    $test = {
        param($Control)

        $wanted = @(Get-AuditSubcategoryDefinition | Where-Object ControlId -EQ $Control.Id)
        $actual = Get-AuditPolicySnapshot

        # A subcategory is compliant when every bit we asked for is set; extra auditing is fine.
        $missing = @($wanted | Where-Object {
                $have = [int]$actual[$_.Guid.ToLowerInvariant()]
                ($have -band $_.Setting) -ne $_.Setting
            })

        @{
            Compliant = ($missing.Count -eq 0)
            Detail    = if ($missing.Count -eq 0) {
                "$($wanted.Count)/$($wanted.Count) subcategories audited."
            } else {
                "Not audited: $(($missing | ForEach-Object Name) -join '; ')"
            }
        }
    }

    $apply = {
        param($Control)

        $wanted = @(Get-AuditSubcategoryDefinition | Where-Object ControlId -EQ $Control.Id)
        $before = Get-AuditPolicySnapshot

        foreach ($sub in $wanted) {
            if (-not (Test-ShouldApply -Target $sub.Name -Action 'Enable audit subcategory')) { continue }

            Add-HardeningStateEntry -Kind 'Note' -ControlId $Control.Id -Before @{
                Description = 'Audit subcategory setting before hardening. Restore with: auditpol /set /subcategory:"<Guid>" /success:<enable|disable> /failure:<enable|disable>'
                Subcategory = $sub.Name
                Guid        = $sub.Guid
                Setting     = [int]$before[$sub.Guid.ToLowerInvariant()]
            }

            $success = if ($sub.Setting -band 1) { 'enable' } else { 'disable' }
            $failure = if ($sub.Setting -band 2) { 'enable' } else { 'disable' }
            $null = & auditpol.exe /set /subcategory:"$($sub.Guid)" /success:$success /failure:$failure 2>&1
            Write-HardeningLog "audit: $($sub.Name) (success=$success, failure=$failure)" 'Detail'
        }
    }

    New-HardeningControl -Id $Id -Name $Name -Category 'Telemetry' -Tier $Tier -Counters $Counters `
        -Rationale $Rationale -Impact $Impact -Test $test -Apply $apply
}

function Get-TelemetryControl {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    New-RegistryControl -Id 'LOG-000' -Name 'Advanced audit policy overrides legacy categories' -Category 'Telemetry' -Tier 'Baseline' `
        -Counters @('audit policy tampering') `
        -Rationale 'Without SCENoApplyLegacyAuditPolicy, a legacy audit policy refresh silently wipes every subcategory setting the other LOG controls apply. This has to be set first or the rest of the telemetry quietly stops working.' `
        -Impact 'None.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; Value = 1; Label = 'Subcategory override' }
    )

    New-AuditPolicyControl -Id 'LOG-001' -Tier 'Baseline' -Name 'Process creation auditing' `
        -Counters @('all post-exploitation tooling', 'living-off-the-land binaries') `
        -Rationale 'Event 4688 with the command line is the single highest-value log on a Windows host. It is what lets you reconstruct exactly what an operator ran, including base64-encoded PowerShell, after the fact.' `
        -Impact 'High event volume. Pair with the larger Security log in LOG-008.'

    New-RegistryControl -Id 'LOG-005' -Name 'Command line recorded in process creation events' -Category 'Telemetry' -Tier 'Baseline' `
        -Counters @('encoded PowerShell stagers', 'LOLBin abuse', 'certutil/bitsadmin downloads') `
        -Rationale 'Without this value, 4688 records only the image name - "powershell.exe" tells you nothing. With it you get the full command line, which is usually the entire payload.' `
        -Impact 'Command lines can contain secrets passed as arguments, and they will be written to the Security log.' `
        -Setting @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Value = 1; Label = 'Command line in 4688' }
    )

    New-AuditPolicyControl -Id 'LOG-002' -Tier 'Baseline' -Name 'Logon and credential validation auditing' `
        -Counters @('hydra', 'CrackMapExec password spray', 'kerbrute', 'pass-the-hash') `
        -Rationale 'Failed logons (4625) in bursts are the clearest signal of an online guessing attack, and successful type-3 network logons (4624) from an unexpected source are how you spot lateral movement landing.' `
        -Impact 'Moderate event volume.'

    New-AuditPolicyControl -Id 'LOG-003' -Tier 'Baseline' -Name 'Service install and policy change auditing' `
        -Counters @('PsExec', 'impacket psexec/smbexec', 'Metasploit service persistence', 'Defender tampering') `
        -Rationale 'Every PsExec-style tool installs a service to get SYSTEM, producing 4697/7045. Policy-change auditing catches an attacker undoing the rest of this hardening, and MPSSVC auditing records firewall rule tampering.' `
        -Impact 'Low event volume, very high signal.'

    New-AuditPolicyControl -Id 'LOG-004' -Tier 'Standard' -Name 'Share access and privilege use auditing' `
        -Counters @('SMB enumeration', 'secretsdump', 'removable media exfiltration') `
        -Rationale 'Detailed file share auditing records which remote host touched which path, and SAM auditing catches credential-store access attempts.' `
        -Impact 'Detailed File Share auditing is restricted to failures here because success auditing is extremely noisy.'

    New-RegistryControl -Id 'LOG-006' -Name 'PowerShell script block and module logging' -Category 'Telemetry' -Tier 'Baseline' `
        -Counters @('Empire', 'PowerSploit', 'Invoke-Mimikatz', 'Invoke-Obfuscation', 'PowerView') `
        -Rationale 'Script block logging records the deobfuscated script text right before execution, so an encoded or layered payload is written to the event log in cleartext. It is the reason attackers try to downgrade to PowerShell v2 (see SVC-009).' `
        -Impact 'Scripts that handle secrets in-line will have those secrets written to the PowerShell operational log.' `
        -Setting @(
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Value = 1; Label = 'Script block logging' }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Name = 'EnableModuleLogging'; Value = 1; Label = 'Module logging' }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; Name = '*'; Value = '*'; Type = 'String'; Label = 'Module logging scope' }
    )

    New-HardeningControl -Id 'LOG-007' -Name 'PowerShell transcription to a protected directory' -Category 'Telemetry' -Tier 'Standard' `
        -Counters @('interactive post-exploitation shells', 'evil-winrm sessions') `
        -Rationale 'Transcripts capture both input and output, which script block logging does not. When an operator runs discovery commands, the transcript is the only record of what they actually saw.' `
        -Impact 'Writes transcript files continuously. Keep an eye on disk usage and restrict the directory ACL.' `
        -Test {
        $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        $enabled = Get-RegistryValueOrNull -Path $base -Name 'EnableTranscripting'
        $dir = Get-RegistryValueOrNull -Path $base -Name 'OutputDirectory'
        @{
            Compliant = ($enabled -eq 1 -and -not [string]::IsNullOrWhiteSpace($dir))
            Detail    = "EnableTranscripting=$enabled, OutputDirectory=$dir."
        }
    } `
        -Apply {
        $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        $dir = Join-Path $env:ProgramData 'KaliCountermeasures\Transcripts'

        if (-not (Test-Path -LiteralPath $dir)) {
            $null = New-Item -ItemType Directory -Path $dir -Force
        }

        Set-GuardedRegistryValue -Path $base -Name 'EnableTranscripting' -Value 1 -ControlId 'LOG-007'
        Set-GuardedRegistryValue -Path $base -Name 'EnableInvocationHeader' -Value 1 -ControlId 'LOG-007'
        Set-GuardedRegistryValue -Path $base -Name 'OutputDirectory' -Value $dir -Type String -ControlId 'LOG-007'
    }

    New-HardeningControl -Id 'LOG-008' -Name 'Security and PowerShell logs large enough to survive an incident' -Category 'Telemetry' -Tier 'Baseline' `
        -Counters @('log flooding', 'anti-forensics') `
        -Rationale 'The default 20 MB Security log rolls over in hours once process auditing is on, and flooding it is a cheap way to destroy evidence. 512 MB keeps weeks of history on a workstation.' `
        -Impact 'Up to roughly 768 MB of disk used by event logs.' `
        -Test {
        $channels = @(
            @{ Name = 'Security'; MinBytes = 536870912 }
            @{ Name = 'Microsoft-Windows-PowerShell/Operational'; MinBytes = 268435456 }
        )

        $small = [System.Collections.Generic.List[string]]::new()
        foreach ($ch in $channels) {
            $size = Get-EventChannelMaxSize -Channel $ch.Name
            if ($null -eq $size -or $size -lt $ch.MinBytes) {
                $small.Add("$($ch.Name)=$([math]::Round(([double]$size) / 1MB))MB")
            }
        }

        @{
            Compliant = ($small.Count -eq 0)
            Detail    = if ($small.Count -eq 0) { 'Security and PowerShell operational logs are adequately sized.' } else { "Undersized: $($small -join ', ')." }
        }
    } `
        -Apply {
        $channels = @(
            @{ Name = 'Security'; Bytes = 536870912 }
            @{ Name = 'Microsoft-Windows-PowerShell/Operational'; Bytes = 268435456 }
        )

        foreach ($ch in $channels) {
            if (-not (Test-ShouldApply -Target $ch.Name -Action "Set maximum log size to $($ch.Bytes) bytes")) { continue }

            Add-HardeningStateEntry -Kind 'Note' -ControlId 'LOG-008' -Before @{
                Description = 'Event channel maximum size before hardening. Restore with: wevtutil sl "<Channel>" /ms:<Bytes>'
                Channel     = $ch.Name
                MaxSize     = Get-EventChannelMaxSize -Channel $ch.Name
            }

            $null = & wevtutil.exe sl $ch.Name /ms:$($ch.Bytes) 2>&1
            Write-HardeningLog "log: $($ch.Name) -> $([math]::Round($ch.Bytes / 1MB)) MB" 'Detail'
        }
    }
}

function Get-EventChannelMaxSize {
    <#
        .SYNOPSIS
        Reads an event channel's maximum size in bytes via wevtutil.
    #>
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory)][string]$Channel
    )

    $output = & wevtutil.exe gl $Channel 2>&1 | Out-String
    # Property names in wevtutil output are not localised, unlike auditpol's values.
    if ($output -match 'maxSize:\s*(\d+)') { return [long]$Matches[1] }
    return $null
}
