<#
    Controls.Defender.ps1 - Microsoft Defender configuration, with an emphasis on the
    Attack Surface Reduction rules that map directly onto post-exploitation tradecraft.
#>

function Get-AsrRuleDefinition {
    <#
        .SYNOPSIS
        The ASR rules this toolkit enforces, as data.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $rules = @(
        @{ Id = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; Tier = 'Baseline'; Name = 'Block credential stealing from LSASS'
            Counters = @('mimikatz', 'procdump lsass', 'nanodump', 'pypykatz') }
        @{ Id = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'; Tier = 'Baseline'; Name = 'Block process creation from PsExec and WMI commands'
            Counters = @('PsExec', 'impacket wmiexec', 'CrackMapExec', 'smbexec') }
        @{ Id = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'; Tier = 'Baseline'; Name = 'Block persistence through WMI event subscription'
            Counters = @('WMI event persistence', 'Empire/PowerSploit persistence') }
        @{ Id = '56a863a9-875e-4185-98a7-b882c64b5ce5'; Tier = 'Baseline'; Name = 'Block abuse of exploited vulnerable signed drivers'
            Counters = @('bring-your-own-vulnerable-driver', 'PPL bypass', 'mimidrv') }
        @{ Id = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'; Tier = 'Baseline'; Name = 'Block execution of potentially obfuscated scripts'
            Counters = @('Invoke-Obfuscation', 'encoded PowerShell stagers', 'Veil') }
        @{ Id = 'd3e037e1-3eb8-44c8-a917-57927947596d'; Tier = 'Standard'; Name = 'Block JavaScript/VBScript from launching downloaded executables'
            Counters = @('script-based droppers', 'HTA loaders') }
        @{ Id = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'; Tier = 'Standard'; Name = 'Block untrusted and unsigned processes running from USB'
            Counters = @('USB drop attacks', 'Rubber Ducky payload stagers') }
        @{ Id = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'; Tier = 'Standard'; Name = 'Block executable content from email and webmail'
            Counters = @('phishing payloads', 'SET-generated attachments') }
        @{ Id = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'; Tier = 'Standard'; Name = 'Block Office applications from creating child processes'
            Counters = @('macro_pack', 'msfvenom VBA payloads', 'Office macro droppers') }
        @{ Id = '3b576869-a4ec-4529-8536-b80a7769e899'; Tier = 'Standard'; Name = 'Block Office applications from creating executable content'
            Counters = @('macro droppers', 'Office payload staging') }
        @{ Id = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'; Tier = 'Standard'; Name = 'Block Win32 API calls from Office macros'
            Counters = @('macro_pack shellcode injection', 'VBA process injection') }
        @{ Id = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'; Tier = 'Standard'; Name = 'Block Office applications from injecting into other processes'
            Counters = @('VBA process injection', 'Office-to-explorer migration') }
        @{ Id = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'; Tier = 'Standard'; Name = 'Block Adobe Reader from creating child processes'
            Counters = @('malicious PDF droppers') }
        @{ Id = '26190899-1602-49e8-8b27-eb1d0a1ce869'; Tier = 'Standard'; Name = 'Block Office communication apps from creating child processes'
            Counters = @('Outlook-based payload execution') }
        @{ Id = 'c1db55ab-c21a-4637-bb3f-a12568109d35'; Tier = 'Standard'; Name = 'Use advanced protection against ransomware'
            Counters = @('ransomware payloads') }
        @{ Id = '01443614-cd74-433a-b99e-2ecdc07bfc25'; Tier = 'Aggressive'; Name = 'Block executables unless they meet prevalence, age or trusted-list criteria'
            Counters = @('freshly compiled msfvenom binaries', 'custom droppers') }
        @{ Id = 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb'; Tier = 'Aggressive'; Name = 'Block use of copied or impersonated system tools'
            Counters = @('renamed LOLBins', 'copied certutil/bitsadmin') }
    )

    foreach ($r in $rules) {
        [pscustomobject]@{
            Id       = $r.Id
            Name     = $r.Name
            Tier     = $r.Tier
            Counters = [string[]]$r.Counters
        }
    }
}

function Get-AsrRuleForTier {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Tier
    )

    $order = @('Baseline', 'Standard', 'Aggressive')
    $max = $order.IndexOf($Tier)
    if ($max -lt 0) { throw "Unknown tier '$Tier'." }

    Get-AsrRuleDefinition | Where-Object { $order.IndexOf($_.Tier) -le $max }
}

function Get-DefenderControl {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$Tier = 'Standard'
    )

    $asrTier = $Tier

    New-HardeningControl -Id 'DEF-001' -Name 'Defender real-time and cloud protection active' -Category 'Defender' -Tier 'Baseline' `
        -Counters @('msfvenom payloads', 'Metasploit stagers', 'public post-exploitation tooling') `
        -Rationale 'Almost everything shipped in Kali is signatured. Cloud-delivered protection with automatic sample submission is what catches the lightly modified variants that local signatures miss, usually within seconds of first execution.' `
        -Impact 'Metadata about suspicious files is sent to Microsoft.' `
        -Test {
        $mp = Get-MpPreference -ErrorAction Stop
        $status = Get-MpComputerStatus -ErrorAction Stop
        $issues = [System.Collections.Generic.List[string]]::new()

        if (-not $status.RealTimeProtectionEnabled) { $issues.Add('real-time protection off') }
        if (-not $status.AntivirusEnabled) { $issues.Add('antivirus off') }
        if ($mp.MAPSReporting -ne 2) { $issues.Add("MAPS=$($mp.MAPSReporting), want 2 (Advanced)") }
        if ($mp.SubmitSamplesConsent -notin @(1, 3)) { $issues.Add("sample submission=$($mp.SubmitSamplesConsent)") }
        if ($mp.PUAProtection -ne 1) { $issues.Add("PUA protection=$($mp.PUAProtection), want 1 (Block)") }
        if ($mp.DisableBehaviorMonitoring) { $issues.Add('behaviour monitoring off') }
        if ($mp.DisableScriptScanning) { $issues.Add('script scanning off') }

        @{
            Compliant = ($issues.Count -eq 0)
            Detail    = if ($issues.Count -eq 0) { 'Real-time, behaviour, script scanning, cloud (Advanced MAPS) and PUA blocking all active.' } else { "Gaps: $($issues -join '; ')." }
        }
    } `
        -Apply {
        Add-HardeningStateEntry -Kind 'Defender' -ControlId 'DEF-001' -Before (ConvertTo-DefenderSnapshot)
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableScriptScanning $false `
            -DisableIOAVProtection $false -MAPSReporting Advanced -SubmitSamplesConsent SendAllSamples -PUAProtection Enabled `
            -ErrorAction Stop
    }

    New-HardeningControl -Id 'DEF-002' -Name 'Network protection blocking malicious destinations' -Category 'Defender' -Tier 'Baseline' `
        -Counters @('reverse shell callbacks', 'C2 beacons', 'credential phishing pages') `
        -Rationale 'Network protection inspects outbound connections from any process against Microsoft reputation data, so it catches a beacon even when the payload itself was never detected on disk. It is the closest thing Windows has to built-in egress filtering.' `
        -Impact 'Occasional false positives on obscure or newly registered domains.' `
        -Test {
        $mp = Get-MpPreference -ErrorAction Stop
        @{
            Compliant = ($mp.EnableNetworkProtection -eq 1)
            Detail    = "EnableNetworkProtection=$($mp.EnableNetworkProtection) (1 = block, 2 = audit, 0 = off)."
        }
    } `
        -Apply {
        Add-HardeningStateEntry -Kind 'Defender' -ControlId 'DEF-002' -Before (ConvertTo-DefenderSnapshot)
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
    }

    $asrTest = {
        param($Control)

        $tier = $Control.Data.AsrTier
        $wanted = @(Get-AsrRuleForTier -Tier $tier)
        $mp = Get-MpPreference -ErrorAction Stop

        $current = @{}
        $ids = @($mp.AttackSurfaceReductionRules_Ids)
        $actions = @($mp.AttackSurfaceReductionRules_Actions)
        for ($i = 0; $i -lt $ids.Count; $i++) {
            if ($i -lt $actions.Count) { $current[[string]$ids[$i]] = [int]$actions[$i] }
        }

        $notBlocking = @($wanted | Where-Object { $current[$_.Id] -ne 1 })

        @{
            Compliant = ($notBlocking.Count -eq 0)
            Detail    = if ($notBlocking.Count -eq 0) {
                "All $($wanted.Count) ASR rules for the $tier tier are set to Block."
            } else {
                "$($wanted.Count - $notBlocking.Count)/$($wanted.Count) ASR rules blocking. Not enforced: $(($notBlocking | ForEach-Object Name) -join '; ')"
            }
        }
    }

    $asrApply = {
        param($Control)

        Add-HardeningStateEntry -Kind 'Defender' -ControlId $Control.Id -Before (ConvertTo-DefenderSnapshot)

        foreach ($rule in (Get-AsrRuleForTier -Tier $Control.Data.AsrTier)) {
            if (-not (Test-ShouldApply -Target $rule.Name -Action 'Enable ASR rule in Block mode')) { continue }
            Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
            Write-HardeningLog "ASR: $($rule.Name)" 'Detail'
        }
    }

    New-HardeningControl -Id 'DEF-003' -Name 'Attack Surface Reduction rules enforced' -Category 'Defender' -Tier 'Baseline' `
        -Counters @(Get-AsrRuleForTier -Tier $asrTier | ForEach-Object Counters | Sort-Object -Unique) `
        -Rationale 'ASR rules are behavioural blocks rather than signatures, so they hold up against repackaged tooling. The LSASS, PsExec/WMI and vulnerable-driver rules in particular break mimikatz, impacket and BYOVD regardless of how the binary was obfuscated.' `
        -Impact 'The Office and script rules can block legitimate macro-based business tooling. Review DEF-003 exclusions if something breaks.' `
        -Data @{ AsrTier = $asrTier } -Test $asrTest -Apply $asrApply

    New-HardeningControl -Id 'DEF-004' -Name 'Tamper Protection enabled' -Category 'Defender' -Tier 'Baseline' -AuditOnly `
        -Counters @('Set-MpPreference -DisableRealtimeMonitoring', 'Defender disable scripts', 'Metasploit post/windows/manage/killav') `
        -Rationale 'Tamper Protection is what stops an attacker who already has admin from simply turning Defender off, which is the first step in most post-exploitation playbooks. It deliberately cannot be enabled by a script - that is the whole point - so this control reports status and leaves the switch to you.' `
        -Impact 'None. Enable it in Windows Security > Virus and threat protection > Manage settings.' `
        -Test {
        $status = Get-MpComputerStatus -ErrorAction Stop
        @{
            Compliant = [bool]$status.IsTamperProtected
            Detail    = if ($status.IsTamperProtected) { 'Tamper Protection is on.' } else { 'Tamper Protection is OFF. Enable it manually: Windows Security > Virus and threat protection > Manage settings > Tamper Protection.' }
        }
    } `
        -Apply { }

    New-HardeningControl -Id 'DEF-005' -Name 'No unexpected Defender exclusions' -Category 'Defender' -Tier 'Standard' -AuditOnly `
        -Counters @('attacker-added exclusions', 'Defender blind spots') `
        -Rationale 'Adding an exclusion folder and then working exclusively inside it is a standard way to neutralise Defender without tripping Tamper Protection. Exclusions are legitimate often enough that this control reports rather than deletes - review each one and remove anything you did not add.' `
        -Impact 'None. This control never removes an exclusion.' `
        -Test {
        $mp = Get-MpPreference -ErrorAction Stop
        $all = @($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension) | Where-Object { $_ }
        @{
            Compliant = (@($all).Count -eq 0)
            Detail    = if (@($all).Count -eq 0) { 'No Defender exclusions configured.' } else { "$(@($all).Count) exclusion(s) configured - review each: $($all -join '; ')" }
        }
    } `
        -Apply { }

    New-HardeningControl -Id 'DEF-006' -Name 'Controlled Folder Access protecting user data' -Category 'Defender' -Tier 'Aggressive' `
        -Counters @('ransomware payloads', 'destructive post-exploitation') `
        -Rationale 'Blocks untrusted processes from writing to Documents, Pictures and other user folders, which contains the damage from a payload that does get through.' `
        -Impact 'High false-positive rate. Expect to allow-list legitimate applications (editors, backup tools, games) by hand.' `
        -Test {
        $mp = Get-MpPreference -ErrorAction Stop
        @{
            Compliant = ($mp.EnableControlledFolderAccess -eq 1)
            Detail    = "EnableControlledFolderAccess=$($mp.EnableControlledFolderAccess) (1 = enabled, 2 = audit, 0 = off)."
        }
    } `
        -Apply {
        Add-HardeningStateEntry -Kind 'Defender' -ControlId 'DEF-006' -Before (ConvertTo-DefenderSnapshot)
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop
    }

    New-HardeningControl -Id 'DEF-007' -Name 'Defender signatures are current' -Category 'Defender' -Tier 'Baseline' -AuditOnly `
        -Counters @('known-signature payloads') `
        -Rationale 'Stale signatures are a silent failure: Defender reports as healthy while missing everything published since it last updated.' `
        -Impact 'None.' `
        -Test {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $age = [int]$status.AntivirusSignatureAge
        @{
            Compliant = ($age -le 3)
            Detail    = "Signature age: $age day(s), version $($status.AntivirusSignatureVersion)."
        }
    } `
        -Apply { }
}

function ConvertTo-DefenderSnapshot {
    <#
        .SYNOPSIS
        Captures the Defender preferences this toolkit modifies, for the rollback journal.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        $mp = Get-MpPreference -ErrorAction Stop
    } catch {
        return @{ Description = 'Get-MpPreference failed; Defender state not captured.'; Error = $_.Exception.Message }
    }

    @{
        Description                        = 'Defender preferences before hardening.'
        MAPSReporting                      = [string]$mp.MAPSReporting
        SubmitSamplesConsent               = [string]$mp.SubmitSamplesConsent
        PUAProtection                      = [string]$mp.PUAProtection
        EnableNetworkProtection            = [string]$mp.EnableNetworkProtection
        EnableControlledFolderAccess       = [string]$mp.EnableControlledFolderAccess
        DisableRealtimeMonitoring          = [string]$mp.DisableRealtimeMonitoring
        DisableBehaviorMonitoring          = [string]$mp.DisableBehaviorMonitoring
        DisableScriptScanning              = [string]$mp.DisableScriptScanning
        AttackSurfaceReductionRules_Ids    = @($mp.AttackSurfaceReductionRules_Ids | ForEach-Object { [string]$_ })
        AttackSurfaceReductionRules_Action = @($mp.AttackSurfaceReductionRules_Actions | ForEach-Object { [string]$_ })
    }
}
