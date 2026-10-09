#Requires -Modules Pester

<#
    Validates the control catalogue itself. Declaring a control never touches Windows,
    so these run on any platform and catch structural mistakes before the script is ever
    pointed at a real machine.
#>
Describe 'Control' {
    BeforeAll {
        $script:RepoRoot = Split-Path -Parent $PSScriptRoot
        $script:SrcRoot = Join-Path $script:RepoRoot 'src'

        foreach ($file in @(
                'Common.ps1'
                'Controls.Firewall.ps1'
                'Controls.Protocols.ps1'
                'Controls.Credentials.ps1'
                'Controls.RemoteAccess.ps1'
                'Controls.Services.ps1'
                'Controls.Defender.ps1'
                'Controls.Telemetry.ps1'
                'ThreatSweep.ps1'
                'Rollback.ps1'
                'Reporting.ps1'
            )) {
            . (Join-Path $script:SrcRoot $file)
        }

        $script:Catalog = @(Get-FirewallControl) +
        @(Get-ProtocolControl) +
        @(Get-CredentialControl) +
        @(Get-RemoteAccessControl) +
        @(Get-ServiceControl) +
        @(Get-DefenderControl -Tier 'Aggressive') +
        @(Get-TelemetryControl)
    }
}

Describe 'Control catalogue' {

    It 'declares a meaningful number of controls' {
        $script:Catalog.Count | Should -BeGreaterThan 40
    }

    It 'uses a unique id for every control' {
        $duplicates = @($script:Catalog | Group-Object Id | Where-Object Count -GT 1)
        $duplicates | Should -BeNullOrEmpty -Because "duplicate ids break -Include/-Exclude and rollback attribution: $($duplicates.Name -join ', ')"
    }

    It 'uses a recognised category for every control' {
        $valid = @('Firewall', 'Protocols', 'Credentials', 'RemoteAccess', 'Services', 'Defender', 'Telemetry')
        foreach ($c in $script:Catalog) {
            $c.Category | Should -BeIn $valid -Because "$($c.Id) must be filterable by -Category"
        }
    }

    It 'uses a recognised tier for every control' {
        foreach ($c in $script:Catalog) {
            $c.Tier | Should -BeIn @('Baseline', 'Standard', 'Aggressive')
        }
    }

    It 'explains what every control counters' {
        foreach ($c in $script:Catalog) {
            @($c.Counters).Count | Should -BeGreaterThan 0 -Because "$($c.Id) should name the tooling it defeats"
        }
    }

    It 'explains the rationale and the operational cost of every control' {
        foreach ($c in $script:Catalog) {
            $c.Rationale | Should -Not -BeNullOrEmpty -Because "$($c.Id) needs a rationale"
            $c.Rationale.Length | Should -BeGreaterThan 60 -Because "$($c.Id) needs a rationale a reader can act on"
            $c.Impact | Should -Not -BeNullOrEmpty -Because "$($c.Id) needs an impact statement"
        }
    }

    It 'gives every control a runnable Test and Apply block' {
        foreach ($c in $script:Catalog) {
            $c.Test | Should -BeOfType [scriptblock] -Because "$($c.Id) must be auditable"
            $c.Apply | Should -BeOfType [scriptblock] -Because "$($c.Id) must be appliable"
        }
    }

    It 'keeps every Aggressive control honest about its impact' {
        foreach ($c in ($script:Catalog | Where-Object Tier -EQ 'Aggressive')) {
            $c.Impact | Should -Not -Be 'No user-visible impact expected.' -Because "$($c.Id) is Aggressive, so it must describe a real cost"
        }
    }
}

Describe 'BitLocker exclusion' {

    It 'refuses to register a control tagged for volume encryption' {
        foreach ($tag in @('bitlocker', 'BitLocker', 'disk-encryption', 'volume-encryption')) {
            {
                New-HardeningControl -Id 'TST-001' -Name 'test' -Category 'Credentials' `
                    -Rationale 'test' -Tags $tag -Test { $true } -Apply { }
            } | Should -Throw -ExpectedMessage '*excluded subsystem*'
        }
    }

    It 'has no control in the catalogue tagged for volume encryption' {
        foreach ($c in $script:Catalog) {
            foreach ($tag in @($c.Tags)) {
                $tag.ToLowerInvariant() | Should -Not -BeIn @('bitlocker', 'disk-encryption', 'volume-encryption')
            }
        }
    }

    It 'never calls a BitLocker cmdlet or manage-bde anywhere in the source' {
        $files = @(Get-ChildItem -Path $script:RepoRoot -Recurse -Filter '*.ps1' |
                Where-Object { $_.FullName -notlike "*$([IO.Path]::DirectorySeparatorChar)tests$([IO.Path]::DirectorySeparatorChar)*" })

        $files.Count | Should -BeGreaterThan 0

        # Matches Enable-BitLocker, Get-BitLockerVolume, manage-bde, Add-BitLockerKeyProtector, etc.
        $pattern = '(?i)(\b\w+-BitLocker\w*\b|\bmanage-bde\b|\bGet-BitLockerVolume\b)'

        foreach ($file in $files) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            $content | Should -Not -Match $pattern -Because "$($file.Name) must not touch volume encryption"
        }
    }
}

Describe 'Select-HardeningControl' {

    BeforeAll {
        $script:Sample = @(
            New-HardeningControl -Id 'AAA-001' -Name 'base' -Category 'Firewall' -Tier 'Baseline' -Rationale 'r' -Test { $true } -Apply { }
            New-HardeningControl -Id 'AAA-002' -Name 'std' -Category 'Firewall' -Tier 'Standard' -Rationale 'r' -Test { $true } -Apply { }
            New-HardeningControl -Id 'BBB-001' -Name 'agg' -Category 'Defender' -Tier 'Aggressive' -Rationale 'r' -Test { $true } -Apply { }
        )
    }

    It 'includes only controls at or below the requested tier' {
        @(Select-HardeningControl -Control $script:Sample -Tier 'Baseline').Id | Should -Be @('AAA-001')
        @(Select-HardeningControl -Control $script:Sample -Tier 'Standard').Id | Should -Be @('AAA-001', 'AAA-002')
        @(Select-HardeningControl -Control $script:Sample -Tier 'Aggressive').Id | Should -Be @('AAA-001', 'AAA-002', 'BBB-001')
    }

    It 'filters by category' {
        @(Select-HardeningControl -Control $script:Sample -Tier 'Aggressive' -Category 'Defender').Id | Should -Be @('BBB-001')
    }

    It 'lets -Include cherry-pick a control above the tier ceiling' {
        $selected = @(Select-HardeningControl -Control $script:Sample -Tier 'Baseline' -Include 'BBB-001')
        $selected.Id | Should -Be @('BBB-001')
    }

    It 'gives -Exclude precedence over -Include' {
        $selected = @(Select-HardeningControl -Control $script:Sample -Tier 'Aggressive' -Include 'BBB-001' -Exclude 'BBB-001')
        $selected | Should -BeNullOrEmpty
    }

    It 'rejects an unknown tier' {
        { Select-HardeningControl -Control $script:Sample -Tier 'Paranoid' } | Should -Throw
    }
}

Describe 'Firewall rule specification' {

    BeforeAll {
        $script:Rules = @(Get-CountermeasureFirewallRule)
    }

    It 'declares rules' {
        $script:Rules.Count | Should -BeGreaterThan 20
    }

    It 'uses a unique display name per rule' {
        $duplicates = @($script:Rules | Group-Object DisplayName | Where-Object Count -GT 1)
        $duplicates | Should -BeNullOrEmpty -Because "New-NetFirewallRule keys on DisplayName: $($duplicates.Name -join ', ')"
    }

    It 'only ever blocks, never allows' {
        foreach ($r in $script:Rules) {
            $r.Action | Should -Be 'Block' -Because 'this toolkit must never widen the attack surface'
        }
    }

    It 'prefixes every rule so it can be found and removed as a group' {
        foreach ($r in $script:Rules) {
            $r.DisplayName | Should -BeLike 'KCM - *'
        }
    }

    It 'gives every rule either ports or an ICMP type' {
        foreach ($r in $script:Rules) {
            $hasPorts = $r.LocalPort -or $r.RemotePort
            $hasIcmp = [bool]$r.IcmpType
            ($hasPorts -or $hasIcmp) | Should -BeTrue -Because "$($r.DisplayName) would otherwise block all traffic for its protocol"
        }
    }

    It 'never puts a port on an ICMP rule' {
        foreach ($r in ($script:Rules | Where-Object { $_.Protocol -like 'ICMP*' })) {
            $r.LocalPort | Should -BeNullOrEmpty
            $r.RemotePort | Should -BeNullOrEmpty
        }
    }

    It 'uses valid port numbers and ranges' {
        foreach ($r in $script:Rules) {
            foreach ($port in (@($r.LocalPort) + @($r.RemotePort) | Where-Object { $_ })) {
                $port | Should -Match '^\d{1,5}(-\d{1,5})?$' -Because "$($r.DisplayName) declares port '$port'"

                foreach ($part in ($port -split '-')) {
                    [int]$part | Should -BeGreaterThan 0
                    [int]$part | Should -BeLessOrEqual 65535
                }
            }
        }
    }

    It 'uses a valid firewall profile set' {
        foreach ($r in $script:Rules) {
            foreach ($p in ($r.Profile -split ',')) {
                $p.Trim() | Should -BeIn @('Any', 'Domain', 'Private', 'Public')
            }
        }
    }

    It 'names the tooling each rule counters' {
        foreach ($r in $script:Rules) {
            @($r.Counters).Count | Should -BeGreaterThan 0 -Because "$($r.DisplayName) should say what it defeats"
        }
    }

    It 'has a matching control for every rule ControlId' {
        $controlIds = @($script:Catalog | ForEach-Object Id)
        foreach ($id in (@($script:Rules | ForEach-Object ControlId) | Sort-Object -Unique)) {
            $id | Should -BeIn $controlIds -Because "firewall rules tagged $id would otherwise never be applied"
        }
    }

    It 'blocks outbound LLMNR, mDNS and NetBIOS name queries, which is what defeats Responder' {
        $outbound = @($script:Rules | Where-Object { $_.Direction -eq 'Outbound' })
        $ports = @($outbound | ForEach-Object { $_.RemotePort } | Where-Object { $_ })

        $ports | Should -Contain '5355'
        $ports | Should -Contain '137'
    }
}

Describe 'Attack Surface Reduction rule set' {

    BeforeAll { $script:Asr = @(Get-AsrRuleDefinition) }

    It 'uses well-formed, unique rule GUIDs' {
        foreach ($r in $script:Asr) {
            $r.Id | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        }
        @($script:Asr | Group-Object Id | Where-Object Count -GT 1) | Should -BeNullOrEmpty
    }

    It 'includes the rules that matter most against post-exploitation tooling' {
        $ids = @($script:Asr | ForEach-Object Id)
        $ids | Should -Contain '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'  # LSASS credential theft
        $ids | Should -Contain 'd1e49aac-8f56-4280-b9ba-993a6d77406c'  # PsExec and WMI process creation
        $ids | Should -Contain '56a863a9-875e-4185-98a7-b882c64b5ce5'  # vulnerable signed drivers
    }

    It 'returns a growing set as the tier rises' {
        $baseline = @(Get-AsrRuleForTier -Tier 'Baseline').Count
        $standard = @(Get-AsrRuleForTier -Tier 'Standard').Count
        $aggressive = @(Get-AsrRuleForTier -Tier 'Aggressive').Count

        $baseline | Should -BeGreaterThan 0
        $standard | Should -BeGreaterThan $baseline
        $aggressive | Should -BeGreaterThan $standard
    }

    It 'puts the LSASS rule in the Baseline tier' {
        $lsass = $script:Asr | Where-Object Id -EQ '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
        $lsass.Tier | Should -Be 'Baseline' -Because 'blocking LSASS dumping should never require opting into a higher tier'
    }
}

Describe 'Audit subcategory definitions' {

    BeforeAll { $script:Subs = @(Get-AuditSubcategoryDefinition) }

    It 'uses well-formed, unique subcategory GUIDs' {
        foreach ($s in $script:Subs) {
            $s.Guid | Should -Match '^\{[0-9A-Fa-f]{8}-69AE-11D9-BED3-505054503030\}$'
        }
        @($script:Subs | Group-Object Guid | Where-Object Count -GT 1) | Should -BeNullOrEmpty
    }

    It 'uses only valid success/failure bit combinations' {
        foreach ($s in $script:Subs) {
            $s.Setting | Should -BeIn @(1, 2, 3)
        }
    }

    It 'audits process creation, which is what records an attacker command line' {
        $processCreation = $script:Subs | Where-Object Name -EQ 'Process Creation'
        $processCreation | Should -Not -BeNullOrEmpty
        ($processCreation.Setting -band 1) | Should -Be 1
    }

    It 'audits logon failures, which is what records password spraying' {
        $logon = $script:Subs | Where-Object Name -EQ 'Logon'
        ($logon.Setting -band 2) | Should -Be 2
    }

    It 'maps every subcategory to a control in the catalogue' {
        $controlIds = @($script:Catalog | ForEach-Object Id)
        foreach ($id in (@($script:Subs | ForEach-Object ControlId) | Sort-Object -Unique)) {
            $id | Should -BeIn $controlIds
        }
    }
}
