#Requires -Modules Pester

<#
    Exercises the execution engine end to end against synthetic controls: the audit and
    apply loop, error isolation, -WhatIf, the audit-only path, and the rollback journal
    round-trip. These run on any platform because no real Windows cmdlet is involved.
#>
Describe 'Invoke-HardeningControl' {
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
    }
}
Describe 'Invoke-HardeningControl against a simulated registry' {

    BeforeEach {
        # Only the registry primitives are mocked, scoped to the HKLM: drive. The real
        # Set-GuardedRegistryValue runs on top of them, so its ShouldProcess gate and its
        # rollback-journal capture are genuinely under test rather than mocked away.
        $script:FakeRegistry = @{}
        $script:FakeKeys = @{}

        Mock Get-RegistryValueOrNull {
            $key = "$Path|$Name"
            if ($script:FakeRegistry.ContainsKey($key)) { $script:FakeRegistry[$key] } else { $null }
        }

        Mock Test-RegistryKeyExists { $script:FakeKeys.ContainsKey($Path) }

        Mock Set-RegistryValue {
            $script:FakeKeys[$Path] = $true
            $script:FakeRegistry["$Path|$Name"] = $Value
        }

        $script:Controls = @(
            New-RegistryControl -Id 'TST-001' -Name 'first setting' -Category 'Credentials' -Tier 'Baseline' `
                -Rationale 'A rationale long enough to satisfy the catalogue rules applied elsewhere in this suite.' `
                -Counters @('test') -Setting @(@{ Path = 'HKLM:\Test'; Name = 'Alpha'; Value = 1 })

            New-RegistryControl -Id 'TST-002' -Name 'two values at once' -Category 'Credentials' -Tier 'Baseline' `
                -Rationale 'A rationale long enough to satisfy the catalogue rules applied elsewhere in this suite.' `
                -Counters @('test') -Setting @(
                @{ Path = 'HKLM:\Test'; Name = 'Beta'; Value = 0 }
                @{ Path = 'HKLM:\Test'; Name = 'Gamma'; Value = 'yes'; Type = 'String' }
            )
        )
    }

    It 'reports drift when nothing is configured' {
        $results = @(Invoke-HardeningControl -Control $script:Controls)

        $results.Count | Should -Be 2
        foreach ($r in $results) { $r.Status | Should -Be 'Drift' }
    }

    It 'changes nothing during an audit' {
        $null = Invoke-HardeningControl -Control $script:Controls
        Should -Invoke Set-RegistryValue -Times 0
        $script:FakeRegistry.Keys.Count | Should -Be 0
    }

    It 'remediates drifted controls and re-verifies them' {
        $results = @(Invoke-HardeningControl -Control $script:Controls -Apply)

        foreach ($r in $results) {
            $r.Status | Should -Be 'Remediated' -Because "$($r.Id) should have been fixed and then confirmed fixed"
            $r.Changed | Should -BeTrue
        }

        $script:FakeRegistry['HKLM:\Test|Alpha'] | Should -Be 1
        $script:FakeRegistry['HKLM:\Test|Beta'] | Should -Be 0
        $script:FakeRegistry['HKLM:\Test|Gamma'] | Should -Be 'yes'
    }

    It 'leaves an already-compliant control alone' {
        $script:FakeRegistry['HKLM:\Test|Alpha'] = 1

        $results = @(Invoke-HardeningControl -Control $script:Controls -Apply)
        ($results | Where-Object Id -EQ 'TST-001').Status | Should -Be 'Compliant'
        ($results | Where-Object Id -EQ 'TST-001').Changed | Should -BeFalse
    }

    It 'treats a control as drifted when only some of its values are set' {
        $script:FakeRegistry['HKLM:\Test|Beta'] = 0

        $results = @(Invoke-HardeningControl -Control $script:Controls)
        ($results | Where-Object Id -EQ 'TST-002').Status | Should -Be 'Drift'
    }

    It 'makes no change under -WhatIf' {
        $results = @(Invoke-HardeningControl -Control $script:Controls -Apply -WhatIf)

        foreach ($r in $results) { $r.Status | Should -Be 'WhatIf' }
        Should -Invoke Set-RegistryValue -Times 0 -Because '-WhatIf must never reach the registry'
        $script:FakeRegistry.Keys.Count | Should -Be 0
    }

    It 'records the previous value in the rollback journal before overwriting it' {
        $journal = Join-Path ([IO.Path]::GetTempPath()) "kcm-apply-$([guid]::NewGuid()).json"
        try {
            $script:FakeKeys['HKLM:\Test'] = $true
            $script:FakeRegistry['HKLM:\Test|Alpha'] = 99

            Initialize-HardeningState -Path $journal
            $null = Invoke-HardeningControl -Control $script:Controls -Apply

            $entry = @($script:State.Entries | Where-Object { $_.Before.Name -eq 'Alpha' })
            $entry.Count | Should -Be 1
            $entry[0].Before.Value | Should -Be 99 -Because 'rollback has to know what the value was before we touched it'
            $entry[0].Before.ValueExists | Should -BeTrue
            $entry[0].ControlId | Should -Be 'TST-001'
        } finally {
            Remove-Item -LiteralPath $journal -Force -ErrorAction SilentlyContinue
        }
    }

    It 'records that a key did not exist so rollback can remove it' {
        $journal = Join-Path ([IO.Path]::GetTempPath()) "kcm-apply-$([guid]::NewGuid()).json"
        try {
            Initialize-HardeningState -Path $journal
            $null = Invoke-HardeningControl -Control $script:Controls -Apply

            $entry = @($script:State.Entries | Where-Object { $_.Before.Name -eq 'Alpha' })[0]
            $entry.Before.KeyExisted | Should -BeFalse
            $entry.Before.ValueExists | Should -BeFalse
        } finally {
            Remove-Item -LiteralPath $journal -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Engine error isolation' {

    It 'reports a failing Test as drift instead of aborting the run' {
        $controls = @(
            New-HardeningControl -Id 'TST-010' -Name 'explodes' -Category 'Firewall' -Rationale 'r' `
                -Test { throw 'cmdlet not found' } -Apply { }
            New-HardeningControl -Id 'TST-011' -Name 'fine' -Category 'Firewall' -Rationale 'r' `
                -Test { $true } -Apply { }
        )

        $results = @(Invoke-HardeningControl -Control $controls)

        $results.Count | Should -Be 2 -Because 'one broken control must not stop the others'
        ($results | Where-Object Id -EQ 'TST-010').Status | Should -Be 'Drift'
        ($results | Where-Object Id -EQ 'TST-010').Error | Should -Match 'cmdlet not found'
        ($results | Where-Object Id -EQ 'TST-011').Status | Should -Be 'Compliant'
    }

    It 'never runs Apply for a control whose Test failed' {
        $script:Applied = $false
        $controls = @(
            New-HardeningControl -Id 'TST-012' -Name 'explodes' -Category 'Firewall' -Rationale 'r' `
                -Test { throw 'boom' } -Apply { $script:Applied = $true }
        )

        $null = Invoke-HardeningControl -Control $controls -Apply
        $script:Applied | Should -BeFalse -Because 'applying a change blind, when we could not read the current state, risks breaking the host'
    }

    It 'reports a failing Apply as an error' {
        $controls = @(
            New-HardeningControl -Id 'TST-013' -Name 'apply fails' -Category 'Firewall' -Rationale 'r' `
                -Test { $false } -Apply { throw 'access denied' }
        )

        $results = @(Invoke-HardeningControl -Control $controls -Apply)
        $results[0].Status | Should -Be 'Error'
        $results[0].Error | Should -Match 'access denied'
    }

    It 'reports a control that applied cleanly but still fails its own re-check' {
        $controls = @(
            New-HardeningControl -Id 'TST-014' -Name 'does not stick' -Category 'Firewall' -Rationale 'r' `
                -Test { $false } -Apply { }
        )

        $results = @(Invoke-HardeningControl -Control $controls -Apply)
        $results[0].Status | Should -Be 'Failed'
    }

    It 'reports a reboot-bearing control that does not stick as pending rather than failed' {
        $controls = @(
            New-HardeningControl -Id 'TST-015' -Name 'needs a restart' -Category 'Credentials' -Rationale 'r' `
                -RequiresReboot -Test { $false } -Apply { }
        )

        $results = @(Invoke-HardeningControl -Control $controls -Apply)
        $results[0].Status | Should -Be 'PendingReboot'
    }

    It 'flags an audit-only control for manual action and never applies it' {
        $script:Applied = $false
        $controls = @(
            New-HardeningControl -Id 'TST-016' -Name 'tamper protection' -Category 'Defender' -Rationale 'r' `
                -AuditOnly -Test { $false } -Apply { $script:Applied = $true }
        )

        $results = @(Invoke-HardeningControl -Control $controls -Apply)
        $results[0].Status | Should -Be 'Manual'
        $script:Applied | Should -BeFalse
    }

    It 'reports an audit-only control that is already compliant as compliant' {
        $controls = @(
            New-HardeningControl -Id 'TST-017' -Name 'tamper protection' -Category 'Defender' -Rationale 'r' `
                -AuditOnly -Test { $true } -Apply { }
        )

        (Invoke-HardeningControl -Control $controls -Apply).Status | Should -Be 'Compliant'
    }
}

Describe 'Rollback journal' {

    BeforeEach {
        $script:JournalPath = Join-Path ([IO.Path]::GetTempPath()) "kcm-journal-$([guid]::NewGuid()).json"
    }

    AfterEach {
        Remove-Item -LiteralPath $script:JournalPath -Force -ErrorAction SilentlyContinue
    }

    It 'round-trips recorded changes through disk' {
        Initialize-HardeningState -Path $script:JournalPath

        Add-HardeningStateEntry -Kind 'Registry' -ControlId 'CRD-001' -Before @{
            Path = 'HKLM:\Test'; Name = 'UseLogonCredential'; Type = 'DWord'
            KeyExisted = $true; ValueExists = $true; Value = 1
        }
        Add-HardeningStateEntry -Kind 'Service' -ControlId 'RMT-001' -Before @{
            Name = 'RemoteRegistry'; StartMode = 'Manual'; Status = 'Running'
        }

        Save-HardeningState

        $loaded = Import-HardeningState -Path $script:JournalPath
        $loaded.SchemaVersion | Should -Be 1
        @($loaded.Entries).Count | Should -Be 2
        $loaded.Entries[0].Before.Value | Should -Be 1
        $loaded.Entries[1].Before.StartMode | Should -Be 'Manual'
    }

    It 'does not write an empty journal' {
        Initialize-HardeningState -Path $script:JournalPath
        Save-HardeningState
        Test-Path -LiteralPath $script:JournalPath | Should -BeFalse
    }

    It 'writes nothing under -WhatIf' {
        Initialize-HardeningState -Path $script:JournalPath
        Add-HardeningStateEntry -Kind 'Note' -ControlId 'X' -Before @{ Description = 'test' }
        Save-HardeningState -WhatIf
        Test-Path -LiteralPath $script:JournalPath | Should -BeFalse
    }

    It 'fails clearly when asked to restore a journal that does not exist' {
        { Import-HardeningState -Path (Join-Path ([IO.Path]::GetTempPath()) 'does-not-exist.json') } |
            Should -Throw -ExpectedMessage '*No rollback journal found*'
    }

    It 'records the firewall rule group only once however many controls use it' {
        Initialize-HardeningState -Path $script:JournalPath

        Register-FirewallGroupForRollback -ControlId 'FWL-001' -Group 'Kali Countermeasures'
        Register-FirewallGroupForRollback -ControlId 'FWL-002' -Group 'Kali Countermeasures'
        Register-FirewallGroupForRollback -ControlId 'FWL-003' -Group 'Kali Countermeasures'

        @($script:State.Entries | Where-Object Kind -EQ 'FirewallGroup').Count | Should -Be 1
    }
}

Describe 'Restore-HardeningState' {

    BeforeEach {
        $script:FakeRegistry = @{}
        $script:FakeKeys = @{}
        $script:Removed = @()

        Mock Test-RegistryKeyExists { $script:FakeKeys.ContainsKey($Path) }
        Mock Set-RegistryValue {
            $script:FakeKeys[$Path] = $true
            $script:FakeRegistry["$Path|$Name"] = $Value
        }
        Mock Remove-RegistryValue {
            $script:Removed += "$Path|$Name"
            $script:FakeRegistry.Remove("$Path|$Name")
        }

        $script:JournalPath = Join-Path ([IO.Path]::GetTempPath()) "kcm-restore-$([guid]::NewGuid()).json"
    }

    AfterEach {
        Remove-Item -LiteralPath $script:JournalPath -Force -ErrorAction SilentlyContinue
    }

    It 'puts a previously set value back' {
        Initialize-HardeningState -Path $script:JournalPath
        Add-HardeningStateEntry -Kind 'Registry' -ControlId 'CRD-001' -Before @{
            Path = 'HKLM:\Test'; Name = 'UseLogonCredential'; Type = 'DWord'
            KeyExisted = $true; ValueExists = $true; Value = 1
        }
        Save-HardeningState

        $script:FakeKeys['HKLM:\Test'] = $true
        $script:FakeRegistry['HKLM:\Test|UseLogonCredential'] = 0

        $outcome = Restore-HardeningState -Path $script:JournalPath -Confirm:$false

        $outcome.Restored | Should -Be 1
        $script:FakeRegistry['HKLM:\Test|UseLogonCredential'] | Should -Be 1
    }

    It 'removes a value that did not exist before hardening' {
        Initialize-HardeningState -Path $script:JournalPath
        Add-HardeningStateEntry -Kind 'Registry' -ControlId 'PRT-001' -Before @{
            Path = 'HKLM:\Policies'; Name = 'EnableMulticast'; Type = 'DWord'
            KeyExisted = $false; ValueExists = $false; Value = $null
        }
        Save-HardeningState

        $script:FakeKeys['HKLM:\Policies'] = $true
        $script:FakeRegistry['HKLM:\Policies|EnableMulticast'] = 0

        $outcome = Restore-HardeningState -Path $script:JournalPath -Confirm:$false

        $outcome.Restored | Should -Be 1
        $script:Removed | Should -Contain 'HKLM:\Policies|EnableMulticast'
        $script:FakeRegistry.ContainsKey('HKLM:\Policies|EnableMulticast') | Should -BeFalse
    }

    It 'replays entries newest first so overlapping changes unwind in order' {
        Initialize-HardeningState -Path $script:JournalPath
        foreach ($value in @(10, 20, 30)) {
            Add-HardeningStateEntry -Kind 'Registry' -ControlId "TST-0$value" -Before @{
                Path = 'HKLM:\Test'; Name = 'Shared'; Type = 'DWord'
                KeyExisted = $true; ValueExists = $true; Value = $value
            }
        }
        Save-HardeningState

        $script:FakeKeys['HKLM:\Test'] = $true
        $null = Restore-HardeningState -Path $script:JournalPath -Confirm:$false

        # Entries replay 30, 20, 10, so the value recorded first wins, which is the state
        # the host was in before any control touched it.
        $script:FakeRegistry['HKLM:\Test|Shared'] | Should -Be 10
    }

    It 'surfaces entries that need a human instead of silently skipping them' {
        Initialize-HardeningState -Path $script:JournalPath
        Add-HardeningStateEntry -Kind 'Note' -ControlId 'LOG-001' -Before @{
            Description = 'Audit subcategory setting before hardening.'
            Subcategory = 'Process Creation'
            Setting     = 0
        }
        Save-HardeningState

        $outcome = Restore-HardeningState -Path $script:JournalPath -Confirm:$false
        $outcome.ManualRequired | Should -Be 1
        $outcome.Failed | Should -Be 0
    }

    It 'keeps going when one entry cannot be restored' {
        Initialize-HardeningState -Path $script:JournalPath
        Add-HardeningStateEntry -Kind 'Registry' -ControlId 'A' -Before @{
            Path = 'HKLM:\Test'; Name = 'Good'; Type = 'DWord'
            KeyExisted = $true; ValueExists = $true; Value = 5
        }
        Add-HardeningStateEntry -Kind 'Service' -ControlId 'B' -Before @{
            Name = 'Nonexistent'; StartMode = 'Gibberish'; Status = 'Stopped'
        }
        Save-HardeningState

        $script:FakeKeys['HKLM:\Test'] = $true
        $outcome = Restore-HardeningState -Path $script:JournalPath -Confirm:$false

        $outcome.Total | Should -Be 2
        $script:FakeRegistry['HKLM:\Test|Good'] | Should -Be 5 -Because 'one bad entry must not block the rest of the rollback'
    }
}

Describe 'Catalogue resilience on a host where the cmdlets are missing' {

    It 'produces a result for every control even when every Test block throws' {
        # On a non-Windows host every Windows-specific cmdlet is absent, so this exercises
        # the worst case: each control's Test block fails. The run must still complete and
        # account for every control rather than stopping at the first error.
        $catalog = @(Get-FirewallControl) + @(Get-ProtocolControl) + @(Get-CredentialControl) +
        @(Get-RemoteAccessControl) + @(Get-ServiceControl) + @(Get-DefenderControl -Tier 'Standard') +
        @(Get-TelemetryControl)

        $results = @(Invoke-HardeningControl -Control $catalog 6>$null)

        $results.Count | Should -Be $catalog.Count
        foreach ($r in $results) {
            $r.Status | Should -BeIn @('Compliant', 'Drift', 'Manual')
            $r.Id | Should -Not -BeNullOrEmpty
        }
    }
}
