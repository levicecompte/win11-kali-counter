<#
    Rollback.ps1 - Restores the host from a rollback journal written by an Apply run.

    Entries are replayed newest-first so that controls which touched the same key
    unwind in the opposite order to the one they were applied in.
#>

function Restore-HardeningState {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    $state = Import-HardeningState -Path $Path
    $entries = @($state.Entries)
    [array]::Reverse($entries)

    Write-HardeningLog "Restoring $($entries.Count) recorded change(s) from $Path" 'Info'
    Write-HardeningLog "Journal written $($state.CreatedUtc) on $($state.ComputerName)" 'Detail'

    $restored = 0
    $manual = [System.Collections.Generic.List[object]]::new()
    $failed = [System.Collections.Generic.List[object]]::new()

    foreach ($entry in $entries) {
        try {
            switch ($entry.Kind) {
                'Registry' { if (Restore-RegistryEntry -Entry $entry) { $restored++ } }
                'Service' { if (Restore-ServiceEntry -Entry $entry) { $restored++ } }
                'FirewallGroup' { if (Restore-FirewallGroupEntry -Entry $entry) { $restored++ } }
                'FirewallRule' { if (Restore-FirewallRuleEntry -Entry $entry) { $restored++ } }
                'FirewallProfile' { if (Restore-FirewallProfileEntry -Entry $entry) { $restored++ } }
                'Defender' { if (Restore-DefenderEntry -Entry $entry) { $restored++ } }
                'Note' {
                    $manual.Add($entry)
                    Write-HardeningLog "manual: [$($entry.ControlId)] $($entry.Before.Description)" 'Warn'
                    foreach ($p in $entry.Before.PSObject.Properties) {
                        if ($p.Name -eq 'Description') { continue }
                        Write-HardeningLog "$($p.Name) = $(Format-RegistryValue -Value $p.Value)" 'Detail'
                    }
                }
                default { Write-HardeningLog "Unknown journal entry kind '$($entry.Kind)', skipped." 'Warn' }
            }
        } catch {
            $failed.Add([pscustomobject]@{ Entry = $entry; Error = $_.Exception.Message })
            Write-HardeningLog "Failed to restore a $($entry.Kind) entry for $($entry.ControlId): $($_.Exception.Message)" 'Bad'
        }
    }

    [pscustomobject]@{
        Total          = $entries.Count
        Restored       = $restored
        ManualRequired = $manual.Count
        Failed         = $failed.Count
        Failures       = $failed
    }
}

function Restore-RegistryEntry {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Entry)

    $before = $Entry.Before
    $target = "$($before.Path)\$($before.Name)"

    if ($before.ValueExists) {
        if (-not $PSCmdlet.ShouldProcess($target, "Restore to '$(Format-RegistryValue -Value $before.Value)'")) { return $false }

        Set-RegistryValue -Path $before.Path -Name $before.Name -Value $before.Value -Type $before.Type
        Write-HardeningLog "restored $target" 'Detail'
        return $true
    }

    if (-not (Test-RegistryKeyExists -Path $before.Path)) { return $false }
    if (-not $PSCmdlet.ShouldProcess($target, 'Remove value added during hardening')) { return $false }

    Remove-RegistryValue -Path $before.Path -Name $before.Name -RemoveEmptyKey:(-not $before.KeyExisted)

    Write-HardeningLog "removed $target" 'Detail'
    $true
}

function Restore-ServiceEntry {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Entry)

    $before = $Entry.Before
    $startupType = switch ([string]$before.StartMode) {
        'Auto' { 'Automatic' }
        'Automatic' { 'Automatic' }
        'Manual' { 'Manual' }
        'Disabled' { 'Disabled' }
        default { $null }
    }

    if (-not $startupType) {
        Write-HardeningLog "Unknown prior start mode '$($before.StartMode)' for service $($before.Name); left disabled." 'Warn'
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess("Service $($before.Name)", "Restore startup type $startupType")) { return $false }

    Set-Service -Name $before.Name -StartupType $startupType -ErrorAction Stop
    if ($before.Status -eq 'Running') {
        Start-Service -Name $before.Name -ErrorAction SilentlyContinue
    }

    Write-HardeningLog "restored service $($before.Name) -> $startupType" 'Detail'
    $true
}

function Restore-FirewallGroupEntry {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Entry)

    $group = $Entry.Before.Group
    if (-not $PSCmdlet.ShouldProcess("Firewall group '$group'", 'Remove all rules created by this toolkit')) { return $false }

    Remove-NetFirewallRule -Group $group -ErrorAction SilentlyContinue
    Write-HardeningLog "removed firewall rule group '$group'" 'Detail'
    $true
}

function Restore-FirewallRuleEntry {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Entry)

    $before = $Entry.Before
    if (-not $PSCmdlet.ShouldProcess("Firewall rule '$($before.Name)'", "Restore profile '$($before.Profile)'")) { return $false }

    Set-NetFirewallRule -Name $before.Name -Profile $before.Profile -Enabled $before.Enabled -ErrorAction SilentlyContinue
    Write-HardeningLog "restored firewall rule $($before.Name)" 'Detail'
    $true
}

function Restore-FirewallProfileEntry {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Entry)

    $before = $Entry.Before
    if (-not $PSCmdlet.ShouldProcess("Firewall profile '$($before.Name)'", 'Restore previous settings')) { return $false }

    $params = @{ Name = $before.Name; ErrorAction = 'SilentlyContinue' }
    foreach ($field in @('Enabled', 'DefaultInboundAction', 'NotifyOnListen', 'LogBlocked', 'LogMaxSizeKilobytes', 'LogFileName')) {
        $prop = $before.PSObject.Properties[$field]
        if ($prop -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value) -and [string]$prop.Value -ne 'NotConfigured') {
            $params[$field] = $prop.Value
        }
    }

    Set-NetFirewallProfile @params
    Write-HardeningLog "restored firewall profile $($before.Name)" 'Detail'
    $true
}

function Restore-DefenderEntry {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Entry)

    $before = $Entry.Before
    if ($before.PSObject.Properties['Error']) {
        Write-HardeningLog 'Defender state was not captured for this entry; nothing to restore.' 'Warn'
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess('Microsoft Defender', 'Restore previous preferences')) { return $false }

    $map = @{
        MAPSReporting                = $before.MAPSReporting
        SubmitSamplesConsent         = $before.SubmitSamplesConsent
        PUAProtection                = $before.PUAProtection
        EnableNetworkProtection      = $before.EnableNetworkProtection
        EnableControlledFolderAccess = $before.EnableControlledFolderAccess
    }

    foreach ($key in $map.Keys) {
        $value = [string]$map[$key]
        if ([string]::IsNullOrWhiteSpace($value)) { continue }

        $splat = @{ $key = $value; ErrorAction = 'SilentlyContinue' }
        Set-MpPreference @splat
    }

    # ASR rules are additive, so the rules this run enabled are removed by id rather
    # than by rewriting the whole list, which would discard rules set by other tooling.
    $previousIds = @($before.AttackSurfaceReductionRules_Ids)
    foreach ($rule in Get-AsrRuleDefinition) {
        if ($rule.Id -in $previousIds) { continue }
        Remove-MpPreference -AttackSurfaceReductionRules_Ids $rule.Id -ErrorAction SilentlyContinue
    }

    Write-HardeningLog 'restored Defender preferences' 'Detail'
    $true
}
