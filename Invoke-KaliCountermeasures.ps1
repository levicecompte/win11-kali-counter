#Requires -Version 5.1

<#
.SYNOPSIS
    Hardens Windows 11 against the attack tooling shipped with penetration-testing
    distributions, and sweeps the host for evidence that such tooling is already running.

.DESCRIPTION
    Applies a catalogue of controls across firewall rules, broadcast name-resolution
    protocols, SMB/NTLM dialects, credential storage, remote-execution surface, Defender
    Attack Surface Reduction, and audit logging. Each control knows what it counters,
    why it works and what it costs, and every change is recorded in a rollback journal
    so the whole run can be undone.

    BitLocker and every other volume-encryption setting are deliberately out of scope.
    The toolkit never reads or modifies them, and the control model refuses to register
    a control tagged for those subsystems.

.PARAMETER Mode
    Audit    - report current state, change nothing. Default.
    Apply    - bring drifted controls into the hardened state, recording a rollback journal.
    Rollback - restore everything recorded in a journal from a previous Apply run.
    Sweep    - read-only hunt for an active attacker on this host or network segment.
    List     - print the control catalogue and exit.

.PARAMETER Tier
    Baseline   - high value, low operational impact. Safe for any workstation.
    Standard   - the recommended default. Adds controls with a small amount of friction.
    Aggressive - maximum reduction in attack surface, with real usability costs.
                 Read the impact text before using this on a machine you depend on.

.PARAMETER Category
    Restrict the run to one or more of: Firewall, Protocols, Credentials, RemoteAccess,
    Services, Defender, Telemetry.

.PARAMETER Include
    Only run these control IDs. Overrides the tier ceiling, so a single Aggressive
    control can be cherry-picked without raising the tier for everything else.

.PARAMETER Exclude
    Skip these control IDs. Always wins over -Include.

.EXAMPLE
    .\Invoke-KaliCountermeasures.ps1
    Audit the host at the Standard tier and print what would change.

.EXAMPLE
    .\Invoke-KaliCountermeasures.ps1 -Mode Apply -Tier Standard -WhatIf
    Show every change an Apply run would make, without making any of them.

.EXAMPLE
    .\Invoke-KaliCountermeasures.ps1 -Mode Apply -Tier Aggressive -Exclude SVC-002,RMT-003
    Apply everything except disabling the print spooler and Remote Desktop Services.

.EXAMPLE
    .\Invoke-KaliCountermeasures.ps1 -Mode Sweep -ReportPath .\sweep.html
    Hunt for an active attacker and write an HTML report.

.EXAMPLE
    .\Invoke-KaliCountermeasures.ps1 -Mode Rollback -StatePath C:\ProgramData\KaliCountermeasures\rollback-20260101-120000.json
    Undo a previous Apply run.

.NOTES
    Run from an elevated PowerShell session. Audit, Sweep and List work unelevated but
    will report less. Test on a non-critical machine before applying the Aggressive tier.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Audit', 'Apply', 'Rollback', 'Sweep', 'List')]
    [string]$Mode = 'Audit',

    [ValidateSet('Baseline', 'Standard', 'Aggressive')]
    [string]$Tier = 'Standard',

    [ValidateSet('Firewall', 'Protocols', 'Credentials', 'RemoteAccess', 'Services', 'Defender', 'Telemetry')]
    [string[]]$Category = @(),

    [string[]]$Include = @(),

    [string[]]$Exclude = @(),

    [string]$StatePath,

    [string]$ReportPath,

    [string]$JsonPath,

    [ValidateRange(1, 720)]
    [int]$SweepHours = 24,

    [switch]$IncludeSweep,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:DataDirectory = if ($env:ProgramData) { Join-Path $env:ProgramData 'KaliCountermeasures' } else { Join-Path $script:Root '.state' }

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
    # Two-argument Join-Path only: the three-argument form does not exist on Windows PowerShell 5.1.
    . (Join-Path (Join-Path $script:Root 'src') $file)
}

function Get-ControlCatalog {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([string]$Tier = 'Standard')

    @(Get-FirewallControl) +
    @(Get-ProtocolControl) +
    @(Get-CredentialControl) +
    @(Get-RemoteAccessControl) +
    @(Get-ServiceControl) +
    @(Get-DefenderControl -Tier $Tier) +
    @(Get-TelemetryControl)
}

function Show-ControlCatalog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Control)

    foreach ($group in ($Control | Group-Object Category | Sort-Object Name)) {
        Write-Host ''
        Write-HardeningLog "$($group.Name) ($($group.Count))" 'Step'

        foreach ($c in ($group.Group | Sort-Object Id)) {
            $flags = @()
            if ($c.RequiresReboot) { $flags += 'reboot' }
            if ($c.AuditOnly) { $flags += 'audit-only' }
            $suffix = if ($flags.Count) { " [$($flags -join ', ')]" } else { '' }

            Write-HardeningLog ("{0,-8} {1,-11} {2}{3}" -f $c.Id, $c.Tier, $c.Name, $suffix) 'Info'
            Write-HardeningLog "counters: $(@($c.Counters) -join ', ')" 'Detail'
            Write-HardeningLog "impact:   $($c.Impact)" 'Detail'
        }
    }
}

function Test-RunnableEnvironment {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Mode,
        [Parameter(Mandatory)][pscustomobject]$Facts
    )

    if ($Mode -eq 'List') { return $true }

    if (-not $Facts.IsWindows) {
        Write-HardeningLog 'This toolkit configures Windows security settings and can only run on Windows.' 'Bad'
        Write-HardeningLog 'Use -Mode List to review the control catalogue on any platform.' 'Detail'
        return $false
    }

    if ($Mode -in @('Apply', 'Rollback') -and -not $Facts.IsElevated) {
        Write-HardeningLog "Mode '$Mode' changes machine-wide settings and needs an elevated session." 'Bad'
        Write-HardeningLog 'Close this window and start PowerShell with "Run as administrator".' 'Detail'
        return $false
    }

    if (-not $Facts.IsElevated) {
        Write-HardeningLog 'Running without administrator rights. Some controls cannot be read and will report as drifted.' 'Warn'
    }

    $true
}

$facts = Get-HostFacts

Write-HardeningBanner -Title 'Windows 11 countermeasures against pen-testing toolkits' `
    -Subtitle "Mode: $Mode | Tier: $Tier | Host: $($facts.ComputerName) ($($facts.OSCaption) build $($facts.OSBuild))"

Write-HardeningLog 'BitLocker and volume encryption are deliberately excluded from this toolkit and are never read or modified.' 'Info'

if (-not (Test-RunnableEnvironment -Mode $Mode -Facts $facts)) { exit 1 }

$catalog = @(Get-ControlCatalog -Tier $Tier)

if ($Mode -eq 'List') {
    $listed = @(Select-HardeningControl -Control $catalog -Tier $Tier -Category $Category -Include $Include -Exclude $Exclude)
    Write-HardeningLog "$($listed.Count) of $($catalog.Count) controls match this selection." 'Info'
    Show-ControlCatalog -Control $listed
    exit 0
}

if ($Mode -eq 'Rollback') {
    if (-not $StatePath) {
        $journals = @(Get-ChildItem -Path $script:DataDirectory -Filter 'rollback-*.json' -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending)
        if ($journals.Count -eq 0) {
            throw "No rollback journal found in $($script:DataDirectory). Pass -StatePath to point at one explicitly."
        }
        $StatePath = $journals[0].FullName
        Write-HardeningLog "Using the most recent journal: $StatePath" 'Info'
    }

    if (-not $Force -and -not $PSCmdlet.ShouldContinue(
            "Restore every setting recorded in $StatePath?",
            'Roll back hardening')) {
        Write-HardeningLog 'Rollback cancelled.' 'Warn'
        return
    }

    $outcome = Restore-HardeningState -Path $StatePath
    Write-Host ''
    Write-HardeningLog "Restored $($outcome.Restored) of $($outcome.Total) recorded changes." $(if ($outcome.Failed -gt 0) { 'Warn' } else { 'Good' })
    if ($outcome.ManualRequired -gt 0) {
        Write-HardeningLog "$($outcome.ManualRequired) change(s) need manual attention - see the 'manual:' lines above." 'Warn'
    }
    exit $(if ($outcome.Failed -gt 0) { 3 } else { 0 })
}

$findings = @()

if ($Mode -eq 'Sweep' -or $IncludeSweep) {
    Write-Host ''
    Write-HardeningBanner -Title 'Threat sweep' -Subtitle "Read-only. Examining the last $SweepHours hour(s)."
    $findings = @(Invoke-ThreatSweep -Hours $SweepHours -BaselinePath (Join-Path $script:DataDirectory 'gateway-baseline.json'))
    Write-SweepSummary -Finding $findings
}

$results = @()

if ($Mode -in @('Audit', 'Apply')) {
    $selected = @(Select-HardeningControl -Control $catalog -Tier $Tier -Category $Category -Include $Include -Exclude $Exclude)

    if ($selected.Count -eq 0) {
        Write-HardeningLog 'No controls matched the given filters.' 'Warn'
        return
    }

    Write-Host ''
    Write-HardeningLog "$($selected.Count) of $($catalog.Count) controls selected." 'Info'

    if ($Mode -eq 'Apply' -and -not $WhatIfPreference) {
        $aggressive = @($selected | Where-Object Tier -EQ 'Aggressive')
        if ($aggressive.Count -gt 0) {
            Write-Host ''
            Write-HardeningLog "$($aggressive.Count) Aggressive control(s) selected. These have real usability costs:" 'Warn'
            foreach ($a in $aggressive) { Write-HardeningLog "$($a.Id)  $($a.Name) - $($a.Impact)" 'Detail' }
        }

        if (-not $Force -and -not $PSCmdlet.ShouldContinue(
                "Apply $($selected.Count) control(s) at the $Tier tier to $($facts.ComputerName)? A rollback journal will be written first.",
                'Harden this machine')) {
            Write-HardeningLog 'Apply cancelled. Nothing was changed.' 'Warn'
            return
        }

        if (-not $StatePath) {
            $StatePath = Join-Path $script:DataDirectory ("rollback-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        }
        Initialize-HardeningState -Path $StatePath
    }

    Write-Host ''
    $results = @(Invoke-HardeningControl -Control $selected -Apply:($Mode -eq 'Apply'))

    if ($Mode -eq 'Apply') {
        Save-HardeningState
    }

    Write-HardeningSummary -Result $results -Mode $Mode
}

if ($ReportPath) {
    Export-HardeningReport -Path $ReportPath -Mode $Mode -Result $results -Finding $findings -Facts $facts
}

if ($JsonPath) {
    Export-HardeningJson -Path $JsonPath -Mode $Mode -Result $results -Finding $findings -Facts $facts
}

$drifted = @($results | Where-Object Status -EQ 'Drift').Count
$actionableFindings = @($findings | Where-Object { $_.Severity -ne 'Info' }).Count

if ($Mode -eq 'Audit' -and $drifted -gt 0) {
    Write-Host ''
    Write-HardeningLog 'Re-run with -Mode Apply to remediate, or add -WhatIf first to preview every change.' 'Info'
}

# Exit codes are stable so this can be wired into scheduled tasks and monitoring:
#   0 clean, 2 drift or findings present, 3 a control failed to apply, 1 fatal error.
if (@($results | Where-Object { $_.Status -in @('Failed', 'Error') }).Count -gt 0) { exit 3 }
if ($drifted -gt 0 -or $actionableFindings -gt 0) { exit 2 }
exit 0
