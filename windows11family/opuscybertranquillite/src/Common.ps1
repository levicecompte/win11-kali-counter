<#
    Common.ps1 - Core engine for the Kali-countermeasure hardening toolkit.

    Provides the control model, console logging, guarded (snapshot-backed) mutators
    for registry/service/firewall state, and the rollback journal.
#>

# Declared up front so Set-StrictMode does not trip on them before an Apply run
# initialises the rollback journal. Audit, Sweep and List never touch them.
$script:State = $null
$script:StatePath = $null

$script:ExcludedSubsystemTags = @('bitlocker', 'disk-encryption', 'volume-encryption')

$script:ControlCategories = @(
    'Firewall'
    'Protocols'
    'Credentials'
    'RemoteAccess'
    'Services'
    'Defender'
    'Telemetry'
)

$script:ControlTiers = @('Baseline', 'Standard', 'Aggressive')

$script:FirewallGroupName = 'Kali Countermeasures'

#region Console output

$script:LogStyles = @{
    Info    = @{ Prefix = '[*]'; Color = 'Cyan' }
    Step    = @{ Prefix = '[>]'; Color = 'White' }
    Good    = @{ Prefix = '[+]'; Color = 'Green' }
    Warn    = @{ Prefix = '[!]'; Color = 'Yellow' }
    Bad     = @{ Prefix = '[-]'; Color = 'Red' }
    Detail  = @{ Prefix = '    '; Color = 'DarkGray' }
}

function Write-HardeningLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [Parameter(Position = 1)]
        [ValidateSet('Info', 'Step', 'Good', 'Warn', 'Bad', 'Detail')]
        [string]$Level = 'Info'
    )

    $style = $script:LogStyles[$Level]
    $line = if ($Level -eq 'Detail') { "$($style.Prefix)$Message" } else { "$($style.Prefix) $Message" }

    Write-Host $line -ForegroundColor $style.Color
}

function Write-HardeningBanner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Title,
        [string]$Subtitle
    )

    $width = 74
    Write-Host ''
    Write-Host ('=' * $width) -ForegroundColor DarkCyan
    Write-Host ("  $Title") -ForegroundColor White
    if ($Subtitle) { Write-Host ("  $Subtitle") -ForegroundColor DarkGray }
    Write-Host ('=' * $width) -ForegroundColor DarkCyan
}

#endregion

#region Environment guards

function Test-IsWindowsPlatform {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '',
        Justification = 'IsWindows is a built-in global automatic variable on PowerShell 6+, not a global of ours.')]
    [CmdletBinding()]
    param()

    # $IsWindows only exists on PowerShell 6+; Windows PowerShell 5.1 is always Windows.
    if (Get-Variable -Name 'IsWindows' -Scope Global -ErrorAction SilentlyContinue) {
        return [bool]$global:IsWindows
    }

    return $true
}

function Test-IsElevated {
    [CmdletBinding()]
    param()

    if (-not (Test-IsWindowsPlatform)) { return $false }

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Get-HostFacts {
    [CmdletBinding()]
    param()

    $facts = [ordered]@{
        ComputerName    = [Environment]::MachineName
        UserName        = [Environment]::UserName
        IsWindows       = Test-IsWindowsPlatform
        IsElevated      = Test-IsElevated
        PSVersion       = $PSVersionTable.PSVersion.ToString()
        OSCaption       = 'unknown'
        OSBuild         = 'unknown'
        DomainJoined    = $false
    }

    if ($facts.IsWindows) {
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $facts.OSCaption = $os.Caption
            $facts.OSBuild = $os.BuildNumber
        } catch {
            Write-Verbose "Unable to read Win32_OperatingSystem: $($_.Exception.Message)"
        }

        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $facts.DomainJoined = [bool]$cs.PartOfDomain
        } catch {
            Write-Verbose "Unable to read Win32_ComputerSystem: $($_.Exception.Message)"
        }
    }

    [pscustomobject]$facts
}

#endregion

#region Control model

function New-HardeningControl {
    <#
        .SYNOPSIS
        Declares a single hardening control.

        .DESCRIPTION
        Test  - scriptblock returning $true/$false or @{ Compliant = $bool; Detail = 'text' }
        Apply - scriptblock that brings the host into the compliant state. Must use the
                Set-Guarded* helpers so the change lands in the rollback journal.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Z]{3}-\d{3}$')][string]$Id,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Rationale,
        [Parameter(Mandatory)][scriptblock]$Test,
        [Parameter(Mandatory)][scriptblock]$Apply,
        [hashtable]$Data = @{},
        [string]$Tier = 'Standard',
        [string[]]$Counters = @(),
        [string[]]$Tags = @(),
        [string]$Impact = 'No user-visible impact expected.',
        [switch]$RequiresReboot,
        [switch]$AuditOnly
    )

    if ($Category -notin $script:ControlCategories) {
        throw "Control '$Id' declares unknown category '$Category'. Valid: $($script:ControlCategories -join ', ')"
    }

    if ($Tier -notin $script:ControlTiers) {
        throw "Control '$Id' declares unknown tier '$Tier'. Valid: $($script:ControlTiers -join ', ')"
    }

    foreach ($tag in $Tags) {
        if ($tag.ToLowerInvariant() -in $script:ExcludedSubsystemTags) {
            throw "Control '$Id' is tagged '$tag', which is an excluded subsystem. BitLocker and other volume-encryption settings are deliberately out of scope for this toolkit."
        }
    }

    [pscustomobject]@{
        PSTypeName     = 'Hardening.Control'
        Id             = $Id
        Name           = $Name
        Category       = $Category
        Tier           = $Tier
        Counters       = [string[]]$Counters
        Tags           = [string[]]$Tags
        Rationale      = $Rationale
        Impact         = $Impact
        RequiresReboot = [bool]$RequiresReboot
        AuditOnly      = [bool]$AuditOnly
        Data           = $Data
        Test           = $Test
        Apply          = $Apply
    }
}

function New-RegistryControl {
    <#
        .SYNOPSIS
        Declares a control backed purely by one or more registry values.

        .PARAMETER Setting
        One hashtable per value: @{ Path = 'HKLM:\...'; Name = 'Foo'; Value = 1; Type = 'DWord'; Label = 'friendly name' }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Rationale,
        [Parameter(Mandatory)][hashtable[]]$Setting,
        [string]$Tier = 'Standard',
        [string[]]$Counters = @(),
        [string[]]$Tags = @(),
        [string]$Impact = 'No user-visible impact expected.',
        [switch]$RequiresReboot
    )

    # Parameters travel on the control's Data bag rather than in a closure. A closure
    # built by GetNewClosure() lives in its own dynamic module, which makes its view of
    # the surrounding functions depend on where it happened to be created. Passing the
    # control in as an argument keeps every block in one session state.
    $test = {
        param($Control)

        $details = [System.Collections.Generic.List[string]]::new()
        $compliant = $true

        foreach ($s in $Control.Data.Settings) {
            $label = if ($s.ContainsKey('Label')) { $s.Label } else { $s.Name }
            $verdict = Test-RegistryCompliance -Path $s.Path -Name $s.Name -Expected $s.Value -Label $label
            if (-not $verdict.Compliant) { $compliant = $false }
            $details.Add($verdict.Detail)
        }

        @{ Compliant = $compliant; Detail = ($details -join ' ') }
    }

    $apply = {
        param($Control)

        foreach ($s in $Control.Data.Settings) {
            $type = if ($s.ContainsKey('Type')) { $s.Type } else { 'DWord' }
            Set-GuardedRegistryValue -Path $s.Path -Name $s.Name -Value $s.Value -Type $type -ControlId $Control.Id
        }
    }

    New-HardeningControl -Id $Id -Name $Name -Category $Category -Tier $Tier -Counters $Counters -Tags $Tags `
        -Rationale $Rationale -Impact $Impact -RequiresReboot:$RequiresReboot -Test $test -Apply $apply `
        -Data @{ Settings = $Setting }
}

function New-ServiceControl {
    <#
        .SYNOPSIS
        Declares a control that disables (and stops) one Windows service.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Rationale,
        [string]$Tier = 'Standard',
        [string[]]$Counters = @(),
        [string]$Impact = 'No user-visible impact expected.'
    )

    $test = {
        param($Control)

        $name = $Control.Data.ServiceName
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { return @{ Compliant = $true; Detail = "Service '$name' is not installed on this host." } }

        $wmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
        $mode = if ($wmi) { $wmi.StartMode } else { 'Unknown' }

        @{
            Compliant = ($mode -eq 'Disabled' -and $svc.Status -eq 'Stopped')
            Detail    = "Service '$name': StartMode=$mode, Status=$($svc.Status)."
        }
    }

    $apply = {
        param($Control)
        Set-GuardedServiceState -Name $Control.Data.ServiceName -StartupType Disabled -ControlId $Control.Id -StopService
    }

    New-HardeningControl -Id $Id -Name $Name -Category $Category -Tier $Tier -Counters $Counters `
        -Rationale $Rationale -Impact $Impact -Test $test -Apply $apply `
        -Data @{ ServiceName = $ServiceName }
}

function New-OptionalFeatureControl {
    <#
        .SYNOPSIS
        Declares a control that removes a Windows optional feature.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$FeatureName,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Rationale,
        [string]$Tier = 'Standard',
        [string[]]$Counters = @(),
        [string]$Impact = 'No user-visible impact expected.'
    )

    $test = {
        param($Control)

        $features = $Control.Data.FeatureName
        $enabled = [System.Collections.Generic.List[string]]::new()

        foreach ($f in $features) {
            $state = (Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue).State
            if ($state -eq 'Enabled') { $enabled.Add($f) }
        }

        @{
            Compliant = ($enabled.Count -eq 0)
            Detail    = if ($enabled.Count -eq 0) { "Features removed or absent: $($features -join ', ')." } else { "Still enabled: $($enabled -join ', ')." }
        }
    }

    $apply = {
        param($Control)

        foreach ($f in $Control.Data.FeatureName) {
            $state = (Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue).State
            if ($state -ne 'Enabled') { continue }
            if (-not (Test-ShouldApply -Target $f -Action 'Disable Windows optional feature')) { continue }

            Add-HardeningStateEntry -Kind 'Note' -ControlId $Control.Id -Before @{
                Description = 'Windows optional feature was enabled before hardening.'
                FeatureName = $f
                State       = 'Enabled'
            }
            $null = Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction SilentlyContinue
            Write-HardeningLog "feature: $f disabled" 'Detail'
        }
    }

    New-HardeningControl -Id $Id -Name $Name -Category $Category -Tier $Tier -Counters $Counters `
        -Rationale $Rationale -Impact $Impact -RequiresReboot -Test $test -Apply $apply `
        -Data @{ FeatureName = $FeatureName }
}

function ConvertTo-ControlVerdict {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowNull()]$Raw
    )

    if ($null -eq $Raw) {
        return [pscustomobject]@{ Compliant = $false; Detail = 'Test returned no value.' }
    }

    if ($Raw -is [bool]) {
        return [pscustomobject]@{
            Compliant = $Raw
            Detail    = if ($Raw) { 'Setting matches the hardened baseline.' } else { 'Setting does not match the hardened baseline.' }
        }
    }

    if ($Raw -is [System.Collections.IDictionary]) {
        return [pscustomobject]@{
            Compliant = [bool]$Raw['Compliant']
            Detail    = [string]$Raw['Detail']
        }
    }

    if ($Raw.PSObject.Properties.Name -contains 'Compliant') {
        return [pscustomobject]@{
            Compliant = [bool]$Raw.Compliant
            Detail    = [string]$Raw.Detail
        }
    }

    [pscustomobject]@{ Compliant = [bool]$Raw; Detail = 'Coerced non-standard test result.' }
}

function Select-HardeningControl {
    <#
        .SYNOPSIS
        Filters the control catalog by tier, category and explicit include/exclude lists.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Control,
        [string]$Tier = 'Standard',
        [string[]]$Category = @(),
        [string[]]$Include = @(),
        [string[]]$Exclude = @()
    )

    $maxRank = $script:ControlTiers.IndexOf($Tier)
    if ($maxRank -lt 0) { throw "Unknown tier '$Tier'." }

    $selected = foreach ($c in $Control) {
        if ($script:ControlTiers.IndexOf($c.Tier) -gt $maxRank) { continue }
        if ($Category.Count -and $c.Category -notin $Category) { continue }
        if ($Include.Count -and $c.Id -notin $Include) { continue }
        if ($Exclude.Count -and $c.Id -in $Exclude) { continue }
        $c
    }

    # Include always wins over the tier ceiling so an operator can cherry-pick one
    # aggressive control without raising the tier for everything else.
    if ($Include.Count) {
        $already = @($selected | ForEach-Object Id)
        $forced = $Control | Where-Object { $_.Id -in $Include -and $_.Id -notin $already -and $_.Id -notin $Exclude }
        $selected = @($selected) + @($forced)
    }

    @($selected) | Sort-Object Id
}

#endregion

#region Rollback journal

function Initialize-HardeningState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    $script:StatePath = $Path
    $script:State = [ordered]@{
        SchemaVersion = 1
        CreatedUtc    = (Get-Date).ToUniversalTime().ToString('o')
        ComputerName  = [Environment]::MachineName
        Entries       = [System.Collections.ArrayList]::new()
    }
}

function Add-HardeningStateEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Registry', 'Service', 'FirewallGroup', 'FirewallRule', 'FirewallProfile', 'Defender', 'Note')]
        [string]$Kind,
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][hashtable]$Before
    )

    if ($null -eq $script:State) { return }

    $null = $script:State.Entries.Add([ordered]@{
            Kind      = $Kind
            ControlId = $ControlId
            Captured  = (Get-Date).ToUniversalTime().ToString('o')
            Before    = $Before
        })
}

function Save-HardeningState {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($null -eq $script:State -or -not $script:StatePath) { return }
    if ($script:State.Entries.Count -eq 0) { return }

    $dir = Split-Path -Parent $script:StatePath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        $null = New-Item -ItemType Directory -Path $dir -Force
    }

    if ($PSCmdlet.ShouldProcess($script:StatePath, 'Write rollback journal')) {
        $script:State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:StatePath -Encoding UTF8
        Write-HardeningLog "Rollback journal written to $($script:StatePath) ($($script:State.Entries.Count) entries)." 'Info'
    }
}

function Import-HardeningState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "No rollback journal found at '$Path'. Nothing to restore."
    }

    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

#endregion

#region Guarded mutators

function Test-ShouldApply {
    <#
        .SYNOPSIS
        ShouldProcess gate usable from inside a control's Apply scriptblock.

        .DESCRIPTION
        Control scriptblocks have no $PSCmdlet of their own. Because $WhatIfPreference
        propagates down the call stack, this thin advanced function gives those blocks a
        correct -WhatIf aware gate without reaching into a caller's $PSCmdlet.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Action
    )

    $PSCmdlet.ShouldProcess($Target, $Action)
}

# Every registry read and write in this toolkit goes through the three functions below.
# Keeping the provider calls in one place means the hardening logic can be exercised
# against a simulated registry, and there is a single answer to "what does this touch?".

function Test-RegistryKeyExists {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    Test-Path -LiteralPath $Path
}

function Get-RegistryValueOrNull {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    if (-not (Test-RegistryKeyExists -Path $Path)) { return $null }

    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch {
        return $null
    }
}

function Set-RegistryValue {
    <#
        .SYNOPSIS
        Writes a registry value, creating the key if it does not exist.

        .DESCRIPTION
        Unguarded: callers are responsible for recording the prior state. Use
        Set-GuardedRegistryValue unless you are implementing rollback.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Value,
        [string]$Type = 'DWord'
    )

    if (-not (Test-RegistryKeyExists -Path $Path)) {
        $null = New-Item -Path $Path -Force
    }

    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

function Remove-RegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [switch]$RemoveEmptyKey
    )

    if (-not (Test-RegistryKeyExists -Path $Path)) { return }

    Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue

    if (-not $RemoveEmptyKey) { return }

    # Only ever removes a key this toolkit created, and only when nothing else is left in
    # it, so a key shared with other settings is never destroyed.
    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($key -and $key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    }
}

function Format-RegistryValue {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Value)

    if ($null -eq $Value) { return '<unset>' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @($Value)
        if ($items.Count -eq 0) { return '<empty>' }
        return ($items -join ', ')
    }
    [string]$Value
}

function Test-RegistryValueEqual {
    <#
        .SYNOPSIS
        Compares a registry value to an expected value, handling MultiString arrays.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Actual,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Expected
    )

    $expectedIsList = ($Expected -isnot [string]) -and ($Expected -is [System.Collections.IEnumerable])

    if ($expectedIsList) {
        # A missing MultiString and an empty one mean the same thing: no entries.
        $a = if ($null -eq $Actual) { @() } else { @($Actual) }
        $e = @($Expected)
        if ($a.Count -ne $e.Count) { return $false }
        for ($i = 0; $i -lt $e.Count; $i++) {
            if ([string]$a[$i] -ne [string]$e[$i]) { return $false }
        }
        return $true
    }

    if ($null -eq $Actual) { return $null -eq $Expected }

    # Registry DWords come back as int, policy strings as string; compare textually
    # so '1' and 1 are treated as the same configured state.
    [string]$Actual -eq [string]$Expected
}

function Test-RegistryCompliance {
    <#
        .SYNOPSIS
        Convenience test used by most registry-backed controls.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Expected,
        [string]$Label
    )

    $actual = Get-RegistryValueOrNull -Path $Path -Name $Name
    $label = if ($Label) { $Label } else { "$Name" }
    $expectedText = Format-RegistryValue -Value $Expected

    $expectsEmptyList = ($Expected -isnot [string]) -and ($Expected -is [System.Collections.IEnumerable]) -and (@($Expected).Count -eq 0)

    if ($null -eq $actual -and -not $expectsEmptyList) {
        return @{ Compliant = $false; Detail = "$label is not set (expected $expectedText)." }
    }

    @{
        Compliant = (Test-RegistryValueEqual -Actual $actual -Expected $Expected)
        Detail    = "$label = $(Format-RegistryValue -Value $actual) (expected $expectedText)."
    }
}

function Set-GuardedRegistryValue {
    <#
        .SYNOPSIS
        Writes a registry value after recording the prior state in the rollback journal.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Value,
        [ValidateSet('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')]
        [string]$Type = 'DWord',
        [Parameter(Mandatory)][string]$ControlId
    )

    $keyExisted = Test-RegistryKeyExists -Path $Path
    $previous = if ($keyExisted) { Get-RegistryValueOrNull -Path $Path -Name $Name } else { $null }
    $valueText = Format-RegistryValue -Value $Value

    if ($keyExisted -and (Test-RegistryValueEqual -Actual $previous -Expected $Value)) {
        Write-HardeningLog "$Path\$Name already $valueText" 'Detail'
        return
    }

    if (-not $PSCmdlet.ShouldProcess("$Path\$Name", "Set to '$valueText' ($Type)")) { return }

    Add-HardeningStateEntry -Kind 'Registry' -ControlId $ControlId -Before @{
        Path        = $Path
        Name        = $Name
        Type        = $Type
        KeyExisted  = $keyExisted
        ValueExists = ($null -ne $previous)
        Value       = $previous
    }

    Set-RegistryValue -Path $Path -Name $Name -Value $Value -Type $Type
    Write-HardeningLog "$Path\$Name -> $valueText" 'Detail'
}

function Set-GuardedServiceState {
    <#
        .SYNOPSIS
        Changes a service startup type (and optionally stops it) with rollback capture.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Automatic', 'Manual', 'Disabled')][string]$StartupType,
        [Parameter(Mandatory)][string]$ControlId,
        [switch]$StopService
    )

    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-HardeningLog "Service '$Name' is not present on this host; nothing to do." 'Detail'
        return
    }

    $wmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    $priorStart = if ($wmi) { $wmi.StartMode } else { 'Unknown' }

    if (-not $PSCmdlet.ShouldProcess("Service $Name", "Set startup to $StartupType$(if ($StopService) { ' and stop' })")) { return }

    Add-HardeningStateEntry -Kind 'Service' -ControlId $ControlId -Before @{
        Name        = $Name
        StartMode   = $priorStart
        Status      = [string]$svc.Status
    }

    Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop

    if ($StopService -and $svc.Status -ne 'Stopped') {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    }

    Write-HardeningLog "Service '$Name' -> $StartupType$(if ($StopService) { ' (stopped)' })" 'Detail'
}

function Register-FirewallGroupForRollback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Group
    )

    $alreadyTracked = $false
    if ($null -ne $script:State) {
        $alreadyTracked = @($script:State.Entries | Where-Object { $_.Kind -eq 'FirewallGroup' -and $_.Before.Group -eq $Group }).Count -gt 0
    }

    if (-not $alreadyTracked) {
        Add-HardeningStateEntry -Kind 'FirewallGroup' -ControlId $ControlId -Before @{ Group = $Group }
    }
}

#endregion

#region Execution engine

function Invoke-HardeningControl {
    <#
        .SYNOPSIS
        Audits (and optionally applies) a set of controls, returning one result per control.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '',
        Justification = 'SupportsShouldProcess is declared so that -WhatIf propagates down to the guarded mutators each control calls. This function performs no state change of its own, so it has nothing to gate directly.')]
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Control,
        [switch]$Apply
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $currentCategory = ''

    foreach ($c in $Control) {
        if ($c.Category -ne $currentCategory) {
            $currentCategory = $c.Category
            Write-Host ''
            Write-HardeningLog "$currentCategory" 'Step'
        }

        $verdict = $null
        $controlError = $null

        try {
            $verdict = ConvertTo-ControlVerdict -Raw (& $c.Test $c)
        } catch {
            $controlError = $_.Exception.Message
            $verdict = [pscustomobject]@{ Compliant = $false; Detail = "Test failed: $controlError" }
        }

        $status = if ($verdict.Compliant) { 'Compliant' } else { 'Drift' }
        $changed = $false

        if (-not $verdict.Compliant -and -not $controlError -and $c.AuditOnly) {
            $status = 'Manual'
        } elseif ($Apply -and -not $verdict.Compliant -and -not $controlError) {
            try {
                & $c.Apply $c
                $changed = $true

                if ($WhatIfPreference) {
                    $status = 'WhatIf'
                } else {
                    $recheck = ConvertTo-ControlVerdict -Raw (& $c.Test $c)
                    $status = if ($recheck.Compliant) { 'Remediated' } elseif ($c.RequiresReboot) { 'PendingReboot' } else { 'Failed' }
                    $verdict = $recheck
                }
            } catch {
                $controlError = $_.Exception.Message
                $status = 'Error'
            }
        }

        $style = switch ($status) {
            'Compliant'     { 'Good' }
            'Remediated'    { 'Good' }
            'PendingReboot' { 'Warn' }
            'WhatIf'        { 'Info' }
            'Drift'         { 'Warn' }
            'Manual'        { 'Warn' }
            default         { 'Bad' }
        }

        Write-HardeningLog ("{0,-7} {1,-13} {2}" -f $c.Id, $status, $c.Name) $style
        if ($verdict.Detail) { Write-HardeningLog $verdict.Detail 'Detail' }
        if ($controlError) { Write-HardeningLog "error: $controlError" 'Detail' }

        $results.Add([pscustomobject]@{
                Id             = $c.Id
                Name           = $c.Name
                Category       = $c.Category
                Tier           = $c.Tier
                Counters       = $c.Counters
                Rationale      = $c.Rationale
                Impact         = $c.Impact
                RequiresReboot = $c.RequiresReboot
                AuditOnly      = $c.AuditOnly
                Status         = $status
                Detail         = $verdict.Detail
                Changed        = $changed
                Error          = $controlError
            })
    }

    $results
}

function Get-HardeningSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Result
    )

    $total = @($Result).Count
    $good = @($Result | Where-Object { $_.Status -in @('Compliant', 'Remediated') }).Count
    $score = if ($total -gt 0) { [math]::Round(100 * $good / $total) } else { 0 }

    [pscustomobject]@{
        Total         = $total
        Compliant     = @($Result | Where-Object Status -EQ 'Compliant').Count
        Remediated    = @($Result | Where-Object Status -EQ 'Remediated').Count
        Drift         = @($Result | Where-Object Status -EQ 'Drift').Count
        Manual        = @($Result | Where-Object Status -EQ 'Manual').Count
        PendingReboot = @($Result | Where-Object Status -EQ 'PendingReboot').Count
        Failed        = @($Result | Where-Object { $_.Status -in @('Failed', 'Error') }).Count
        ScorePercent  = $score
        NeedsReboot   = @($Result | Where-Object { $_.RequiresReboot -and $_.Changed }).Count -gt 0
    }
}

#endregion
