@{
    Severity     = @('Error', 'Warning')

    ExcludeRules = @(
        # This is an operator-facing console tool. Coloured status output is the primary
        # interface, not incidental logging, so Write-Host is the correct cmdlet here.
        'PSAvoidUsingWriteHost'

        # Control packs intentionally expose plural-sounding collections of settings and
        # rules (Get-FirewallControl, Get-AsrRuleDefinition) returning many objects.
        'PSUseSingularNouns'

        # The toolkit targets Windows PowerShell 5.1 and PowerShell 7 on Windows only;
        # cross-edition compatibility warnings for Windows-specific cmdlets are expected.
        'PSUseCompatibleCmdlets'

        # Every New-* function in this repository is a constructor that builds an in-memory
        # object (a control definition, a firewall rule spec, a sweep finding). None of them
        # touch the system, so ShouldProcess would be meaningless on them. The functions that
        # do change state are the Set-Guarded* helpers, and those implement it properly.
        'PSUseShouldProcessForStateChangingFunctions'

        # The control packs are written as aligned data tables where a trailing property sits
        # on a continuation line. That reads far better than one property per line for ~60
        # rule definitions, and this rule objects to it.
        'PSPlaceCloseBrace'
    )

    Rules        = @{
        PSPlaceOpenBrace           = @{ Enable = $true; OnSameLine = $true; NewLineAfter = $true }
        PSUseConsistentIndentation = @{ Enable = $true; Kind = 'space'; IndentationSize = 4 }
    }
}
