<#
    Controls.Credentials.ps1 - Credential-theft and enumeration countermeasures.

    Covers what an operator does after landing on the box (dump LSASS, read cached
    secrets, pass the hash) and what they do before landing on it (null-session and
    SAMR enumeration to build a user list for spraying).
#>

function Get-CredentialControl {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    New-RegistryControl -Id 'CRD-001' -Name 'WDigest plaintext credential caching disabled' -Category 'Credentials' -Tier 'Baseline' `
        -Counters @('mimikatz sekurlsa::wdigest', 'LaZagne', 'pypykatz') `
        -Rationale 'With UseLogonCredential set, LSASS keeps a reversible copy of the password in memory and mimikatz recovers it as cleartext rather than a hash. Attack tooling frequently sets this value to 1 and waits for a re-logon, so pinning it to 0 is both a hardening step and a tamper tripwire.' `
        -Impact 'None on modern Windows. WDigest has not been needed since Server 2008 R2.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name = 'UseLogonCredential'; Value = 0; Label = 'WDigest cleartext caching' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name = 'Negotiate'; Value = 0; Label = 'WDigest negotiate' }
    )

    New-RegistryControl -Id 'CRD-002' -Name 'LSA Protection (RunAsPPL) enabled' -Category 'Credentials' -Tier 'Baseline' `
        -Counters @('mimikatz sekurlsa::logonpasswords', 'procdump -ma lsass.exe', 'comsvcs.dll MiniDump', 'nanodump') `
        -Rationale 'Running LSASS as a protected process means a handle opened by an administrator-level tool cannot read its memory. This is the control that makes the standard mimikatz and procdump LSASS dump fail outright and forces an attacker into a driver-based bypass that EDR will see.' `
        -Impact 'Unsigned LSA plugins and some smartcard or password-filter DLLs will stop loading. Takes effect after reboot.' `
        -RequiresReboot `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RunAsPPL'; Value = 1; Label = 'LSA Protection' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RunAsPPLBoot'; Value = 1; Label = 'LSA Protection at boot' }
    )

    New-RegistryControl -Id 'CRD-004' -Name 'Anonymous (null session) enumeration refused' -Category 'Credentials' -Tier 'Baseline' `
        -Counters @('enum4linux', 'rpcclient -U ""', 'smbclient -N -L', 'nmap smb-enum-*') `
        -Rationale 'A null session is the first thing enum4linux tries: no credentials, yet it can return share names, the user list, the password policy and the domain SID. Those three registry values close anonymous access to all of it.' `
        -Impact 'Legacy applications that browse shares anonymously will break. Normal authenticated access is unchanged.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; Value = 1; Label = 'RestrictAnonymous' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymousSAM'; Value = 1; Label = 'RestrictAnonymousSAM' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'EveryoneIncludesAnonymous'; Value = 0; Label = 'EveryoneIncludesAnonymous' }
    )

    New-RegistryControl -Id 'CRD-005' -Name 'Remote SAM enumeration limited to administrators' -Category 'Credentials' -Tier 'Baseline' `
        -Counters @('CrackMapExec --users', 'SharpHound', 'lsarelayx', 'samrdump') `
        -Rationale 'Even with null sessions blocked, any authenticated low-privilege account can still read the SAM remotely and harvest a user list for password spraying. The RestrictRemoteSAM descriptor limits that call to the local Administrators group.' `
        -Impact 'Inventory and asset-management tools running as a non-admin service account may lose the ability to enumerate local users.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictRemoteSAM'; Value = 'O:BAG:BAD:(A;;RC;;;BA)'; Type = 'String'; Label = 'RestrictRemoteSAM SDDL' }
    )

    New-RegistryControl -Id 'CRD-006' -Name 'Local accounts blocked from network logon' -Category 'Credentials' -Tier 'Baseline' `
        -Counters @('pass-the-hash', 'impacket psexec', 'CrackMapExec --local-auth', 'smbexec') `
        -Rationale 'Pass-the-hash against a local administrator account is only useful if that account gets a full elevated token over the network. FilterAdministratorToken closes the built-in RID-500 path and LocalAccountTokenFilterPolicy=0 keeps the default UAC remote restrictions for every other local admin. A shared local admin password across machines becomes far less useful.' `
        -Impact 'Remote administration using a local account requires using the real built-in Administrator with UAC remote restrictions, or a domain account.' `
        -Setting @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'LocalAccountTokenFilterPolicy'; Value = 0; Label = 'LocalAccountTokenFilterPolicy' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'FilterAdministratorToken'; Value = 1; Label = 'FilterAdministratorToken' }
    )

    New-RegistryControl -Id 'CRD-007' -Name 'Blank passwords refused for network logon' -Category 'Credentials' -Tier 'Baseline' `
        -Counters @('CrackMapExec blank-password spray', 'hydra') `
        -Rationale 'Accounts with empty passwords should only ever be usable at the console, never across the network.' `
        -Impact 'None in practice.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LimitBlankPasswordUse'; Value = 1; Label = 'LimitBlankPasswordUse' }
    )

    New-RegistryControl -Id 'CRD-008' -Name 'Cached domain credentials limited' -Category 'Credentials' -Tier 'Standard' `
        -Counters @('mimikatz lsadump::cache', 'hashcat -m 2100 (DCC2)', 'secretsdump') `
        -Rationale 'Every cached domain logon is an MSCACHEv2 hash sitting in the registry waiting to be dumped and cracked offline. Reducing the cache to a single entry minimises what a successful SYSTEM-level dump is worth.' `
        -Impact 'Only the most recent domain user can log on while disconnected from the corporate network. Irrelevant on non-domain machines.' `
        -Setting @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'CachedLogonsCount'; Value = '1'; Type = 'String'; Label = 'CachedLogonsCount' }
    )

    New-RegistryControl -Id 'CRD-009' -Name 'UAC enforced with secure desktop prompts' -Category 'Credentials' -Tier 'Standard' `
        -Counters @('UACMe', 'fodhelper bypass', 'Metasploit bypassuac modules') `
        -Rationale 'Most UAC bypasses require auto-elevation to be permitted. Disabling EnableInstallerDetection-era shortcuts, forcing consent on the secure desktop, and requiring signed elevated binaries removes the easy paths the public bypass catalogue relies on.' `
        -Impact 'More elevation prompts, and they render on the secure desktop so remote-control tools may not display them.' `
        -Setting @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableLUA'; Value = 1; Label = 'UAC enabled' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ConsentPromptBehaviorAdmin'; Value = 2; Label = 'Admin consent prompt' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ConsentPromptBehaviorUser'; Value = 0; Label = 'Standard user elevation' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'PromptOnSecureDesktop'; Value = 1; Label = 'Secure desktop' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableInstallerDetection'; Value = 1; Label = 'Installer detection' }
    )

    New-RegistryControl -Id 'CRD-010' -Name 'Saved network credentials disabled' -Category 'Credentials' -Tier 'Aggressive' `
        -Counters @('mimikatz vault::cred', 'LaZagne', 'SharpDPAPI') `
        -Rationale 'Credential Manager is a convenient single stop for an attacker who already has your user token. DisableDomainCreds stops Windows storing network credentials there at all.' `
        -Impact 'Significant day-to-day friction: saved RDP, network share and some application credentials stop being remembered.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'DisableDomainCreds'; Value = 1; Label = 'DisableDomainCreds' }
    )

    New-HardeningControl -Id 'CRD-003' -Name 'Credential Guard and VBS enabled' -Category 'Credentials' -Tier 'Standard' `
        -Counters @('mimikatz sekurlsa::logonpasswords', 'pass-the-hash', 'pass-the-ticket', 'Rubeus') `
        -Rationale 'Credential Guard moves NTLM hashes and Kerberos tickets into a VBS-isolated process that the normal kernel cannot read. Even SYSTEM with a dumped LSASS gets nothing replayable, which defeats pass-the-hash and pass-the-ticket rather than merely making them harder.' `
        -Impact 'Requires virtualisation support and Secure Boot, blocks some third-party hypervisors and older VPN clients, and only takes effect after a reboot.' `
        -RequiresReboot `
        -Test {
        $dgPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        $vbs = Get-RegistryValueOrNull -Path $dgPath -Name 'EnableVirtualizationBasedSecurity'
        $cg = Get-RegistryValueOrNull -Path "$dgPath\Scenarios\CredentialGuard" -Name 'Enabled'

        $running = 'unknown'
        try {
            $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
            $running = if (1 -in @($dg.SecurityServicesRunning)) { 'running' } else { 'configured but not running' }
        } catch {
            Write-Verbose "DeviceGuard WMI namespace unavailable: $($_.Exception.Message)"
        }

        @{
            Compliant = ($vbs -eq 1 -and $cg -eq 1)
            Detail    = "VBS=$vbs, CredentialGuard=$cg, runtime state: $running."
        }
    } `
        -Apply {
        $dgPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        Set-GuardedRegistryValue -Path $dgPath -Name 'EnableVirtualizationBasedSecurity' -Value 1 -ControlId 'CRD-003'
        # 1 = Secure Boot only. Use 3 only where DMA protection is guaranteed, or VBS will refuse to start.
        Set-GuardedRegistryValue -Path $dgPath -Name 'RequirePlatformSecurityFeatures' -Value 1 -ControlId 'CRD-003'
        Set-GuardedRegistryValue -Path "$dgPath\Scenarios\CredentialGuard" -Name 'Enabled' -Value 1 -ControlId 'CRD-003'
        Set-GuardedRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags' -Value 1 -ControlId 'CRD-003'
    }

    New-HardeningControl -Id 'CRD-011' -Name 'Guest account disabled' -Category 'Credentials' -Tier 'Baseline' `
        -Counters @('smbclient -N', 'anonymous share access', 'enum4linux') `
        -Rationale 'An enabled Guest account turns every "access denied" into "access granted, read-only" and gives an attacker an authenticated foothold for enumeration.' `
        -Impact 'None. Guest is disabled by default on Windows 11; this control catches hosts where it was turned on.' `
        -Test {
        $guest = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like 'S-1-5-21-*-501' }
        if (-not $guest) { return @{ Compliant = $true; Detail = 'No Guest account present.' } }
        @{
            Compliant = (-not $guest.Enabled)
            Detail    = "Account '$($guest.Name)' (RID 501) enabled=$($guest.Enabled)."
        }
    } `
        -Apply {
        $guest = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like 'S-1-5-21-*-501' }
        if ($guest -and $guest.Enabled) {
            Add-HardeningStateEntry -Kind 'Note' -ControlId 'CRD-011' -Before @{
                Description = 'Guest account was enabled before hardening.'
                AccountName = $guest.Name
                Enabled     = $true
            }
            Disable-LocalUser -SID $guest.SID
        }
    }

    New-HardeningControl -Id 'CRD-012' -Name 'Account lockout policy blunts password spraying' -Category 'Credentials' -Tier 'Baseline' `
        -Counters @('hydra', 'CrackMapExec password spray', 'kerbrute', 'medusa') `
        -Rationale 'Online guessing is only viable with unlimited attempts. A lockout threshold with a long observation window turns a spray that would take minutes into one that locks accounts and generates alerts instead.' `
        -Impact 'Users who fat-finger their password 10 times in 15 minutes get locked out for 15 minutes. An attacker can also use this to deny service deliberately.' `
        -Test {
        $policy = Get-LocalPasswordPolicySnapshot
        $ok = ($policy.LockoutBadCount -gt 0 -and $policy.LockoutBadCount -le 10 -and $policy.LockoutDuration -ge 15)
        @{
            Compliant = $ok
            Detail    = "Threshold=$($policy.LockoutBadCount) attempts, duration=$($policy.LockoutDuration) min, window=$($policy.ResetLockoutCount) min."
        }
    } `
        -Apply {
        $policy = Get-LocalPasswordPolicySnapshot
        Add-HardeningStateEntry -Kind 'Note' -ControlId 'CRD-012' -Before @{
            Description       = 'Local account lockout policy before hardening.'
            LockoutBadCount   = $policy.LockoutBadCount
            LockoutDuration   = $policy.LockoutDuration
            ResetLockoutCount = $policy.ResetLockoutCount
        }

        if (Test-ShouldApply -Target 'Local account policy' -Action 'Set lockout threshold 10 / duration 15 / window 15') {
            # net.exe is used deliberately: it is locale-independent at the parameter level,
            # unlike parsing the localised text output of "net accounts".
            $null = & net.exe accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15 2>&1
        }
    }

    New-HardeningControl -Id 'CRD-013' -Name 'No plaintext autologon password in the registry' -Category 'Credentials' -Tier 'Standard' `
        -Counters @('mimikatz lsadump::secrets', 'LaZagne', 'reg query Winlogon') `
        -Rationale 'AutoAdminLogon stores DefaultPassword as cleartext in a registry key any local user can read. It is one of the first places post-exploitation tooling looks.' `
        -Impact 'Unattended logon at boot stops working if it was configured this way.' `
        -Test {
        $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $auto = Get-RegistryValueOrNull -Path $winlogon -Name 'AutoAdminLogon'
        $storedPassword = Get-RegistryValueOrNull -Path $winlogon -Name 'DefaultPassword'
        @{
            Compliant = (($auto -ne '1' -and $auto -ne 1) -and [string]::IsNullOrEmpty($storedPassword))
            Detail    = "AutoAdminLogon=$auto, DefaultPassword present=$(-not [string]::IsNullOrEmpty($storedPassword))."
        }
    } `
        -Apply {
        $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Set-GuardedRegistryValue -Path $winlogon -Name 'AutoAdminLogon' -Value '0' -Type String -ControlId 'CRD-013'

        if ($null -ne (Get-RegistryValueOrNull -Path $winlogon -Name 'DefaultPassword')) {
            if (Test-ShouldApply -Target "$winlogon\DefaultPassword" -Action 'Remove cleartext autologon password') {
                Add-HardeningStateEntry -Kind 'Note' -ControlId 'CRD-013' -Before @{
                    Description = 'A cleartext DefaultPassword value was removed. Its value is deliberately not recorded in this journal.'
                    Path        = $winlogon
                    Name        = 'DefaultPassword'
                }
                Remove-RegistryValue -Path $winlogon -Name 'DefaultPassword'
            }
        }
    }
}

function Get-LocalPasswordPolicySnapshot {
    <#
        .SYNOPSIS
        Reads the effective local account policy via secedit, avoiding localised text parsing.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("secpol-{0}.inf" -f [guid]::NewGuid())
    try {
        $null = & secedit.exe /export /cfg $tmp /quiet 2>&1
        $raw = if (Test-Path -LiteralPath $tmp) { Get-Content -LiteralPath $tmp -ErrorAction Stop } else { @() }
        ConvertFrom-SeceditPolicy -Line $raw
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function ConvertFrom-SeceditPolicy {
    <#
        .SYNOPSIS
        Pure parser for the [System Access] section of a secedit export.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Line
    )

    $values = @{}
    foreach ($l in $Line) {
        if ($l -match '^\s*([A-Za-z]\w*)\s*=\s*(.+?)\s*$') {
            $values[$Matches[1]] = $Matches[2]
        }
    }

    function ConvertTo-PolicyInt([string]$Text) {
        $parsed = 0
        if ([int]::TryParse($Text, [ref]$parsed)) { return $parsed }
        return -1
    }

    [pscustomobject]@{
        LockoutBadCount   = ConvertTo-PolicyInt ([string]$values['LockoutBadCount'])
        LockoutDuration   = ConvertTo-PolicyInt ([string]$values['LockoutDuration'])
        ResetLockoutCount = ConvertTo-PolicyInt ([string]$values['ResetLockoutCount'])
        MinimumPasswordLength = ConvertTo-PolicyInt ([string]$values['MinimumPasswordLength'])
    }
}
