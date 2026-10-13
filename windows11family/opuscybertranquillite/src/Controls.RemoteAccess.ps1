<#
    Controls.RemoteAccess.ps1 - Remote execution and remote administration surface.

    The firewall pack blocks these services at the network edge; this pack switches
    them off at the host so a firewall change, a VPN adapter on a different profile,
    or an attacker already on the box cannot bring them back.
#>

function Get-RemoteAccessControl {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    New-ServiceControl -Id 'RMT-001' -Name 'Remote Registry service disabled' -ServiceName 'RemoteRegistry' -Category 'RemoteAccess' -Tier 'Baseline' `
        -Counters @('impacket reg.py', 'CrackMapExec', 'remote hive dump', 'nmap smb-enum scripts') `
        -Rationale 'Remote Registry lets an authenticated attacker read the SAM and SECURITY hives, harvest autorun keys and plant persistence without ever dropping a file. Almost nothing on a workstation needs it.' `
        -Impact 'Remote registry editing and a few inventory/monitoring agents stop working.'

    New-ServiceControl -Id 'RMT-002' -Name 'WinRM service disabled' -ServiceName 'WinRM' -Category 'RemoteAccess' -Tier 'Standard' `
        -Counters @('evil-winrm', 'CrackMapExec winrm', 'Enter-PSSession lateral movement') `
        -Rationale 'evil-winrm gives a full interactive shell with nothing but valid credentials or a hash, and it leaves far less forensic trace than PsExec. If you do not administer this machine over PowerShell Remoting, the listener should not exist.' `
        -Impact 'PowerShell Remoting into this machine stops. Outbound Enter-PSSession to other hosts still works.'

    New-ServiceControl -Id 'RMT-003' -Name 'Remote Desktop Services disabled' -ServiceName 'TermService' -Category 'RemoteAccess' -Tier 'Aggressive' `
        -Counters @('hydra rdp', 'crowbar', 'BlueKeep', 'RDP session hijacking') `
        -Rationale 'Removes the RDP listener entirely rather than relying on the firewall rule alone.' `
        -Impact 'You cannot RDP into this machine at all, including over a VPN. Skip this control if you rely on remote desktop.'

    New-RegistryControl -Id 'RMT-004' -Name 'Incoming Remote Desktop connections refused' -Category 'RemoteAccess' -Tier 'Standard' `
        -Counters @('hydra rdp', 'crowbar', 'rdp_scanner') `
        -Rationale 'The policy-level switch that tells Terminal Services to deny connections. Belt-and-braces with the firewall rule and the service control, and it survives a firewall reset.' `
        -Impact 'Incoming RDP is refused. Remove this control if you need remote desktop access.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'; Name = 'fDenyTSConnections'; Value = 1; Label = 'Deny RDP connections' }
    )

    New-RegistryControl -Id 'RMT-005' -Name 'RDP requires Network Level Authentication and TLS' -Category 'RemoteAccess' -Tier 'Baseline' `
        -Counters @('BlueKeep', 'pre-auth RDP exploits', 'rdesktop MITM', 'Seth RDP downgrade') `
        -Rationale 'NLA forces authentication before a session is created, which removes the pre-authentication attack surface that CVE-2019-0708 class bugs live in. SecurityLayer 2 forces TLS so a Seth-style downgrade cannot strip the channel. This matters even when RDP is disabled, because it is the state RDP returns to if someone re-enables it.' `
        -Impact 'Very old RDP clients that do not support CredSSP can no longer connect.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name = 'UserAuthentication'; Value = 1; Label = 'NLA required' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name = 'SecurityLayer'; Value = 2; Label = 'TLS security layer' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name = 'MinEncryptionLevel'; Value = 3; Label = 'High encryption' }
    )

    New-RegistryControl -Id 'RMT-006' -Name 'Administrative shares removed' -Category 'RemoteAccess' -Tier 'Standard' `
        -Counters @('PsExec', 'impacket psexec/smbexec', 'CrackMapExec', 'SMB payload drop') `
        -Rationale 'PsExec and every impacket clone write their service binary to ADMIN$ and then start it over the service control manager. Without the hidden admin shares that upload step fails, which breaks the single most common lateral-movement technique.' `
        -Impact 'Remote administration tools and backup software that rely on \\host\C$ will stop working. Takes effect on the next restart of the Server service.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AutoShareWks'; Value = 0; Label = 'Workstation admin shares' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AutoShareServer'; Value = 0; Label = 'Server admin shares' }
    )

    New-RegistryControl -Id 'RMT-007' -Name 'Anonymous access to named pipes and shares removed' -Category 'RemoteAccess' -Tier 'Baseline' `
        -Counters @('enum4linux', 'rpcclient', 'smbclient -N', 'IPC$ null session') `
        -Rationale 'Even with RestrictAnonymous set, any pipe left in NullSessionPipes stays reachable without credentials. Emptying both lists removes the last unauthenticated RPC entry points.' `
        -Impact 'Legacy applications depending on anonymous pipe access (very rare on a workstation) will break.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'NullSessionPipes'; Value = @(); Type = 'MultiString'; Label = 'NullSessionPipes' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'NullSessionShares'; Value = @(); Type = 'MultiString'; Label = 'NullSessionShares' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'RestrictNullSessAccess'; Value = 1; Label = 'RestrictNullSessAccess' }
    )

    New-RegistryControl -Id 'RMT-008' -Name 'Remote Assistance disabled' -Category 'RemoteAccess' -Tier 'Standard' `
        -Counters @('Remote Assistance abuse', 'social-engineered remote control') `
        -Rationale 'Remote Assistance is a second, less-watched remote control channel that also enables unsolicited offers of help when policy allows it.' `
        -Impact 'The "Invite someone to help you" workflow stops working.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'; Name = 'fAllowToGetHelp'; Value = 0; Label = 'Solicited Remote Assistance' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'; Name = 'fAllowFullControl'; Value = 0; Label = 'Remote Assistance full control' }
    )

    New-HardeningControl -Id 'RMT-009' -Name 'No WinRM listeners configured' -Category 'RemoteAccess' -Tier 'Standard' `
        -Counters @('evil-winrm', 'CrackMapExec winrm') `
        -Rationale 'Disabling the service is not quite enough: a configured listener and its firewall exception come straight back the moment anything starts WinRM. Removing the listeners makes re-enabling the service insufficient on its own.' `
        -Impact 'PowerShell Remoting must be reconfigured with Enable-PSRemoting if you need it later.' `
        -Test {
        $svc = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.Status -ne 'Running') {
            return @{ Compliant = $true; Detail = 'WinRM is not running, so no listener is active.' }
        }

        $listeners = @(Get-ChildItem -Path 'WSMan:\localhost\Listener' -ErrorAction SilentlyContinue)
        @{
            Compliant = ($listeners.Count -eq 0)
            Detail    = "$($listeners.Count) WinRM listener(s) configured."
        }
    } `
        -Apply {
        $listeners = @(Get-ChildItem -Path 'WSMan:\localhost\Listener' -ErrorAction SilentlyContinue)
        foreach ($l in $listeners) {
            if (-not (Test-ShouldApply -Target $l.Name -Action 'Remove WinRM listener')) { continue }
            Add-HardeningStateEntry -Kind 'Note' -ControlId 'RMT-009' -Before @{
                Description = 'WinRM listener removed. Re-create with Enable-PSRemoting if needed.'
                Listener    = [string]$l.Name
            }
            Remove-Item -Path $l.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
