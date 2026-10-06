<#
    Controls.Firewall.ps1 - Windows Defender Firewall countermeasures.

    The rule set is declared as data (Get-CountermeasureFirewallRule) so it can be
    reviewed and unit-tested without touching a live firewall. Every rule is created
    under a single rule group, which makes rollback a one-line group removal.
#>

function Get-CountermeasureFirewallRule {
    <#
        .SYNOPSIS
        The declarative firewall rule set, one object per rule.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $rules = @(
        # --- Inbound: SMB / RPC / NetBIOS ------------------------------------
        @{ ControlId = 'FWL-001'; Name = 'Block inbound SMB (TCP 445)'; Direction = 'Inbound'; Protocol = 'TCP'; LocalPort = @('445'); Profile = 'Public,Private'
            Counters = @('impacket psexec/smbexec', 'CrackMapExec', 'ntlmrelayx', 'smbclient') }
        @{ ControlId = 'FWL-001'; Name = 'Block inbound NetBIOS session (TCP 139)'; Direction = 'Inbound'; Protocol = 'TCP'; LocalPort = @('139'); Profile = 'Public,Private'
            Counters = @('enum4linux', 'nbtscan') }
        @{ ControlId = 'FWL-001'; Name = 'Block inbound NetBIOS name/datagram (UDP 137-138)'; Direction = 'Inbound'; Protocol = 'UDP'; LocalPort = @('137', '138'); Profile = 'Public,Private'
            Counters = @('nbtscan', 'Responder') }
        @{ ControlId = 'FWL-001'; Name = 'Block inbound RPC endpoint mapper (TCP 135)'; Direction = 'Inbound'; Protocol = 'TCP'; LocalPort = @('135'); Profile = 'Public,Private'
            Counters = @('impacket wmiexec/dcomexec', 'rpcclient', 'rpcdump') }

        # --- Inbound: remote management --------------------------------------
        @{ ControlId = 'FWL-002'; Name = 'Block inbound RDP (TCP 3389)'; Direction = 'Inbound'; Protocol = 'TCP'; LocalPort = @('3389'); Profile = 'Public,Private'
            Counters = @('hydra rdp', 'crowbar', 'xfreerdp', 'BlueKeep scanners') }
        @{ ControlId = 'FWL-002'; Name = 'Block inbound RDP UDP transport (UDP 3389)'; Direction = 'Inbound'; Protocol = 'UDP'; LocalPort = @('3389'); Profile = 'Public,Private'
            Counters = @('hydra rdp', 'crowbar') }
        @{ ControlId = 'FWL-002'; Name = 'Block inbound WinRM (TCP 5985-5986)'; Direction = 'Inbound'; Protocol = 'TCP'; LocalPort = @('5985', '5986'); Profile = 'Public,Private'
            Counters = @('evil-winrm', 'CrackMapExec winrm', 'Metasploit winrm modules') }

        # --- Inbound/outbound: name-resolution poisoning ----------------------
        @{ ControlId = 'FWL-003'; Name = 'Block inbound LLMNR (UDP 5355)'; Direction = 'Inbound'; Protocol = 'UDP'; LocalPort = @('5355'); Profile = 'Any'
            Counters = @('Responder', 'Inveigh') }
        @{ ControlId = 'FWL-003'; Name = 'Block outbound LLMNR queries (UDP 5355)'; Direction = 'Outbound'; Protocol = 'UDP'; RemotePort = @('5355'); Profile = 'Any'
            Counters = @('Responder', 'Inveigh', 'mitm6') }
        @{ ControlId = 'FWL-003'; Name = 'Block outbound NetBIOS name queries (UDP 137)'; Direction = 'Outbound'; Protocol = 'UDP'; RemotePort = @('137'); Profile = 'Any'
            Counters = @('Responder', 'Inveigh') }
        @{ ControlId = 'FWL-003'; Name = 'Block inbound mDNS (UDP 5353)'; Direction = 'Inbound'; Protocol = 'UDP'; LocalPort = @('5353'); Profile = 'Public,Private'
            Counters = @('Responder -m', 'Bettercap mdns.spoof') }
        @{ ControlId = 'FWL-003'; Name = 'Block inbound SSDP/UPnP discovery (UDP 1900)'; Direction = 'Inbound'; Protocol = 'UDP'; LocalPort = @('1900'); Profile = 'Public,Private'
            Counters = @('nmap --script broadcast-upnp-info', 'evil-ssdp') }
        @{ ControlId = 'FWL-003'; Name = 'Block inbound UPnP host (TCP 2869)'; Direction = 'Inbound'; Protocol = 'TCP'; LocalPort = @('2869'); Profile = 'Public,Private'
            Counters = @('evil-ssdp', 'UPnP enumeration') }
        @{ ControlId = 'FWL-003'; Name = 'Block inbound WSD (TCP 5357-5358)'; Direction = 'Inbound'; Protocol = 'TCP'; LocalPort = @('5357', '5358'); Profile = 'Public,Private'
            Counters = @('nmap service scan', 'WSD device enumeration') }

        # --- Inbound: host discovery -----------------------------------------
        @{ ControlId = 'FWL-004'; Name = 'Block inbound ICMPv4 echo request'; Direction = 'Inbound'; Protocol = 'ICMPv4'; IcmpType = '8'; Profile = 'Public,Private'
            Counters = @('nmap -PE', 'fping', 'netdiscover') }
        @{ ControlId = 'FWL-004'; Name = 'Block inbound ICMPv4 timestamp request'; Direction = 'Inbound'; Protocol = 'ICMPv4'; IcmpType = '13'; Profile = 'Public,Private'
            Counters = @('nmap -PP', 'ICMP OS fingerprinting') }
        @{ ControlId = 'FWL-004'; Name = 'Block inbound ICMPv6 echo request'; Direction = 'Inbound'; Protocol = 'ICMPv6'; IcmpType = '128'; Profile = 'Public,Private'
            Counters = @('nmap -6 -PE', 'atk6-alive6') }

        # --- Inbound: listener blackhole --------------------------------------
        @{ ControlId = 'FWL-005'; Name = 'Block inbound remote shell and DB service ports'; Direction = 'Inbound'; Protocol = 'TCP'
            LocalPort = @('21', '22', '23', '69', '512', '513', '514', '1433', '3306', '5432', '5900', '5901', '6379', '27017'); Profile = 'Any'
            Counters = @('hydra', 'nmap service scan', 'rogue listener planted by a dropper') }

        # --- Outbound: hostile-network SMB egress ------------------------------
        @{ ControlId = 'FWL-006'; Name = 'Block outbound SMB on untrusted networks (TCP 445)'; Direction = 'Outbound'; Protocol = 'TCP'; RemotePort = @('445'); Profile = 'Public'
            Counters = @('ntlmrelayx', 'PetitPotam-style coercion', 'UNC path hash leak') }
        @{ ControlId = 'FWL-006'; Name = 'Block outbound NetBIOS session on untrusted networks (TCP 139)'; Direction = 'Outbound'; Protocol = 'TCP'; RemotePort = @('139'); Profile = 'Public'
            Counters = @('ntlmrelayx', 'UNC path hash leak') }

        # --- Outbound: implant callback ports (aggressive) ---------------------
        @{ ControlId = 'FWL-007'; Name = 'Block outbound implant callback ports'; Direction = 'Outbound'; Protocol = 'TCP'
            RemotePort = @('1337', '1338', '4444', '4445', '5554', '5555', '6666', '6667', '9001', '9002', '31337'); Profile = 'Any'
            Counters = @('msfvenom default LPORT', 'meterpreter reverse_tcp', 'netcat reverse shell') }
        @{ ControlId = 'FWL-007'; Name = 'Block outbound implant callback ports (UDP)'; Direction = 'Outbound'; Protocol = 'UDP'
            RemotePort = @('4444', '5555', '31337'); Profile = 'Any'
            Counters = @('meterpreter reverse_udp', 'UDP beacons') }

        # --- IPv6 takeover (aggressive) ----------------------------------------
        @{ ControlId = 'FWL-009'; Name = 'Block inbound DHCPv6 replies (UDP 546)'; Direction = 'Inbound'; Protocol = 'UDP'; LocalPort = @('546'); Profile = 'Any'
            Counters = @('mitm6', 'DHCPv6 DNS takeover') }
        @{ ControlId = 'FWL-009'; Name = 'Block inbound IPv6 router advertisements'; Direction = 'Inbound'; Protocol = 'ICMPv6'; IcmpType = '134'; Profile = 'Any'
            Counters = @('mitm6', 'atk6-fake_router6', 'SLAAC man-in-the-middle') }

        # --- Inbound: dynamic RPC range on hostile networks (aggressive) -------
        @{ ControlId = 'FWL-008'; Name = 'Block inbound dynamic RPC range on untrusted networks'; Direction = 'Inbound'; Protocol = 'TCP'
            LocalPort = @('49152-65535'); Profile = 'Public'
            Counters = @('impacket wmiexec', 'DCOM lateral movement', 'nmap high-port scan') }
    )

    foreach ($r in $rules) {
        [pscustomobject]@{
            ControlId   = $r.ControlId
            DisplayName = "KCM - $($r.Name)"
            Direction   = $r.Direction
            Action      = 'Block'
            Protocol    = $r.Protocol
            LocalPort   = if ($r.ContainsKey('LocalPort')) { [string[]]$r.LocalPort } else { $null }
            RemotePort  = if ($r.ContainsKey('RemotePort')) { [string[]]$r.RemotePort } else { $null }
            IcmpType    = if ($r.ContainsKey('IcmpType')) { [string]$r.IcmpType } else { $null }
            Profile     = $r.Profile
            Counters    = [string[]]$r.Counters
        }
    }
}

function Test-CountermeasureFirewallRule {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$ControlId
    )

    $specs = @(Get-CountermeasureFirewallRule | Where-Object ControlId -EQ $ControlId)
    $missing = [System.Collections.Generic.List[string]]::new()

    foreach ($spec in $specs) {
        $rule = Get-NetFirewallRule -DisplayName $spec.DisplayName -ErrorAction SilentlyContinue
        if (-not $rule -or $rule.Enabled -ne 'True' -or $rule.Action -ne 'Block') {
            $missing.Add($spec.DisplayName -replace '^KCM - ', '')
        }
    }

    @{
        Compliant = ($missing.Count -eq 0)
        Detail    = if ($missing.Count -eq 0) {
            "$($specs.Count)/$($specs.Count) rules present and enabled."
        } else {
            "$($specs.Count - $missing.Count)/$($specs.Count) rules present. Missing: $($missing -join '; ')"
        }
    }
}

function Install-CountermeasureFirewallRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ControlId
    )

    Register-FirewallGroupForRollback -ControlId $ControlId -Group $script:FirewallGroupName

    foreach ($spec in (Get-CountermeasureFirewallRule | Where-Object ControlId -EQ $ControlId)) {
        if (-not $PSCmdlet.ShouldProcess($spec.DisplayName, 'Create firewall block rule')) { continue }

        Remove-NetFirewallRule -DisplayName $spec.DisplayName -ErrorAction SilentlyContinue

        $params = @{
            DisplayName = $spec.DisplayName
            Group       = $script:FirewallGroupName
            Direction   = $spec.Direction
            Action      = $spec.Action
            Protocol    = $spec.Protocol
            Profile     = $spec.Profile
            Enabled     = 'True'
            Description = "Counters: $($spec.Counters -join ', ')"
            ErrorAction = 'Stop'
        }

        if ($spec.LocalPort) { $params.LocalPort = $spec.LocalPort }
        if ($spec.RemotePort) { $params.RemotePort = $spec.RemotePort }
        if ($spec.IcmpType) { $params.IcmpType = $spec.IcmpType }

        $null = New-NetFirewallRule @params
        Write-HardeningLog "rule: $($spec.DisplayName)" 'Detail'
    }
}

function New-FirewallControl {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Rationale,
        [Parameter(Mandatory)][string]$Impact,
        [string]$Tier = 'Standard'
    )

    $counters = @(Get-CountermeasureFirewallRule | Where-Object ControlId -EQ $Id | ForEach-Object Counters) |
        Sort-Object -Unique

    New-HardeningControl -Id $Id -Name $Name -Category 'Firewall' -Tier $Tier -Rationale $Rationale -Impact $Impact -Counters $counters `
        -Test { param($Control) Test-CountermeasureFirewallRule -ControlId $Control.Id } `
        -Apply { param($Control) Install-CountermeasureFirewallRule -ControlId $Control.Id }
}

function Get-FirewallControl {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    New-FirewallControl -Id 'FWL-001' -Tier 'Baseline' -Name 'Block inbound SMB, RPC and NetBIOS' `
        -Rationale 'TCP 445/139/135 are the primary lateral-movement and enumeration surface that impacket, CrackMapExec and ntlmrelayx target. An explicit block rule wins over any pre-existing allow rule, including the built-in File and Printer Sharing group.' `
        -Impact 'Incoming file/printer sharing and remote WMI stop working on Public and Private networks. Domain profile is left untouched so managed endpoints keep working.'

    New-FirewallControl -Id 'FWL-002' -Tier 'Baseline' -Name 'Block inbound RDP and WinRM' `
        -Rationale 'RDP and WinRM are the two services password-spraying and evil-winrm sessions ride in on. Closing them at the firewall removes the brute-force surface entirely.' `
        -Impact 'You cannot be remoted into over RDP or PowerShell Remoting from Public/Private networks. Outbound RDP to other machines is unaffected.'

    New-FirewallControl -Id 'FWL-003' -Tier 'Baseline' -Name 'Shut down name-resolution poisoning channels' `
        -Rationale 'Responder and Inveigh work by answering LLMNR, NBT-NS and mDNS broadcasts. Blocking the outbound query means the host never asks, so there is nothing to poison and no NetNTLM hash to capture.' `
        -Impact 'Single-label hostnames that only resolved via LLMNR/NetBIOS will fail. Use FQDNs, DNS, or a hosts entry instead.'

    New-FirewallControl -Id 'FWL-004' -Tier 'Standard' -Name 'Silence ICMP host discovery' `
        -Rationale 'nmap -PE, fping and netdiscover rely on ICMP echo replies to build a target list. Dropping echo and timestamp requests removes the host from the fast sweep.' `
        -Impact 'The machine stops replying to ping. Troubleshooting tools that rely on ICMP will report it as down.'

    New-FirewallControl -Id 'FWL-005' -Tier 'Standard' -Name 'Blackhole common service and shell ports' `
        -Rationale 'Catches both nmap service scans and listeners a dropped payload might open (bind shells, rogue SSH/VNC, exposed databases).' `
        -Impact 'If you intentionally run SSH, VNC, MySQL, PostgreSQL, Redis or MongoDB on this host, add an explicit allow rule above this one or exclude FWL-005.'

    New-FirewallControl -Id 'FWL-006' -Tier 'Standard' -Name 'Block SMB egress on untrusted networks' `
        -Rationale 'An attacker on the same coffee-shop LAN only needs you to touch one UNC path or HTML image to collect a NetNTLMv2 hash for relaying. Blocking outbound 445/139 on the Public profile kills the coercion path.' `
        -Impact 'Mapping network drives while connected to a Public-profile network will fail. Private and Domain networks are unaffected.'

    New-FirewallControl -Id 'FWL-007' -Tier 'Aggressive' -Name 'Block implant callback ports' `
        -Rationale 'Defence in depth against unsophisticated payloads: msfvenom, netcat and most tutorial-grade reverse shells ship with these default listener ports and operators rarely change them.' `
        -Impact 'Trivially bypassed by an attacker who picks port 443, so treat this as noise reduction rather than a control you rely on. May block legitimate dev servers on 4444/9001.'

    New-FirewallControl -Id 'FWL-008' -Tier 'Aggressive' -Name 'Block dynamic RPC range on untrusted networks' `
        -Rationale 'Blocking only TCP 135 still leaves the high-port range DCOM negotiates onto. Closing 49152-65535 inbound on Public completes the block against wmiexec and dcomexec.' `
        -Impact 'Any inbound peer-to-peer app negotiating an ephemeral port on a Public network will break.'

    New-FirewallControl -Id 'FWL-009' -Tier 'Aggressive' -Name 'Block IPv6 takeover (mitm6)' `
        -Rationale 'mitm6 wins the race to answer DHCPv6 solicitations, becomes your IPv6 DNS server, and relays the WPAD lookup that follows. Dropping inbound DHCPv6 replies and rogue router advertisements removes both halves of that attack.' `
        -Impact 'Breaks stateful DHCPv6 and SLAAC. Only enable this on IPv4-only networks, or you will lose IPv6 connectivity.'

    New-HardeningControl -Id 'FWL-010' -Name 'All firewall profiles on with default-deny inbound' -Category 'Firewall' -Tier 'Baseline' `
        -Counters @('nmap', 'any direct network attack') `
        -Rationale 'Every other firewall control is meaningless if a profile is switched off. Default-deny inbound means anything not explicitly allowed is dropped rather than refused.' `
        -Impact 'Apps that silently relied on an open inbound port will prompt or fail until you add a rule.' `
        -Test {
        $profiles = Get-NetFirewallProfile -All -ErrorAction Stop
        $bad = @($profiles | Where-Object { -not $_.Enabled -or $_.DefaultInboundAction -ne 'Block' })
        @{
            Compliant = ($bad.Count -eq 0)
            Detail    = if ($bad.Count -eq 0) {
                'Domain, Private and Public profiles are enabled with DefaultInboundAction=Block.'
            } else {
                "Non-compliant profiles: $(($bad | ForEach-Object { "$($_.Name) (Enabled=$($_.Enabled), Inbound=$($_.DefaultInboundAction))" }) -join '; ')"
            }
        }
    } `
        -Apply {
        foreach ($p in (Get-NetFirewallProfile -All)) {
            Add-HardeningStateEntry -Kind 'FirewallProfile' -ControlId 'FWL-010' -Before @{
                Name                 = [string]$p.Name
                Enabled              = [string]$p.Enabled
                DefaultInboundAction = [string]$p.DefaultInboundAction
                NotifyOnListen       = [string]$p.NotifyOnListen
            }
        }
        Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowLocalFirewallRules True
    }

    New-HardeningControl -Id 'FWL-011' -Name 'Firewall drop logging enabled' -Category 'Firewall' -Tier 'Standard' `
        -Counters @('nmap', 'masscan', 'port sweeps') `
        -Rationale 'Dropped-packet logs are what turns a silent block into evidence. The sweep mode reads this log to spot scans in progress.' `
        -Impact 'Writes up to 16 MB per profile under %SystemRoot%\System32\LogFiles\Firewall.' `
        -Test {
        $profiles = Get-NetFirewallProfile -All -ErrorAction Stop
        $bad = @($profiles | Where-Object { $_.LogBlocked -ne 'True' -or $_.LogMaxSizeKilobytes -lt 16384 })
        @{
            Compliant = ($bad.Count -eq 0)
            Detail    = if ($bad.Count -eq 0) { 'Blocked-packet logging on for all profiles (16 MB).' } else { "Logging incomplete on: $(($bad | ForEach-Object Name) -join ', ')" }
        }
    } `
        -Apply {
        foreach ($p in (Get-NetFirewallProfile -All)) {
            Add-HardeningStateEntry -Kind 'FirewallProfile' -ControlId 'FWL-011' -Before @{
                Name                = [string]$p.Name
                LogBlocked          = [string]$p.LogBlocked
                LogMaxSizeKilobytes = [string]$p.LogMaxSizeKilobytes
                LogFileName         = [string]$p.LogFileName
            }
        }
        Set-NetFirewallProfile -All -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 16384 `
            -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log'
    }

    New-HardeningControl -Id 'FWL-012' -Name 'Strip inbound allow rules from the Public profile' -Category 'Firewall' -Tier 'Aggressive' `
        -Counters @('nmap', 'CrackMapExec', 'any inbound exploit') `
        -Rationale 'Third-party installers quietly punch inbound holes scoped to all profiles. On an untrusted network those holes are the attack surface, so every inbound allow rule has the Public profile removed from its scope.' `
        -Impact 'Rules scoped only to Public are disabled outright. Domain and Private scopes are preserved. Fully reversible from the rollback journal.' `
        -Test {
        $leaky = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop |
                Where-Object { $_.Group -ne $script:FirewallGroupName -and ($_.Profile.ToString() -split ',\s*') -contains 'Public' })
        @{
            Compliant = ($leaky.Count -eq 0)
            Detail    = if ($leaky.Count -eq 0) { 'No third-party inbound allow rules apply to the Public profile.' } else { "$($leaky.Count) inbound allow rule(s) still exposed on Public." }
        }
    } `
        -Apply {
        $leaky = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop |
                Where-Object { $_.Group -ne $script:FirewallGroupName -and ($_.Profile.ToString() -split ',\s*') -contains 'Public' })

        foreach ($rule in $leaky) {
            $profiles = @($rule.Profile.ToString() -split ',\s*')
            Add-HardeningStateEntry -Kind 'FirewallRule' -ControlId 'FWL-012' -Before @{
                Name    = [string]$rule.Name
                Profile = [string]$rule.Profile
                Enabled = [string]$rule.Enabled
            }

            $remaining = @($profiles | Where-Object { $_ -ne 'Public' -and $_ -ne 'Any' })
            if ($remaining.Count -gt 0) {
                Set-NetFirewallRule -Name $rule.Name -Profile ($remaining -join ',') -ErrorAction SilentlyContinue
            } else {
                Set-NetFirewallRule -Name $rule.Name -Enabled False -ErrorAction SilentlyContinue
            }
        }
        Write-HardeningLog "Re-scoped $($leaky.Count) inbound allow rule(s) away from the Public profile." 'Detail'
    }
}
