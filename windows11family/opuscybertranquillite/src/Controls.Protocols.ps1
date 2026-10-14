<#
    Controls.Protocols.ps1 - Protocol-level countermeasures.

    Targets the broadcast name-resolution protocols that Responder/Inveigh poison,
    the legacy SMB and NTLM dialects that relay and cracking attacks depend on, and
    the WPAD/IPv6 paths used for transparent proxy and DNS takeover.
#>

function Get-ProtocolControl {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    New-RegistryControl -Id 'PRT-001' -Name 'LLMNR disabled' -Category 'Protocols' -Tier 'Baseline' `
        -Counters @('Responder', 'Inveigh', 'NetNTLMv2 capture') `
        -Rationale 'LLMNR broadcasts any failed DNS lookup to the whole subnet and trusts the first answer. Responder answers every one of them and collects the NetNTLMv2 hash your machine offers. There is no safe way to use LLMNR on an untrusted network.' `
        -Impact 'Single-label names that only resolved by multicast stop resolving. Use DNS, an FQDN, or a hosts file entry.' `
        -Setting @(
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name = 'EnableMulticast'; Value = 0; Label = 'LLMNR (EnableMulticast)' }
    )

    New-RegistryControl -Id 'PRT-003' -Name 'mDNS disabled' -Category 'Protocols' -Tier 'Standard' `
        -Counters @('Responder -m', 'bettercap mdns.spoof') `
        -Rationale 'mDNS is the third broadcast resolver Responder poisons, and it stays exploitable after LLMNR and NetBIOS are switched off.' `
        -Impact 'Breaks .local discovery for some printers, Chromecast and AirPrint devices.' `
        -RequiresReboot `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'; Name = 'EnableMDNS'; Value = 0; Label = 'mDNS (EnableMDNS)' }
    )

    New-RegistryControl -Id 'PRT-005' -Name 'SMBv1 server dialect disabled' -Category 'Protocols' -Tier 'Baseline' `
        -Counters @('EternalBlue / MS17-010', 'nmap smb-vuln scripts', 'Metasploit ms17_010_eternalblue') `
        -Rationale 'SMBv1 has no signing worth the name and carries the MS17-010 family of remote code execution bugs that are still the first thing a Kali operator tries against a Windows host.' `
        -Impact 'Devices that only speak SMBv1 (pre-2008 NAS appliances, some scanners) become unreachable.' `
        -RequiresReboot `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'SMB1'; Value = 0; Label = 'SMBv1 server' }
    )

    New-RegistryControl -Id 'PRT-006' -Name 'SMB signing required (client and server)' -Category 'Protocols' -Tier 'Baseline' `
        -Counters @('ntlmrelayx', 'CrackMapExec smb signing:False', 'SMB relay') `
        -Rationale 'SMB relay works because an unsigned session can be replayed to a third host. Requiring signing on both sides is the single control that makes ntlmrelayx fail outright - it is also the check CrackMapExec prints first when it fingerprints a target.' `
        -Impact 'Small CPU cost per SMB operation. Legacy devices that cannot sign will fail to connect.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'RequireSecuritySignature'; Value = 1; Label = 'Server signing required' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'EnableSecuritySignature'; Value = 1; Label = 'Server signing enabled' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name = 'RequireSecuritySignature'; Value = 1; Label = 'Client signing required' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name = 'EnableSecuritySignature'; Value = 1; Label = 'Client signing enabled' }
    )

    New-RegistryControl -Id 'PRT-007' -Name 'Insecure SMB guest authentication refused' -Category 'Protocols' -Tier 'Baseline' `
        -Counters @('impacket smbserver', 'rogue SMB share', 'Responder SMB server') `
        -Rationale 'Guest fallback lets the client authenticate to an attacker-run share with no credentials and no signing, which is how a rogue SMB server gets a foothold for payload delivery.' `
        -Impact 'Anonymous access to NAS devices configured for guest shares will stop working.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name = 'AllowInsecureGuestAuth'; Value = 0; Label = 'Insecure guest auth' }
    )

    New-RegistryControl -Id 'PRT-008' -Name 'NTLMv2 only - LM and NTLMv1 refused' -Category 'Protocols' -Tier 'Baseline' `
        -Counters @('Responder --lm', 'hashcat NetNTLMv1', 'crack.sh') `
        -Rationale 'NetNTLMv1 and LM responses are effectively plaintext: they reduce to DES keys that can be cracked in hours. LmCompatibilityLevel 5 sends and accepts NTLMv2 only, so a downgrade attempt by a rogue server gets nothing usable.' `
        -Impact 'Windows NT/2000-era hosts and some embedded devices can no longer authenticate to or from this machine.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LmCompatibilityLevel'; Value = 5; Label = 'LmCompatibilityLevel' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'NoLMHash'; Value = 1; Label = 'LM hash storage disabled' }
    )

    New-RegistryControl -Id 'PRT-009' -Name 'NTLM session security requires 128-bit and NTLMv2' -Category 'Protocols' -Tier 'Standard' `
        -Counters @('NTLM downgrade', 'ntlmrelayx') `
        -Rationale 'Setting LmCompatibilityLevel alone still permits weak session security on the NTLM channel itself. NtlmMinClientSec/NtlmMinServerSec force NTLMv2 session security with 128-bit encryption on both sides.' `
        -Impact 'Legacy applications negotiating weak NTLM session security will fail to connect.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'NtlmMinClientSec'; Value = 537395200; Label = 'NtlmMinClientSec (0x20080000)' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'NtlmMinServerSec'; Value = 537395200; Label = 'NtlmMinServerSec (0x20080000)' }
    )

    New-RegistryControl -Id 'PRT-010' -Name 'Outbound NTLM to remote servers denied' -Category 'Protocols' -Tier 'Aggressive' `
        -Counters @('Responder', 'ntlmrelayx', 'UNC path hash leak') `
        -Rationale 'The strongest available answer to hash capture: even if something tricks the machine into contacting an attacker host, LSA refuses to send an NTLM response at all.' `
        -Impact 'Significant. Any remote resource that authenticates with NTLM instead of Kerberos will break, including many NAS devices and non-domain file shares. Audit with RestrictSendingNTLMTraffic=1 before committing to 2.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'RestrictSendingNTLMTraffic'; Value = 2; Label = 'RestrictSendingNTLMTraffic' }
    )

    New-HardeningControl -Id 'PRT-002' -Name 'NetBIOS over TCP/IP disabled on every adapter' -Category 'Protocols' -Tier 'Baseline' `
        -Counters @('Responder', 'nbtscan', 'enum4linux', 'NBT-NS poisoning') `
        -Rationale 'NBT-NS is the oldest and loudest of the broadcast resolvers. It is configured per adapter, so a single new VPN or Wi-Fi adapter silently reintroduces the exposure - this control walks every interface and sets NetbiosOptions to 2 (disabled).' `
        -Impact 'Pre-Windows 2000 name resolution stops. Modern file sharing over SMB on port 445 is unaffected.' `
        -RequiresReboot `
        -Test {
        $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        if (-not (Test-Path -LiteralPath $root)) { return @{ Compliant = $false; Detail = 'NetBT interface key not found.' } }

        $ifaces = @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)
        $enabled = @($ifaces | Where-Object { (Get-RegistryValueOrNull -Path $_.PSPath -Name 'NetbiosOptions') -ne 2 })

        @{
            Compliant = ($enabled.Count -eq 0)
            Detail    = "$($ifaces.Count - $enabled.Count)/$($ifaces.Count) adapters have NetBIOS over TCP/IP disabled."
        }
    } `
        -Apply {
        $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        foreach ($iface in (Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
            Set-GuardedRegistryValue -Path $iface.PSPath -Name 'NetbiosOptions' -Value 2 -Type DWord -ControlId 'PRT-002'
        }
        # P-node: never fall back to broadcast name resolution for new adapters.
        Set-GuardedRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NodeType' -Value 2 -Type DWord -ControlId 'PRT-002'
    }

    New-HardeningControl -Id 'PRT-004' -Name 'WPAD disabled and sinkholed' -Category 'Protocols' -Tier 'Baseline' `
        -Counters @('Responder WPAD', 'mitm6', 'Inveigh', 'proxy injection') `
        -Rationale 'WPAD makes the machine ask the network "who is my proxy?" and then send credentials to whoever answers. Three layers are needed: stop the auto-discovery service, set the WpadOverride policy, and sinkhole the wpad and isatap names in the hosts file so a poisoned answer resolves nowhere.' `
        -Impact 'Networks that genuinely distribute proxy settings via WPAD will need the proxy configured manually.' `
        -Test {
        $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        $override = Get-RegistryValueOrNull -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -Name 'WpadOverride'
        $svc = Get-Service -Name 'WinHttpAutoProxySvc' -ErrorAction SilentlyContinue
        $svcDisabled = $true
        if ($svc) {
            $wmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='WinHttpAutoProxySvc'" -ErrorAction SilentlyContinue
            $svcDisabled = ($wmi -and $wmi.StartMode -eq 'Disabled')
        }

        $sinkholed = $false
        if (Test-Path -LiteralPath $hostsPath) {
            $content = Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue
            $sinkholed = @($content | Where-Object { $_ -match '^\s*0\.0\.0\.0\s+wpad\b' }).Count -gt 0
        }

        @{
            Compliant = ($override -eq 1 -and $svcDisabled -and $sinkholed)
            Detail    = "WpadOverride=$override; auto-proxy service disabled=$svcDisabled; hosts sinkhole=$sinkholed."
        }
    } `
        -Apply {
        Set-GuardedRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -Name 'WpadOverride' -Value 1 -Type DWord -ControlId 'PRT-004'
        Set-GuardedServiceState -Name 'WinHttpAutoProxySvc' -StartupType Disabled -ControlId 'PRT-004' -StopService

        $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        $existing = if (Test-Path -LiteralPath $hostsPath) { @(Get-Content -LiteralPath $hostsPath) } else { @() }

        $wanted = @('wpad', 'wpad.localdomain', 'isatap', 'isatap.localdomain')
        $toAdd = @($wanted | Where-Object { $name = $_; -not ($existing | Where-Object { $_ -match "^\s*0\.0\.0\.0\s+$([regex]::Escape($name))\s*$" }) })

        if ($toAdd.Count -gt 0 -and (Test-ShouldApply -Target $hostsPath -Action "Sinkhole $($toAdd -join ', ')")) {
            Add-HardeningStateEntry -Kind 'Note' -ControlId 'PRT-004' -Before @{
                Description = 'Appended WPAD/ISATAP sinkhole entries to the hosts file.'
                HostsPath   = $hostsPath
                AddedNames  = $toAdd
            }

            $block = @('', '# Added by Invoke-KaliCountermeasures (PRT-004): sinkhole WPAD/ISATAP poisoning') +
            ($toAdd | ForEach-Object { "0.0.0.0`t$_" })
            Add-Content -LiteralPath $hostsPath -Value $block -Encoding ASCII
            Write-HardeningLog "hosts: sinkholed $($toAdd -join ', ')" 'Detail'
        }
    }

    New-HardeningControl -Id 'PRT-011' -Name 'DHCPv6 and router discovery disabled (anti-mitm6)' -Category 'Protocols' -Tier 'Aggressive' `
        -Counters @('mitm6', 'atk6-fake_router6', 'IPv6 DNS takeover') `
        -Rationale 'Windows prefers IPv6 and ships with DHCPv6 enabled even on IPv4-only networks, which is exactly the gap mitm6 drives through. Turning off DHCPv6 and router discovery per interface removes the takeover path without disabling IPv6 entirely.' `
        -Impact 'Only safe on IPv4-only networks. On a real IPv6 network this removes addressing and default-route discovery.' `
        -Test {
        $ifaces = @(Get-NetIPInterface -AddressFamily IPv6 -ErrorAction Stop |
                Where-Object { $_.InterfaceAlias -notmatch 'Loopback' })
        $exposed = @($ifaces | Where-Object { $_.Dhcp -eq 'Enabled' -or $_.RouterDiscovery -eq 'Enabled' })

        @{
            Compliant = ($exposed.Count -eq 0)
            Detail    = "$($ifaces.Count - $exposed.Count)/$($ifaces.Count) IPv6 interfaces have DHCPv6 and router discovery off."
        }
    } `
        -Apply {
        foreach ($iface in (Get-NetIPInterface -AddressFamily IPv6 -ErrorAction Stop | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' })) {
            Add-HardeningStateEntry -Kind 'Note' -ControlId 'PRT-011' -Before @{
                Description     = 'IPv6 interface configuration before anti-mitm6 hardening.'
                InterfaceIndex  = $iface.InterfaceIndex
                InterfaceAlias  = $iface.InterfaceAlias
                Dhcp            = [string]$iface.Dhcp
                RouterDiscovery = [string]$iface.RouterDiscovery
            }
            Set-NetIPInterface -InterfaceIndex $iface.InterfaceIndex -AddressFamily IPv6 -Dhcp Disabled -RouterDiscovery Disabled -ErrorAction SilentlyContinue
        }
    }
}
