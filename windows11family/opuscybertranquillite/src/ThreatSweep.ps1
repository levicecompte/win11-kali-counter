<#
    ThreatSweep.ps1 - Read-only detection pass.

    Hardening stops the easy attacks. This pass looks for evidence that someone is
    currently running the hard ones: ARP spoofing, name-resolution poisoning, port
    scans in the firewall log, password spraying in the Security log, PsExec-style
    service installs, named pipes belonging to known tooling, and tampering with the
    defences this toolkit configures.

    Nothing in this file changes system state.
#>

function New-SweepFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Detail,
        [string]$Recommendation = '',
        [object[]]$Evidence = @()
    )

    [pscustomobject]@{
        PSTypeName     = 'Hardening.SweepFinding'
        Id             = $Id
        Severity       = $Severity
        Title          = $Title
        Detail         = $Detail
        Recommendation = $Recommendation
        Evidence       = $Evidence
        ObservedUtc    = (Get-Date).ToUniversalTime().ToString('o')
    }
}

#region Pure analysers

function Find-ArpAnomaly {
    <#
        .SYNOPSIS
        Finds MAC addresses claiming more than one IPv4 address - the signature left by
        arpspoof, ettercap and bettercap when they insert themselves between you and the
        gateway.

        .PARAMETER Entry
        Objects with IPAddress and LinkLayerAddress properties (as returned by Get-NetNeighbor).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entry
    )

    $ignored = @('00-00-00-00-00-00', 'FF-FF-FF-FF-FF-FF')

    $usable = $Entry | Where-Object {
        $mac = [string]$_.LinkLayerAddress
        $ip = [string]$_.IPAddress
        $mac -and $ip -and
        ($mac.ToUpperInvariant() -notin $ignored) -and
        # IPv4 multicast maps to 01-00-5E-xx, IPv6 multicast to 33-33-xx.
        ($mac -notmatch '^(01-00-5E|33-33)') -and
        ($ip -notmatch '^(224\.|239\.|255\.)')
    }

    $usable | Group-Object -Property LinkLayerAddress | Where-Object { @($_.Group.IPAddress | Sort-Object -Unique).Count -gt 1 } | ForEach-Object {
        $addresses = @($_.Group.IPAddress | Sort-Object -Unique)
        [pscustomobject]@{
            MacAddress  = $_.Name
            IPAddresses = $addresses
            Count       = $addresses.Count
        }
    }
}

function ConvertFrom-FirewallLogLine {
    <#
        .SYNOPSIS
        Pure parser for a Windows Firewall pfirewall.log line.

        .DESCRIPTION
        Field order is fixed by the log header:
        date time action protocol src-ip dst-ip src-port dst-port size tcpflags ... path
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Line
    )

    if ([string]::IsNullOrWhiteSpace($Line) -or $Line.StartsWith('#')) { return }

    $f = $Line -split '\s+'
    if ($f.Count -lt 8) { return }

    $timestamp = [datetime]::MinValue
    $parsed = [datetime]::TryParse("$($f[0]) $($f[1])", [ref]$timestamp)

    [pscustomobject]@{
        Timestamp  = if ($parsed) { $timestamp } else { $null }
        Action     = $f[2]
        Protocol   = $f[3]
        SourceIp   = $f[4]
        DestIp     = $f[5]
        SourcePort = $f[6]
        DestPort   = $f[7]
        Direction  = if ($f.Count -ge 17) { $f[16] } else { '' }
    }
}

function Find-PortScanSource {
    <#
        .SYNOPSIS
        Flags source addresses that were dropped while probing many distinct ports.

        .PARAMETER Record
        Parsed firewall log records (see ConvertFrom-FirewallLogLine).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
        [int]$DistinctPortThreshold = 15,
        [int]$WindowMinutes = 60,
        [datetime]$Now = (Get-Date)
    )

    $cutoff = $Now.AddMinutes(-$WindowMinutes)

    $relevant = $Record | Where-Object {
        $_.Action -eq 'DROP' -and
        $_.SourceIp -and $_.SourceIp -ne '-' -and
        $_.Timestamp -and $_.Timestamp -ge $cutoff
    }

    $relevant | Group-Object -Property SourceIp | ForEach-Object {
        $ports = @($_.Group.DestPort | Where-Object { $_ -and $_ -ne '-' } | Sort-Object -Unique)
        if ($ports.Count -lt $DistinctPortThreshold) { return }

        [pscustomobject]@{
            SourceIp      = $_.Name
            DistinctPorts = $ports.Count
            Attempts      = $_.Group.Count
            FirstSeen     = ($_.Group.Timestamp | Measure-Object -Minimum).Minimum
            LastSeen      = ($_.Group.Timestamp | Measure-Object -Maximum).Maximum
            SamplePorts   = @($ports | Select-Object -First 20)
        }
    }
}

function Test-SuspiciousPipeName {
    <#
        .SYNOPSIS
        Matches a named pipe against patterns used by remote-execution and C2 tooling.
        Returns the indicator name, or $null when the pipe looks ordinary.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name
    )

    $indicators = [ordered]@{
        'PsExec service'               = '^psexesvc'
        'PAExec'                       = '^paexec'
        'CSExec'                       = '^csexec'
        'RemCom'                       = '^remcom'
        'impacket smbexec'             = '^(execpipe|BUILTIN)'
        'Cobalt Strike SMB beacon'     = '^(msagent_|postex_|postex_ssh_|status_|MSSE-\d+-server)'
        'Metasploit named-pipe pivot'  = '^(msf-pipe|meterpreter)'
        'mimikatz'                     = 'mimikatz|mimi'
    }

    $leaf = ($Name -replace '^.*\\pipe\\', '')

    foreach ($key in $indicators.Keys) {
        if ($leaf -match $indicators[$key]) { return $key }
    }

    $null
}

function Find-BruteForceSource {
    <#
        .SYNOPSIS
        Groups failed-logon records by workstation/source address and flags high counts.

        .PARAMETER Record
        Objects with SourceName, SourceIp, TargetUser and TimeCreated properties.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
        [int]$FailureThreshold = 10
    )

    $Record | Group-Object -Property SourceIp | ForEach-Object {
        if ($_.Group.Count -lt $FailureThreshold) { return }

        [pscustomobject]@{
            SourceIp       = if ([string]::IsNullOrWhiteSpace($_.Name)) { '(not recorded)' } else { $_.Name }
            SourceName     = @($_.Group.SourceName | Where-Object { $_ } | Sort-Object -Unique) -join ', '
            Failures       = $_.Group.Count
            TargetedUsers  = @($_.Group.TargetUser | Where-Object { $_ } | Sort-Object -Unique)
            FirstSeen      = ($_.Group.TimeCreated | Measure-Object -Minimum).Minimum
            LastSeen       = ($_.Group.TimeCreated | Measure-Object -Maximum).Maximum
        }
    }
}

function Test-SuspiciousServiceName {
    <#
        .SYNOPSIS
        Matches a service name against names used by known remote-execution tooling.

        .DESCRIPTION
        Exact matches only, deliberately.

        A "does this name look randomly generated?" heuristic was tried here and removed.
        Metasploit generates service names with random casing, which is statistically
        indistinguishable from ordinary CamelCase Windows service names - WdNisSvc and
        WinHttpAutoProxySvc both score as "random" under every variant that also catches
        real payloads. Telling someone their machine is compromised because they run
        Windows Defender is worse than missing the service entirely, so the detection
        weight sits in Test-SuspiciousServiceImagePath instead, where the signal is real.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }

    $known = @(
        'psexesvc'    # Sysinternals PsExec
        'paexec'      # PAExec
        'remcom'      # RemCom
        'csexec'      # CSExec
        'winexesvc'   # winexe
        'mimidrv'     # mimikatz kernel driver
        'pwdump'      # pwdump service
        'wceservice'  # Windows Credentials Editor
    )

    $Name.ToLowerInvariant() -in $known
}

function Test-SuspiciousServiceImagePath {
    <#
        .SYNOPSIS
        Flags a service image path that runs from a user-writable directory or launches a
        script interpreter. Legitimate services run signed binaries out of Program Files
        or System32; payload services almost never do.

        Returns the reason it was flagged, or $null.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$ImagePath
    )

    if ([string]::IsNullOrWhiteSpace($ImagePath)) { return $null }

    $checks = [ordered]@{
        'runs from a user-writable directory' = '(?i)\\(Temp|Users\\Public|Users\\[^\\]+\\(AppData|Downloads|Desktop)|ProgramData|\$Recycle\.Bin)\\'
        'launches a script interpreter'       = '(?i)\b(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msbuild)\.exe\b'
        'passes an encoded command'           = '(?i)(\s-enc(odedcommand)?\s|FromBase64String|\s-nop\s|\s-w\s+hidden\b)'
        'runs from a network share'           = '^\s*"?\\\\[^\\]+\\'
    }

    foreach ($reason in $checks.Keys) {
        if ($ImagePath -match $checks[$reason]) { return $reason }
    }

    $null
}

#endregion

#region Collectors

function Get-FirewallLogRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [int]$TailLines = 20000
    )

    $path = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log'
    if (-not (Test-Path -LiteralPath $path)) { return }

    $stream = $null
    $reader = $null
    $lines = @()

    try {
        # The firewall service holds the log open, so it must be read share-all.
        $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $reader = [IO.StreamReader]::new($stream)
        $lines = $reader.ReadToEnd() -split "`r?`n"
    } catch {
        Write-HardeningLog "Could not read the firewall log: $($_.Exception.Message)" 'Detail'
        return
    } finally {
        if ($reader) { $reader.Dispose() }
        if ($stream) { $stream.Dispose() }
    }

    $tail = if ($lines.Count -gt $TailLines) { $lines[-$TailLines..-1] } else { $lines }
    foreach ($line in $tail) { ConvertFrom-FirewallLogLine -Line $line }
}

function Get-FailedLogonRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [int]$Hours = 24,
        [int]$MaxEvents = 2000
    )

    $filter = @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddHours(-$Hours) }

    try {
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
    } catch {
        return
    }

    foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

        [pscustomobject]@{
            TimeCreated = $e.TimeCreated
            TargetUser  = $data['TargetUserName']
            SourceIp    = $data['IpAddress']
            SourceName  = $data['WorkstationName']
            LogonType   = $data['LogonType']
        }
    }
}

#endregion

function Invoke-ThreatSweep {
    <#
        .SYNOPSIS
        Runs every detection in this module and returns the findings.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [int]$Hours = 24,
        [string]$BaselinePath
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    # --- 1. ARP spoofing -------------------------------------------------------
    Write-HardeningLog 'Checking the neighbour cache for ARP spoofing' 'Step'
    try {
        $neighbors = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |
                Where-Object { $_.State -in @('Reachable', 'Stale', 'Permanent') })
        $anomalies = @(Find-ArpAnomaly -Entry $neighbors)

        foreach ($a in $anomalies) {
            $severity = if ($a.Count -ge 3) { 'High' } else { 'Medium' }
            $findings.Add((New-SweepFinding -Id 'SWP-ARP-01' -Severity $severity `
                        -Title 'One MAC address is claiming multiple IP addresses' `
                        -Detail "MAC $($a.MacAddress) currently answers for $($a.Count) addresses: $($a.IPAddresses -join ', '). This is what arpspoof, ettercap and bettercap look like from the victim side. A router or a host with several interfaces can look the same, so confirm the MAC belongs to equipment you recognise." `
                        -Recommendation 'Compare the MAC against your gateway hardware. If it does not match, treat the segment as hostile: disconnect, and prefer a wired link or a VPN tunnel that authenticates the far end.' `
                        -Evidence $a))
        }

        if ($anomalies.Count -eq 0) {
            Write-HardeningLog "No duplicate-MAC anomalies across $($neighbors.Count) neighbour entries." 'Detail'
        }

        if ($BaselinePath) {
            $findings.AddRange(@(Compare-NeighborBaseline -Neighbor $neighbors -BaselinePath $BaselinePath))
        }
    } catch {
        Write-HardeningLog "Neighbour cache unavailable: $($_.Exception.Message)" 'Detail'
    }

    # --- 2. Name-resolution poisoning ------------------------------------------
    Write-HardeningLog 'Probing for an LLMNR/NBT-NS poisoner' 'Step'
    $findings.AddRange(@(Test-NameResolutionPoisoning))

    # --- 3. mitm6 / rogue IPv6 DNS ---------------------------------------------
    Write-HardeningLog 'Checking for rogue IPv6 DNS servers' 'Step'
    try {
        $v6dns = @(Get-DnsClientServerAddress -AddressFamily IPv6 -ErrorAction Stop |
                Where-Object { $_.ServerAddresses } |
                ForEach-Object { $_.ServerAddresses } |
                Where-Object { $_ -notmatch '^(fec0:0:0:ffff|::1)' })

        if ($v6dns.Count -gt 0) {
            $findings.Add((New-SweepFinding -Id 'SWP-DNS-01' -Severity 'Medium' `
                        -Title 'IPv6 DNS servers are configured' `
                        -Detail "This host is using IPv6 DNS server(s): $($v6dns -join ', '). On an IPv4-only network that is the exact result of a successful mitm6 run, because Windows prefers IPv6 DNS over IPv4." `
                        -Recommendation 'If your network does not actually provide IPv6, apply PRT-011 and FWL-009 to stop the host accepting DHCPv6 and router advertisements.' `
                        -Evidence $v6dns))
        } else {
            Write-HardeningLog 'No non-default IPv6 DNS servers configured.' 'Detail'
        }
    } catch {
        Write-HardeningLog "IPv6 DNS configuration unavailable: $($_.Exception.Message)" 'Detail'
    }

    # --- 4. Port scans in the firewall log --------------------------------------
    Write-HardeningLog 'Scanning the firewall log for port sweeps' 'Step'
    $fwRecords = @(Get-FirewallLogRecord)
    if ($fwRecords.Count -eq 0) {
        Write-HardeningLog 'No firewall log data. Apply FWL-011 to turn on dropped-packet logging.' 'Detail'
    } else {
        $scanners = @(Find-PortScanSource -Record $fwRecords -WindowMinutes ($Hours * 60))
        foreach ($s in $scanners) {
            $severity = if ($s.DistinctPorts -ge 100) { 'High' } else { 'Medium' }
            $findings.Add((New-SweepFinding -Id 'SWP-SCAN-01' -Severity $severity `
                        -Title 'A host on the network is port-scanning this machine' `
                        -Detail "$($s.SourceIp) was dropped probing $($s.DistinctPorts) distinct ports in $($s.Attempts) attempts between $($s.FirstSeen) and $($s.LastSeen). That pattern is an nmap or masscan sweep." `
                        -Recommendation "Identify $($s.SourceIp) on your network. If you do not recognise it, treat the segment as compromised and investigate that host." `
                        -Evidence $s))
        }
        if ($scanners.Count -eq 0) {
            Write-HardeningLog "Parsed $($fwRecords.Count) firewall log records, no scan pattern found." 'Detail'
        }
    }

    # --- 5. Password guessing ----------------------------------------------------
    Write-HardeningLog 'Reviewing failed logons for password spraying' 'Step'
    $failures = @(Get-FailedLogonRecord -Hours $Hours)
    if ($failures.Count -eq 0) {
        Write-HardeningLog 'No failed logons recorded (or Security log auditing is off - see LOG-002).' 'Detail'
    } else {
        foreach ($b in @(Find-BruteForceSource -Record $failures)) {
            $severity = if ($b.TargetedUsers.Count -ge 5) { 'High' } else { 'Medium' }
            $findings.Add((New-SweepFinding -Id 'SWP-AUTH-01' -Severity $severity `
                        -Title 'Repeated failed logons from a single source' `
                        -Detail "$($b.Failures) failed logons from $($b.SourceIp) ($($b.SourceName)) against $($b.TargetedUsers.Count) account(s): $($b.TargetedUsers -join ', '). Several accounts from one source is password spraying rather than a forgotten password." `
                        -Recommendation 'Confirm the lockout policy is active (CRD-012) and block the source. If the source is this machine''s own address, look for a local process doing the guessing.' `
                        -Evidence $b))
        }
    }

    # --- 6. Remote-execution service installs -------------------------------------
    Write-HardeningLog 'Looking for PsExec-style service installs' 'Step'
    $findings.AddRange(@(Find-SuspiciousServiceInstall -Hours $Hours))

    # --- 7. Named pipes ------------------------------------------------------------
    Write-HardeningLog 'Enumerating named pipes for known tooling' 'Step'
    try {
        $pipes = @(Get-ChildItem -Path '\\.\pipe\' -ErrorAction Stop | ForEach-Object Name)
        foreach ($pipe in $pipes) {
            $indicator = Test-SuspiciousPipeName -Name $pipe
            if (-not $indicator) { continue }

            $findings.Add((New-SweepFinding -Id 'SWP-PIPE-01' -Severity 'Critical' `
                        -Title 'A named pipe matching known attack tooling is open' `
                        -Detail "Pipe '$pipe' matches the pattern for $indicator. Remote-execution and C2 frameworks create these pipes for their command channel." `
                        -Recommendation 'Treat this host as compromised. Capture volatile state, isolate it from the network, and rebuild rather than clean.' `
                        -Evidence $pipe))
        }
        Write-HardeningLog "Checked $($pipes.Count) named pipes." 'Detail'
    } catch {
        Write-HardeningLog "Could not enumerate named pipes: $($_.Exception.Message)" 'Detail'
    }

    # --- 8. Unexpected listeners ----------------------------------------------------
    Write-HardeningLog 'Reviewing listening sockets' 'Step'
    $findings.AddRange(@(Find-UnexpectedListener))

    # --- 9. Tampering with the defences ----------------------------------------------
    Write-HardeningLog 'Checking whether defences have been tampered with' 'Step'
    $findings.AddRange(@(Find-DefenceTampering))

    # --- 10. Local administrators -----------------------------------------------------
    Write-HardeningLog 'Reviewing local administrator membership' 'Step'
    try {
        $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
        Write-HardeningLog "Local Administrators: $(($admins | ForEach-Object Name) -join ', ')" 'Detail'

        $recent = @(Get-LocalUser -ErrorAction SilentlyContinue |
                Where-Object { $_.Enabled -and $_.PasswordLastSet -and $_.PasswordLastSet -gt (Get-Date).AddHours(-$Hours) })

        foreach ($u in $recent) {
            $isAdmin = @($admins | Where-Object { $_.SID.Value -eq $u.SID.Value }).Count -gt 0
            if (-not $isAdmin) { continue }

            $findings.Add((New-SweepFinding -Id 'SWP-ACCT-01' -Severity 'High' `
                        -Title 'A local administrator password was set very recently' `
                        -Detail "Account '$($u.Name)' is in the Administrators group and its password was set at $($u.PasswordLastSet), within the last $Hours hours. Creating a local admin is a standard persistence step." `
                        -Recommendation 'Confirm you made this change. If not, disable the account and investigate how it was created.' `
                        -Evidence $u.Name))
        }
    } catch {
        Write-HardeningLog "Could not read local group membership: $($_.Exception.Message)" 'Detail'
    }

    $findings
}

function Test-NameResolutionPoisoning {
    <#
        .SYNOPSIS
        Asks for a hostname that cannot exist. Any answer means something on the segment
        is answering every query, which is exactly what Responder and Inveigh do.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $probe = 'wpad-' + ([guid]::NewGuid().ToString('N').Substring(0, 12))

    $answers = @()
    try {
        $answers = @(Resolve-DnsName -Name $probe -LlmnrNetbiosOnly -DnsOnly:$false -QuickTimeout -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress })
    } catch {
        Write-HardeningLog "Multicast name probe failed: $($_.Exception.Message)" 'Detail'
    }

    if ($answers.Count -gt 0) {
        $ips = @($answers | ForEach-Object IPAddress | Sort-Object -Unique)
        New-SweepFinding -Id 'SWP-POISON-01' -Severity 'Critical' `
            -Title 'A name-resolution poisoner is active on this network' `
            -Detail "The random hostname '$probe' resolved to $($ips -join ', ') over LLMNR/NBT-NS. That name does not exist, so something on the segment is answering every broadcast query - the defining behaviour of Responder and Inveigh. Any credential your machine offers to that address can be relayed or cracked." `
            -Recommendation 'Disconnect from this network. Apply PRT-001, PRT-002 and FWL-003 so the host stops broadcasting queries, and treat any credentials used on this segment as exposed.' `
            -Evidence $ips
        return
    }

    $llmnr = Get-RegistryValueOrNull -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
    if ($llmnr -eq 0) {
        Write-HardeningLog 'LLMNR is disabled, so the multicast probe cannot be answered. This check is inert by design once PRT-001 is applied.' 'Detail'
    } else {
        Write-HardeningLog 'No poisoned answer to the multicast probe.' 'Detail'
    }
}

function Find-SuspiciousServiceInstall {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([int]$Hours = 24)

    try {
        $events = @(Get-WinEvent -FilterHashtable @{
                LogName   = 'System'
                Id        = 7045
                StartTime = (Get-Date).AddHours(-$Hours)
            } -ErrorAction Stop)
    } catch {
        Write-HardeningLog 'No service-install events in the window.' 'Detail'
        return
    }

    foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

        $name = [string]$data['ServiceName']
        $image = [string]$data['ImagePath']

        $reason = if (Test-SuspiciousServiceName -Name $name) {
            "its name matches known remote-execution tooling"
        } else {
            $pathReason = Test-SuspiciousServiceImagePath -ImagePath $image
            if ($pathReason) { "it $pathReason" } else { $null }
        }

        if (-not $reason) { continue }

        New-SweepFinding -Id 'SWP-SVC-01' -Severity 'Critical' `
            -Title 'A service was installed that looks like remote-execution tooling' `
            -Detail "Service '$name' was installed at $($e.TimeCreated) and flagged because $reason. Image path: $image. PsExec, impacket and Metasploit all gain SYSTEM by installing a temporary service exactly like this." `
            -Recommendation 'If you did not install this, treat the host as compromised: isolate it, preserve the Security and System logs, and rebuild rather than clean.' `
            -Evidence ([pscustomobject]@{ ServiceName = $name; ImagePath = $image; Installed = $e.TimeCreated; Reason = $reason })
    }
}

function Find-UnexpectedListener {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    # Ports Windows itself legitimately listens on.
    $expected = @(135, 139, 445, 5040, 7680, 49664, 49665, 49666, 49667, 49668, 49669, 49670)

    try {
        $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
                Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') })
    } catch {
        Write-HardeningLog "Could not enumerate listening sockets: $($_.Exception.Message)" 'Detail'
        return
    }

    foreach ($l in $listeners) {
        if ($l.LocalPort -in $expected -or $l.LocalPort -ge 49152) { continue }

        $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
        $path = if ($proc) { $proc.Path } else { $null }

        $risky = ($path -match '\\(Temp|Users\\Public|ProgramData|Downloads)\\') -or (-not $path)

        New-SweepFinding -Id 'SWP-LISTEN-01' -Severity ($(if ($risky) { 'High' } else { 'Info' })) `
            -Title "Process is listening on $($l.LocalAddress):$($l.LocalPort)" `
            -Detail "$(if ($proc) { $proc.ProcessName } else { "PID $($l.OwningProcess)" }) is accepting connections from the network on port $($l.LocalPort)$(if ($path) { " (image: $path)" })." `
            -Recommendation 'Confirm this listener is something you installed. Anything listening from a Temp, Downloads or Public directory should be treated as hostile.' `
            -Evidence ([pscustomobject]@{ Port = $l.LocalPort; Address = $l.LocalAddress; Process = $(if ($proc) { $proc.ProcessName } else { 'unknown' }); Path = $path })
    }
}

function Find-DefenceTampering {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $wdigest = Get-RegistryValueOrNull -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential'
    if ($wdigest -eq 1) {
        New-SweepFinding -Id 'SWP-TAMPER-01' -Severity 'Critical' `
            -Title 'WDigest cleartext credential caching has been switched on' `
            -Detail 'UseLogonCredential is set to 1. Nothing on a modern system needs this. Attack tooling sets it deliberately so that the next logon leaves a cleartext password in LSASS for mimikatz to read.' `
            -Recommendation 'Apply CRD-001 immediately, then change the passwords of every account that has logged on since this value was set.'
    }

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        if (-not $status.RealTimeProtectionEnabled) {
            New-SweepFinding -Id 'SWP-TAMPER-02' -Severity 'Critical' `
                -Title 'Defender real-time protection is off' `
                -Detail 'Real-time protection is disabled. Disabling antivirus is step one of most post-exploitation playbooks.' `
                -Recommendation 'Re-enable it with DEF-001 and turn on Tamper Protection (DEF-004) so it cannot be switched off again from a script.'
        }

        $mp = Get-MpPreference -ErrorAction Stop
        $exclusions = @($mp.ExclusionPath) + @($mp.ExclusionProcess) | Where-Object { $_ }
        if ($exclusions.Count -gt 0) {
            New-SweepFinding -Id 'SWP-TAMPER-03' -Severity 'Medium' `
                -Title 'Defender exclusions are configured' `
                -Detail "Defender is ignoring: $($exclusions -join '; '). Adding an exclusion and then staging tooling inside it is a common way to work around antivirus without tripping Tamper Protection." `
                -Recommendation 'Remove any exclusion you did not deliberately add.' `
                -Evidence $exclusions
        }
    } catch {
        Write-HardeningLog "Defender status unavailable: $($_.Exception.Message)" 'Detail'
    }

    $auditOverride = Get-RegistryValueOrNull -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy'
    $lsaPpl = Get-RegistryValueOrNull -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL'
    if ($lsaPpl -eq 0 -and $null -ne $auditOverride) {
        New-SweepFinding -Id 'SWP-TAMPER-04' -Severity 'High' `
            -Title 'LSA Protection has been explicitly turned off' `
            -Detail 'RunAsPPL is set to 0 rather than simply absent, which means something wrote that value deliberately. Disabling LSA Protection is a prerequisite for dumping LSASS.' `
            -Recommendation 'Apply CRD-002 and reboot, then investigate what wrote the value.'
    }
}

function Compare-NeighborBaseline {
    <#
        .SYNOPSIS
        Compares the current gateway MAC against a stored baseline, so a gateway
        impersonation shows up even when the ARP cache itself looks clean.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Neighbor,
        [Parameter(Mandatory)][string]$BaselinePath
    )

    $gateways = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            ForEach-Object NextHop | Where-Object { $_ -and $_ -ne '0.0.0.0' } | Sort-Object -Unique)

    $current = @{}
    foreach ($gw in $gateways) {
        $entry = $Neighbor | Where-Object { $_.IPAddress -eq $gw } | Select-Object -First 1
        if ($entry) { $current[$gw] = [string]$entry.LinkLayerAddress }
    }

    if ($current.Count -eq 0) { return }

    $baseline = @{}
    if (Test-Path -LiteralPath $BaselinePath) {
        try {
            $loaded = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
            foreach ($p in $loaded.PSObject.Properties) { $baseline[$p.Name] = [string]$p.Value }
        } catch {
            Write-HardeningLog "Gateway baseline unreadable, rewriting: $($_.Exception.Message)" 'Detail'
        }
    }

    foreach ($gw in $current.Keys) {
        if (-not $baseline.ContainsKey($gw)) { continue }
        if ($baseline[$gw] -eq $current[$gw]) { continue }

        New-SweepFinding -Id 'SWP-ARP-02' -Severity 'High' `
            -Title 'The default gateway is answering from a different MAC address' `
            -Detail "Gateway $gw previously resolved to $($baseline[$gw]) and now resolves to $($current[$gw]). Replacing router hardware does this. So does a machine impersonating the gateway." `
            -Recommendation 'If you did not change routers, stop using this network and treat all traffic sent over it as observed.' `
            -Evidence ([pscustomobject]@{ Gateway = $gw; Was = $baseline[$gw]; Now = $current[$gw] })
    }

    $merged = @{}
    foreach ($k in $baseline.Keys) { $merged[$k] = $baseline[$k] }
    foreach ($k in $current.Keys) { $merged[$k] = $current[$k] }

    $dir = Split-Path -Parent $BaselinePath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $merged | ConvertTo-Json | Set-Content -LiteralPath $BaselinePath -Encoding UTF8
}
