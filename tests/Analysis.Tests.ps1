#Requires -Modules Pester

<#
    Tests for the pure analysis functions: the parsers that read Windows' locale-dependent
    command output, the detection heuristics used by the threat sweep, and the engine
    helpers that decide whether a setting is compliant.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:SrcRoot = Join-Path $script:RepoRoot 'src'

    foreach ($file in @('Common.ps1', 'Controls.Credentials.ps1', 'Controls.Telemetry.ps1', 'ThreatSweep.ps1', 'Reporting.ps1')) {
        . (Join-Path $script:SrcRoot $file)
    }
}

Describe 'ConvertTo-ControlVerdict' {

    It 'wraps a bare boolean' {
        (ConvertTo-ControlVerdict -Raw $true).Compliant | Should -BeTrue
        (ConvertTo-ControlVerdict -Raw $false).Compliant | Should -BeFalse
    }

    It 'passes a hashtable through' {
        $v = ConvertTo-ControlVerdict -Raw @{ Compliant = $true; Detail = 'all good' }
        $v.Compliant | Should -BeTrue
        $v.Detail | Should -Be 'all good'
    }

    It 'passes an object with a Compliant property through' {
        $v = ConvertTo-ControlVerdict -Raw ([pscustomobject]@{ Compliant = $false; Detail = 'drifted' })
        $v.Compliant | Should -BeFalse
        $v.Detail | Should -Be 'drifted'
    }

    It 'treats a null result as non-compliant rather than silently passing' {
        $v = ConvertTo-ControlVerdict -Raw $null
        $v.Compliant | Should -BeFalse
    }
}

Describe 'Test-RegistryValueEqual' {

    It 'compares DWord values written as int or string the same way' {
        Test-RegistryValueEqual -Actual 1 -Expected 1 | Should -BeTrue
        Test-RegistryValueEqual -Actual '1' -Expected 1 | Should -BeTrue
        Test-RegistryValueEqual -Actual 1 -Expected 0 | Should -BeFalse
    }

    It 'treats zero as a real value rather than as unset' {
        Test-RegistryValueEqual -Actual 0 -Expected 0 | Should -BeTrue
    }

    It 'treats a missing value as non-compliant' {
        Test-RegistryValueEqual -Actual $null -Expected 1 | Should -BeFalse
    }

    It 'compares MultiString arrays element by element' {
        Test-RegistryValueEqual -Actual @() -Expected @() | Should -BeTrue
        Test-RegistryValueEqual -Actual @('a', 'b') -Expected @('a', 'b') | Should -BeTrue
        Test-RegistryValueEqual -Actual @('a') -Expected @('a', 'b') | Should -BeFalse
        Test-RegistryValueEqual -Actual @('b', 'a') -Expected @('a', 'b') | Should -BeFalse
    }

    It 'treats an absent MultiString as equal to the empty list we want' {
        # NullSessionPipes is compliant whether it is empty or missing entirely.
        Test-RegistryValueEqual -Actual $null -Expected @() | Should -BeTrue
    }
}

Describe 'ConvertFrom-AuditPolBackup' {

    It 'reads the numeric setting column rather than the localised text' {
        # German output: the "Inclusion Setting" column is translated, column 6 is not.
        $lines = @(
            'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
            'WIN11,System,Anmelden,{0cce9215-69ae-11d9-bed3-505054503030},Erfolg und Fehler,,3'
            'WIN11,System,Prozesserstellung,{0cce922b-69ae-11d9-bed3-505054503030},Erfolg,,1'
        )

        $map = ConvertFrom-AuditPolBackup -Line $lines
        $map['{0cce9215-69ae-11d9-bed3-505054503030}'] | Should -Be 3
        $map['{0cce922b-69ae-11d9-bed3-505054503030}'] | Should -Be 1
    }

    It 'ignores the header, blank lines and malformed rows' {
        $map = ConvertFrom-AuditPolBackup -Line @(
            'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
            ''
            'too,few,columns'
            'WIN11,System,Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3'
        )
        $map.Keys.Count | Should -Be 1
    }

    It 'handles quoted subcategory names containing commas' {
        $map = ConvertFrom-AuditPolBackup -Line @(
            'WIN11,System,"Other Logon/Logoff Events, extended",{0cce921c-69ae-11d9-bed3-505054503030},Success,,1'
        )
        $map['{0cce921c-69ae-11d9-bed3-505054503030}'] | Should -Be 1
    }

    It 'returns an empty map for no input' {
        (ConvertFrom-AuditPolBackup -Line @()).Keys.Count | Should -Be 0
    }
}

Describe 'ConvertFrom-SeceditPolicy' {

    It 'reads the lockout policy out of a secedit export' {
        $policy = ConvertFrom-SeceditPolicy -Line @(
            '[Unicode]'
            'Unicode=yes'
            '[System Access]'
            'MinimumPasswordLength = 14'
            'LockoutBadCount = 10'
            'ResetLockoutCount = 15'
            'LockoutDuration = 15'
        )

        $policy.LockoutBadCount | Should -Be 10
        $policy.LockoutDuration | Should -Be 15
        $policy.ResetLockoutCount | Should -Be 15
        $policy.MinimumPasswordLength | Should -Be 14
    }

    It 'reports -1 for values the export does not contain' {
        $policy = ConvertFrom-SeceditPolicy -Line @('[System Access]')
        $policy.LockoutBadCount | Should -Be -1
    }
}

Describe 'ConvertFrom-FirewallLogLine' {

    It 'parses a dropped inbound packet' {
        $r = ConvertFrom-FirewallLogLine -Line '2026-10-05 22:14:03 DROP TCP 192.168.1.66 192.168.1.20 51234 445 52 S 1234 0 64240 - - - RECEIVE'

        $r.Action | Should -Be 'DROP'
        $r.Protocol | Should -Be 'TCP'
        $r.SourceIp | Should -Be '192.168.1.66'
        $r.DestPort | Should -Be '445'
        $r.Direction | Should -Be 'RECEIVE'
        $r.Timestamp | Should -Not -BeNullOrEmpty
    }

    It 'ignores comment and header lines' {
        ConvertFrom-FirewallLogLine -Line '#Version: 1.5' | Should -BeNullOrEmpty
        ConvertFrom-FirewallLogLine -Line '#Fields: date time action protocol' | Should -BeNullOrEmpty
        ConvertFrom-FirewallLogLine -Line '' | Should -BeNullOrEmpty
    }

    It 'ignores truncated lines' {
        ConvertFrom-FirewallLogLine -Line '2026-10-05 22:14:03 DROP TCP' | Should -BeNullOrEmpty
    }
}

Describe 'Find-PortScanSource' {

    BeforeAll {
        $script:Now = Get-Date

        function New-DropRecord {
            param($Ip, $Port, $MinutesAgo = 1)
            [pscustomobject]@{
                Timestamp = $script:Now.AddMinutes(-$MinutesAgo)
                Action    = 'DROP'
                Protocol  = 'TCP'
                SourceIp  = $Ip
                DestIp    = '192.168.1.20'
                DestPort  = "$Port"
                Direction = 'RECEIVE'
            }
        }
    }

    It 'flags a source probing many distinct ports' {
        $records = 1..40 | ForEach-Object { New-DropRecord -Ip '192.168.1.66' -Port (1000 + $_) }

        $scanners = @(Find-PortScanSource -Record $records -Now $script:Now)
        $scanners.Count | Should -Be 1
        $scanners[0].SourceIp | Should -Be '192.168.1.66'
        $scanners[0].DistinctPorts | Should -Be 40
    }

    It 'ignores a source that hammers one port, which is retry traffic rather than a scan' {
        $records = 1..200 | ForEach-Object { New-DropRecord -Ip '192.168.1.70' -Port 445 }
        @(Find-PortScanSource -Record $records -Now $script:Now) | Should -BeNullOrEmpty
    }

    It 'ignores activity outside the time window' {
        $records = 1..40 | ForEach-Object { New-DropRecord -Ip '192.168.1.66' -Port (1000 + $_) -MinutesAgo 600 }
        @(Find-PortScanSource -Record $records -WindowMinutes 60 -Now $script:Now) | Should -BeNullOrEmpty
    }

    It 'ignores allowed traffic' {
        $records = 1..40 | ForEach-Object {
            $r = New-DropRecord -Ip '192.168.1.66' -Port (1000 + $_)
            $r.Action = 'ALLOW'
            $r
        }
        @(Find-PortScanSource -Record $records -Now $script:Now) | Should -BeNullOrEmpty
    }

    It 'separates concurrent scanners' {
        $records = @()
        $records += 1..30 | ForEach-Object { New-DropRecord -Ip '10.0.0.5' -Port (1000 + $_) }
        $records += 1..30 | ForEach-Object { New-DropRecord -Ip '10.0.0.6' -Port (2000 + $_) }

        @(Find-PortScanSource -Record $records -Now $script:Now).Count | Should -Be 2
    }

    It 'returns nothing for an empty log' {
        @(Find-PortScanSource -Record @() -Now $script:Now) | Should -BeNullOrEmpty
    }
}

Describe 'Find-ArpAnomaly' {

    It 'flags one MAC claiming several IP addresses' {
        $entries = @(
            [pscustomobject]@{ IPAddress = '192.168.1.1'; LinkLayerAddress = 'AA-BB-CC-DD-EE-FF' }
            [pscustomobject]@{ IPAddress = '192.168.1.50'; LinkLayerAddress = 'AA-BB-CC-DD-EE-FF' }
            [pscustomobject]@{ IPAddress = '192.168.1.60'; LinkLayerAddress = '11-22-33-44-55-66' }
        )

        $anomalies = @(Find-ArpAnomaly -Entry $entries)
        $anomalies.Count | Should -Be 1
        $anomalies[0].MacAddress | Should -Be 'AA-BB-CC-DD-EE-FF'
        $anomalies[0].Count | Should -Be 2
    }

    It 'does not flag a clean neighbour cache' {
        $entries = @(
            [pscustomobject]@{ IPAddress = '192.168.1.1'; LinkLayerAddress = 'AA-BB-CC-DD-EE-FF' }
            [pscustomobject]@{ IPAddress = '192.168.1.60'; LinkLayerAddress = '11-22-33-44-55-66' }
        )
        @(Find-ArpAnomaly -Entry $entries) | Should -BeNullOrEmpty
    }

    It 'ignores multicast and broadcast entries, which legitimately share a MAC' {
        $entries = @(
            [pscustomobject]@{ IPAddress = '224.0.0.251'; LinkLayerAddress = '01-00-5E-00-00-FB' }
            [pscustomobject]@{ IPAddress = '224.0.0.252'; LinkLayerAddress = '01-00-5E-00-00-FC' }
            [pscustomobject]@{ IPAddress = '239.255.255.250'; LinkLayerAddress = '01-00-5E-7F-FF-FA' }
            [pscustomobject]@{ IPAddress = '255.255.255.255'; LinkLayerAddress = 'FF-FF-FF-FF-FF-FF' }
        )
        @(Find-ArpAnomaly -Entry $entries) | Should -BeNullOrEmpty
    }

    It 'does not count the same IP seen twice as an anomaly' {
        $entries = @(
            [pscustomobject]@{ IPAddress = '192.168.1.1'; LinkLayerAddress = 'AA-BB-CC-DD-EE-FF' }
            [pscustomobject]@{ IPAddress = '192.168.1.1'; LinkLayerAddress = 'AA-BB-CC-DD-EE-FF' }
        )
        @(Find-ArpAnomaly -Entry $entries) | Should -BeNullOrEmpty
    }

    It 'handles an empty cache' {
        @(Find-ArpAnomaly -Entry @()) | Should -BeNullOrEmpty
    }
}

Describe 'Test-SuspiciousPipeName' {

    It 'recognises remote-execution tooling' {
        Test-SuspiciousPipeName -Name 'psexesvc' | Should -Be 'PsExec service'
        Test-SuspiciousPipeName -Name '\\.\pipe\psexesvc' | Should -Be 'PsExec service'
        Test-SuspiciousPipeName -Name 'paexec-1234-host.exe' | Should -Be 'PAExec'
        Test-SuspiciousPipeName -Name 'remcom_communicaton' | Should -Be 'RemCom'
    }

    It 'recognises C2 framework pipes' {
        Test-SuspiciousPipeName -Name 'msagent_7f' | Should -Be 'Cobalt Strike SMB beacon'
        Test-SuspiciousPipeName -Name 'postex_1234' | Should -Be 'Cobalt Strike SMB beacon'
        Test-SuspiciousPipeName -Name 'MSSE-1337-server' | Should -Be 'Cobalt Strike SMB beacon'
    }

    It 'leaves ordinary Windows pipes alone' {
        foreach ($name in @('lsass', 'srvsvc', 'wkssvc', 'epmapper', 'eventlog', 'spoolss', 'InitShutdown', 'LOCAL\\chrome.sync')) {
            Test-SuspiciousPipeName -Name $name | Should -BeNullOrEmpty -Because "'$name' is a normal pipe and a false positive here would be alarming"
        }
    }
}

Describe 'Test-SuspiciousServiceName' {

    It 'recognises known remote-execution service names' {
        Test-SuspiciousServiceName -Name 'PSEXESVC' | Should -BeTrue
        Test-SuspiciousServiceName -Name 'paexec' | Should -BeTrue
        Test-SuspiciousServiceName -Name 'mimidrv' | Should -BeTrue
    }

    It 'leaves ordinary Windows service names alone' {
        # Every one of these is a real service. A false positive here would tell a user
        # their machine is compromised when it is not, so this list is deliberately broad
        # and includes the CamelCase shapes that a "looks random" heuristic gets wrong.
        $realServices = @(
            'Spooler', 'WinRM', 'RemoteRegistry', 'wuauserv', 'Dnscache', 'LanmanServer',
            'EventLog', 'AppIDSvc', 'ProfSvc', 'BITS', 'SENS', 'TermService', 'WebClient',
            'FDResPub', 'SSDPSRV', 'upnphost', 'lltdsvc', 'seclogon', 'WinHttpAutoProxySvc',
            'CryptSvc', 'TrustedInstaller', 'WdNisSvc', 'SecurityHealthService', 'camsvc',
            'RpcSs', 'DPS', 'NlaSvc', 'DsmSvc', 'XblGameSave'
        )

        foreach ($name in $realServices) {
            Test-SuspiciousServiceName -Name $name | Should -BeFalse -Because "'$name' is a real Windows service"
        }
    }

    It 'handles an empty name' {
        Test-SuspiciousServiceName -Name '' | Should -BeFalse
    }
}

Describe 'Test-SuspiciousServiceImagePath' {

    It 'flags a service running out of a user-writable directory' {
        Test-SuspiciousServiceImagePath -ImagePath 'C:\Windows\Temp\svc.exe' | Should -Not -BeNullOrEmpty
        Test-SuspiciousServiceImagePath -ImagePath 'C:\Users\Public\a.exe' | Should -Not -BeNullOrEmpty
        Test-SuspiciousServiceImagePath -ImagePath 'C:\Users\jean\AppData\Local\x.exe' | Should -Not -BeNullOrEmpty
        Test-SuspiciousServiceImagePath -ImagePath 'C:\ProgramData\loader.exe' | Should -Not -BeNullOrEmpty
    }

    It 'flags a service that launches a script interpreter' {
        Test-SuspiciousServiceImagePath -ImagePath '%COMSPEC% /c powershell.exe -nop -w hidden -enc SQBFAFgA' | Should -Not -BeNullOrEmpty
        Test-SuspiciousServiceImagePath -ImagePath 'C:\Windows\System32\rundll32.exe shell32.dll,Control_RunDLL' | Should -Not -BeNullOrEmpty
        Test-SuspiciousServiceImagePath -ImagePath 'cmd.exe /c start /b nc.exe 10.0.0.5 4444' | Should -Not -BeNullOrEmpty
    }

    It 'flags a service running from a network share' {
        Test-SuspiciousServiceImagePath -ImagePath '\\10.0.0.5\share\payload.exe' | Should -Not -BeNullOrEmpty
    }

    It 'leaves ordinary service image paths alone' {
        $legitimate = @(
            'C:\Windows\system32\svchost.exe -k netsvcs -p'
            '"C:\Program Files\Mozilla Firefox\maintenanceservice.exe"'
            'C:\Windows\System32\spoolsv.exe'
            '"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /svc'
            'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe'
        )

        foreach ($path in $legitimate) {
            Test-SuspiciousServiceImagePath -ImagePath $path | Should -BeNullOrEmpty -Because "'$path' is a normal service image path"
        }
    }

    It 'handles an empty path' {
        Test-SuspiciousServiceImagePath -ImagePath '' | Should -BeNullOrEmpty
    }
}

Describe 'Find-BruteForceSource' {

    It 'flags many failures from one source against several accounts' {
        $records = @()
        foreach ($user in @('alice', 'bob', 'carol', 'dave', 'erin')) {
            $records += 1..4 | ForEach-Object {
                [pscustomobject]@{ TimeCreated = (Get-Date); TargetUser = $user; SourceIp = '192.168.1.66'; SourceName = 'KALI' }
            }
        }

        $hits = @(Find-BruteForceSource -Record $records)
        $hits.Count | Should -Be 1
        $hits[0].Failures | Should -Be 20
        $hits[0].TargetedUsers.Count | Should -Be 5
        $hits[0].SourceName | Should -Be 'KALI'
    }

    It 'ignores a handful of failures, which is a user mistyping a password' {
        $records = 1..3 | ForEach-Object {
            [pscustomobject]@{ TimeCreated = (Get-Date); TargetUser = 'alice'; SourceIp = '192.168.1.10'; SourceName = 'DESKTOP' }
        }
        @(Find-BruteForceSource -Record $records) | Should -BeNullOrEmpty
    }

    It 'labels failures with no recorded source address' {
        $records = 1..12 | ForEach-Object {
            [pscustomobject]@{ TimeCreated = (Get-Date); TargetUser = 'alice'; SourceIp = ''; SourceName = '' }
        }
        $hits = @(Find-BruteForceSource -Record $records)
        $hits[0].SourceIp | Should -Be '(not recorded)'
    }
}

Describe 'Reporting' {

    BeforeAll {
        $script:Facts = [pscustomobject]@{
            ComputerName = 'TESTHOST'; UserName = 'tester'; IsWindows = $true; IsElevated = $true
            PSVersion = '5.1'; OSCaption = 'Windows 11 Pro'; OSBuild = '26100'; DomainJoined = $false
        }

        $script:Results = @(
            [pscustomobject]@{ Id = 'FWL-001'; Name = 'Block inbound SMB'; Category = 'Firewall'; Tier = 'Baseline'
                Counters = @('impacket'); Rationale = 'r'; Impact = 'i'; RequiresReboot = $false; AuditOnly = $false
                Status = 'Remediated'; Detail = 'd'; Changed = $true; Error = $null }
            [pscustomobject]@{ Id = 'CRD-002'; Name = 'LSA Protection'; Category = 'Credentials'; Tier = 'Baseline'
                Counters = @('mimikatz'); Rationale = 'r'; Impact = 'i'; RequiresReboot = $true; AuditOnly = $false
                Status = 'Drift'; Detail = 'd'; Changed = $false; Error = $null }
        )
    }

    It 'scores a run by the proportion of controls in the desired state' {
        $summary = Get-HardeningSummary -Result $script:Results
        $summary.Total | Should -Be 2
        $summary.Remediated | Should -Be 1
        $summary.Drift | Should -Be 1
        $summary.ScorePercent | Should -Be 50
    }

    It 'reports a zero score rather than dividing by zero when nothing ran' {
        (Get-HardeningSummary -Result @()).ScorePercent | Should -Be 0
    }

    It 'notes that a reboot is needed only when a reboot-bearing control actually changed' {
        (Get-HardeningSummary -Result $script:Results).NeedsReboot | Should -BeFalse

        $rebooted = $script:Results | ForEach-Object { $_.PSObject.Copy() }
        $rebooted[1].Changed = $true
        (Get-HardeningSummary -Result $rebooted).NeedsReboot | Should -BeTrue
    }

    It 'escapes HTML so a hostile value cannot inject markup into the report' {
        ConvertTo-HtmlText -Text '<script>alert(1)</script>' | Should -Be '&lt;script&gt;alert(1)&lt;/script&gt;'
        ConvertTo-HtmlText -Text 'a & b' | Should -Be 'a &amp; b'
        ConvertTo-HtmlText -Text $null | Should -Be ''
    }

    It 'writes a self-contained HTML report' {
        $path = Join-Path ([IO.Path]::GetTempPath()) "kcm-report-$([guid]::NewGuid()).html"
        try {
            Export-HardeningReport -Path $path -Mode 'Audit' -Result $script:Results -Facts $script:Facts

            Test-Path -LiteralPath $path | Should -BeTrue
            $html = Get-Content -LiteralPath $path -Raw

            $html | Should -Match '<!DOCTYPE html>'
            $html | Should -Match 'TESTHOST'
            $html | Should -Match 'FWL-001'
            $html | Should -Match 'CRD-002'
            $html | Should -Match 'BitLocker'
            $html | Should -Not -Match '<link|<script src'
        } finally {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }

    It 'writes a machine-readable JSON report' {
        $path = Join-Path ([IO.Path]::GetTempPath()) "kcm-report-$([guid]::NewGuid()).json"
        try {
            Export-HardeningJson -Path $path -Mode 'Audit' -Result $script:Results -Facts $script:Facts

            $data = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            $data.Mode | Should -Be 'Audit'
            $data.Summary.Total | Should -Be 2
            @($data.Controls).Count | Should -Be 2
            $data.Host.ComputerName | Should -Be 'TESTHOST'
        } finally {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Sweep findings' {

    It 'rejects a severity outside the defined scale' {
        { New-SweepFinding -Id 'X' -Severity 'Catastrophic' -Title 't' -Detail 'd' } | Should -Throw
    }

    It 'records when the observation was made' {
        $f = New-SweepFinding -Id 'SWP-TEST-01' -Severity 'High' -Title 't' -Detail 'd' -Recommendation 'r'
        $f.ObservedUtc | Should -Not -BeNullOrEmpty
        [datetime]::Parse($f.ObservedUtc) | Should -BeOfType [datetime]
    }
}
