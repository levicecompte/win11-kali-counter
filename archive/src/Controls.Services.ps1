<#
    Controls.Services.ps1 - Attack-surface reduction for services, legacy engines
    and removable media.
#>

function Get-ServiceControl {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    New-ServiceControl -Id 'SVC-001' -Name 'WebClient (WebDAV) service disabled' -ServiceName 'WebClient' -Category 'Services' -Tier 'Baseline' `
        -Counters @('ntlmrelayx WebDAV', 'PetitPotam', 'PrinterBug', 'SMB-to-HTTP relay') `
        -Rationale 'WebClient is what lets a UNC path fall back to HTTP, and that fallback is how an attacker converts a coerced authentication into an HTTP NTLM relay - the path that survives SMB signing. Disabling it removes an entire relay family.' `
        -Impact 'Mapping WebDAV or SharePoint drives by UNC path stops working. Browser-based access is unaffected.'

    New-ServiceControl -Id 'SVC-002' -Name 'Print Spooler disabled' -ServiceName 'Spooler' -Category 'Services' -Tier 'Aggressive' `
        -Counters @('PrintNightmare (CVE-2021-34527)', 'impacket printerbug', 'SpoolSample coercion') `
        -Rationale 'The spooler exposes a remotely reachable RPC interface with a long history of RCE and a reliable authentication-coercion primitive. If this host does not print, the service should not run.' `
        -Impact 'All printing stops, including print-to-PDF. Only apply this to machines that genuinely never print.'

    New-ServiceControl -Id 'SVC-003' -Name 'SSDP Discovery disabled' -ServiceName 'SSDPSRV' -Category 'Services' -Tier 'Standard' `
        -Counters @('evil-ssdp', 'nmap broadcast-upnp-info', 'UPnP enumeration') `
        -Rationale 'SSDP broadcasts what this machine is and what it runs, and evil-ssdp answers those broadcasts with phishing templates that harvest credentials.' `
        -Impact 'Discovery of UPnP media devices (DLNA servers, some smart TVs) stops working.'

    New-ServiceControl -Id 'SVC-004' -Name 'UPnP Device Host disabled' -ServiceName 'upnphost' -Category 'Services' -Tier 'Standard' `
        -Counters @('UPnP enumeration', 'port-mapping abuse') `
        -Rationale 'Hosting UPnP devices lets software punch holes in the perimeter router without asking you.' `
        -Impact 'Applications that rely on automatic router port-forwarding will need manual configuration.'

    New-ServiceControl -Id 'SVC-005' -Name 'Function Discovery Resource Publication disabled' -ServiceName 'FDResPub' -Category 'Services' -Tier 'Standard' `
        -Counters @('WSD enumeration', 'nmap service scan', 'network neighbourhood recon') `
        -Rationale 'This is the service that advertises the machine to Network Neighbourhood and WSD scanners, handing an attacker the hostname, OS and service list for free.' `
        -Impact 'The machine no longer appears under Network in File Explorer for other devices.'

    New-ServiceControl -Id 'SVC-006' -Name 'Link-Layer Topology Discovery responder disabled' -ServiceName 'lltdsvc' -Category 'Services' -Tier 'Standard' `
        -Counters @('network mapping', 'LLTD topology discovery') `
        -Rationale 'LLTD answers link-layer mapping requests and reveals topology position to anyone on the segment.' `
        -Impact 'The Windows network map feature no longer shows this device.'

    New-ServiceControl -Id 'SVC-007' -Name 'Secondary Logon service disabled' -ServiceName 'seclogon' -Category 'Services' -Tier 'Aggressive' `
        -Counters @('runas credential use', 'some UAC bypass chains', 'token manipulation') `
        -Rationale 'Secondary Logon is the mechanism behind runas and a component in several privilege-escalation chains. Workstations with a single interactive user rarely need it.' `
        -Impact 'The "Run as different user" option stops working, which some legitimate admin workflows rely on.'

    New-OptionalFeatureControl -Id 'SVC-008' -Name 'SMBv1 feature removed' -FeatureName @('SMB1Protocol', 'SMB1Protocol-Client', 'SMB1Protocol-Server') -Category 'Services' -Tier 'Baseline' `
        -Counters @('EternalBlue / MS17-010', 'nmap smb-vuln-ms17-010', 'SMBGhost scanners') `
        -Rationale 'The registry switch stops SMBv1 being negotiated; removing the optional feature takes the vulnerable driver and binaries off the disk entirely so they cannot be re-enabled by a misconfiguration.' `
        -Impact 'Pre-2008 NAS devices and some network scanners become unreachable. Requires a reboot.'

    New-OptionalFeatureControl -Id 'SVC-009' -Name 'PowerShell 2.0 engine removed' -FeatureName @('MicrosoftWindowsPowerShellV2', 'MicrosoftWindowsPowerShellV2Root') -Category 'Services' -Tier 'Baseline' `
        -Counters @('powershell -version 2 downgrade', 'AMSI bypass', 'script block logging evasion') `
        -Rationale 'The v2 engine predates AMSI, script block logging and the constrained language mode, so "powershell.exe -version 2" is a one-flag bypass for the entire PowerShell telemetry stack. Removing the engine closes it.' `
        -Impact 'Scripts that explicitly require the v2 engine stop working. In practice nothing modern does.'

    New-RegistryControl -Id 'SVC-010' -Name 'AutoRun and AutoPlay disabled on all drive types' -Category 'Services' -Tier 'Baseline' `
        -Counters @('malicious USB payload', 'autorun.inf droppers', 'USB drop attacks') `
        -Rationale 'Removable media is the standard way past a network perimeter. NoDriveTypeAutoRun 255 covers every drive class including network and removable, and NoAutorun stops autorun.inf being honoured at all.' `
        -Impact 'Inserting media no longer offers to run anything automatically. You can still browse it manually.' `
        -Setting @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoDriveTypeAutoRun'; Value = 255; Label = 'NoDriveTypeAutoRun' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoAutorun'; Value = 1; Label = 'NoAutorun' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoAutoplayfornonVolume'; Value = 1; Label = 'AutoPlay for non-volume devices' }
    )

    New-RegistryControl -Id 'SVC-011' -Name 'Windows Script Host disabled' -Category 'Services' -Tier 'Aggressive' `
        -Counters @('.vbs/.js droppers', 'wscript payload stagers', 'HTA loaders') `
        -Rationale 'cscript and wscript execute arbitrary code with no logging worth the name and are a favourite first-stage loader. Very little modern software needs them.' `
        -Impact 'Any .vbs, .js or .wsf script, including some installers and corporate login scripts, stops running.' `
        -Setting @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'; Name = 'Enabled'; Value = 0; Label = 'Windows Script Host' }
        @{ Path = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows Script Host\Settings'; Name = 'Enabled'; Value = 0; Label = 'Windows Script Host (32-bit)' }
    )

    New-RegistryControl -Id 'SVC-012' -Name 'Network discovery and workgroup browsing restricted' -Category 'Services' -Tier 'Standard' `
        -Counters @('network recon', 'host enumeration') `
        -Rationale 'Stops the machine advertising itself through the legacy computer browser and master-browser elections, which is free reconnaissance for anyone already on the segment.' `
        -Impact 'The machine stops appearing in legacy network browse lists.' `
        -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'Hidden'; Value = 1; Label = 'Hide from browse list' }
    )
}
