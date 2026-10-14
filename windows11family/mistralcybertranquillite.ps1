<#
.SYNOPSIS
    Windows 11 hardening script for a gaming PC (Edge browsing + World of Warcraft
    + Heroes of the Storm) that counters the attack-technique categories exercised
    by common red-team / pentest / AI-security tooling vendors:
      - Pentest/BAS platforms (Horizon3 NodeZero, XBOW, Pentera, Cobalt):
        SMB relay & guest access, credential dumping, lateral movement (PsExec/WMI),
        LOLBins, macros from the internet, vulnerable drivers, ransomware behavior.
      - AI/LLM red-team tooling (Mindgard, Lakera, Promptfoo, Garak, PyRIT):
        delivered to an endpoint through the same initial-access channels
        (phishing payloads, obfuscated scripts, drive-by downloads, local model servers
        exposed on well-known ports).
    NO SCRIPT CAN NEUTRALIZE A FULL PENTEST PLATFORM - this one shrinks the local
    attack surface so the techniques those vendors automate mostly have nothing
    to attach to on this machine.

.DESCRIPTION
    What it does:
      1. Verifies admin rights and creates a System Restore point (rollback!).
      2. Microsoft Defender: real-time + cloud + network protection, PUA blocking,
         and 12 ASR rules in Block mode (macro abuse, PSExec/WMI, LSASS dumping,
         obfuscated scripts, USB autoexec, ransomware behavior, vulnerable drivers).
      3. Firewall:
         - Inbound BLOCK rules: SMB (445), NetBIOS (137-139), RDP (3389),
           WinRM (5985/5986), and common locally-exposed AI/model-server ports
           (11434 Ollama, 1234 LM Studio, 5000/8000/7860/8080 webui/agents).
         - Outbound ALLOW rules for msedge.exe, Battle.net.exe, Agent.exe,
           Wow.exe, WowClassic.exe, HeroesOfTheStorm.exe.
         - Optional -StrictFirewall: default outbound Block + explicit allowlist
           (system services, DNS, Edge, Blizzard games only).
      4. Network hardening: SMBv1 off, SMB signing required, LLMNR/NBT-NS/WPAD
         off (Responder-style poisoning), RDP/WinRM/RemoteRegistry disabled.
      5. Script-host hardening: WScript/HS script hosts blocked for VBS/JS,
         Office macros from the internet force-blocked, PowerShell 2.0 engine off,
         PowerShell script-block logging + transcription on.
      6. Credential hardening: LSA Protection (RunAsPPL), WDigest plaintext off,
         UAC secure-desktop prompts, network-level auth if RDP is ever re-enabled.
      7. Advanced audit policies (process creation w/ command line, logon events)
         so any residual technique leaves forensic traces.

.PARAMETER StrictFirewall
    Switch outbound firewall default to Block and allow only whitelisted apps
    (Edge, Blizzard games, Battle.net) plus core Windows services and DNS/NTP.
    Aggressive: will silently break other apps' internet access (that is the point).

.PARAMETER SkipRestorePoint
    Skip creating the System Restore point (not recommended).

.EXAMPLE
    .\Win11-Gaming-Hardening.ps1                     # standard hardening
    .\Win11-Gaming-Hardening.ps1 -StrictFirewall     # outbound allowlist too
#>

#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$StrictFirewall,
    [switch]$SkipRestorePoint
)

$ErrorActionPreference = 'Stop'
$Log = Join-Path $env:TEMP ("Win11-Hardening-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Start-Transcript -Path $Log -IncludeInvocationHeader | Out-Null

function Write-Section([string]$t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type)
    # Auto-detect registry type when not forced: numbers -> DWord, strings -> String
    if (-not $Type) {
        $Type = if ($Value -is [int] -or $Value -is [long] -or ($Value -is [string] -and $Value -match '^\d+$')) { 'DWord' } else { 'String' }
    }
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Write-Host ("  [reg] {0}\{1} = {2} ({3})" -f $Path, $Name, $Value, $Type)
}
function New-BlockRule {
    param([string]$Name, [string[]]$Ports, [string]$Protocol = 'TCP')
    New-NetFirewallRule -DisplayName $Name -Direction Inbound -Action Block `
        -Protocol $Protocol -LocalPort $Ports -Profile Any | Out-Null
    Write-Host ("  [fw ] block inbound {0} : {1}" -f $Protocol, ($Ports -join ','))
}

Write-Host "Windows 11 gaming-PC hardening - $(Get-Date)" -ForegroundColor Green
Write-Host "Log: $Log"

# ---------------------------------------------------------------------------
# 0. Rollback anchor
# ---------------------------------------------------------------------------
Write-Section "0. System restore point"
if (-not $SkipRestorePoint) {
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description "Before Win11 gaming hardening" -RestorePointType MODIFY_SETTINGS
        Write-Host "  Restore point created (use it to roll back)."
    } catch { Write-Warning "Could not create restore point: $_" }
} else { Write-Host "  Skipped by parameter." }

# ---------------------------------------------------------------------------
# 1. Defender + ASR rules  (counters: macro/phishing payload execution,
#    PsExec/WMI lateral movement, LSASS/Mimikatz dumping, obfuscated-script
#    payloads, USB autorun malware, ransomware behavior, vulnerable drivers)
# ---------------------------------------------------------------------------
Write-Section "1. Microsoft Defender hardening"
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableScriptScanning $false
Set-MpPreference -EnableNetworkProtection Enabled
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendSafeSamples
Set-MpPreference -PUAProtection 1
Write-Host "  Real-time, behavior, script, network, cloud, PUA protection: ON"

# ASR rules: GUID -> short technique label
$asr = @{
    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'Office apps creating child processes (macro droppers)'
    '3B576869-A4EC-4529-8536-B80A7769E899' = 'Office apps creating executable content'
    '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' = 'Office apps injecting code into other processes'
    '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 'Win32 API calls from Office macros (fileless payloads)'
    'D3E037E1-3EB8-44C8-A917-57927947596D' = 'JS/VBScript launching downloaded executables'
    '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'Obfuscated script execution'
    '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' = 'Credential stealing from LSASS (Mimikatz-class)'
    'D1E49AAC-8F56-4280-B9BA-993A6D77406C' = 'Process creation via PsExec/WMI (lateral movement)'
    'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4' = 'Untrusted/unsigned processes from USB'
    'C1DB55AB-C21A-4637-BB3F-A12568109D35' = 'Ransomware behavior (advanced protection)'
    '56A863A9-875E-4185-98A7-B882C64B5CE5' = 'Abuse of exploited vulnerable signed drivers'
    'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 'Executable content from email/webmail'
}
$guids = @($asr.Keys)
Set-MpPreference -AttackSurfaceReductionRules_Ids $guids
Set-MpPreference -AttackSurfaceReductionRules_Actions ($guids | ForEach-Object { 1 })  # 1 = Block
foreach ($g in $guids) { Write-Host ("  [asr] {0} -> {1}" -f $g, $asr[$g]) }

# ---------------------------------------------------------------------------
# 2. Firewall: block pentest-entry ports inbound, whitelist game/browser apps
# ---------------------------------------------------------------------------
Write-Section "2. Firewall rules"

# 2a. Inbound blocks (SMB relay/capture, NetBIOS poisoning, RDP/WinRM takeover)
New-BlockRule -Name 'HARD-SMB'          -Ports 445
New-BlockRule -Name 'HARD-NetBIOS-UDP'  -Ports 137,138,139 -Protocol UDP
New-BlockRule -Name 'HARD-NetBIOS-TCP'  -Ports 139
New-BlockRule -Name 'HARD-RDP'          -Ports 3389
New-BlockRule -Name 'HARD-WinRM'        -Ports 5985,5986

# 2b. Locally-exposed AI/model servers (target of LLM tooling: Ollama 11434,
#     LM Studio 1234, Flask/FastAPI 5000/8000, Gradio 7860, generic webui 8080)
New-BlockRule -Name 'HARD-LLM-Servers' -Ports 11434,1234,5000,8000,7860,8080

# 2c. Outbound allow rules for allowed apps (done BEFORE strict mode so they win)
$blizzardRoots = @(
    'C:\Program Files (x86)\World of Warcraft',
    'C:\Program Files (x86)\Blizzard App',
    "$env:ProgramData\Battle.net",
    "$env:ProgramData\Blizzard Entertainment"
)
$allowedNames = @(
    'msedge.exe', 'Battle.net.exe', 'Agent.exe', 'Battle.net Update Agent.exe',
    'Wow.exe', 'WowClassic.exe', 'WowT.exe', 'HeroesOfTheStorm.exe'
)
$allowedFound = New-Object System.Collections.Generic.List[string]
foreach ($root in $blizzardRoots) {
    if (-not (Test-Path $root)) { continue }
    foreach ($exe in (Get-ChildItem -Path $root -Recurse -Filter *.exe -ErrorAction SilentlyContinue |
                      Where-Object { $allowedNames -contains $_.Name })) {
        $allowedFound.Add($exe.FullName)
    }
}
$edgePath = (Get-ChildItem 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe' -ErrorAction SilentlyContinue).FullName
if ($edgePath) { $allowedFound.Add($edgePath) }

foreach ($p in ($allowedFound | Select-Object -Unique)) {
    New-NetFirewallRule -DisplayName ("HARD-ALLOW {0}" -f (Split-Path $p -Leaf)) `
        -Direction Outbound -Action Allow -Program $p -Profile Any | Out-Null
    Write-Host ("  [fw ] allow outbound: {0}" -f $p)
}

# 2d. Optional strict outbound allowlist
if ($StrictFirewall) {
    Write-Host "  StrictFirewall ON - outbound default becomes Block." -ForegroundColor Yellow
    # Core system services need outbound (Windows Update, DNS, licensing, Store, NTP)
    New-NetFirewallRule -DisplayName 'HARD-ALLOW System svchost' -Direction Outbound `
        -Action Allow -Program "$env:SystemRoot\System32\svchost.exe" -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName 'HARD-ALLOW System binaries' -Direction Outbound `
        -Action Allow -Program "$env:SystemRoot\System32\*.exe" -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName 'HARD-ALLOW DNS' -Direction Outbound -Action Allow `
        -Protocol UDP -RemotePort 53 -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName 'HARD-ALLOW NTP' -Direction Outbound -Action Allow `
        -Protocol UDP -RemotePort 123 -Profile Any | Out-Null
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
    Write-Host "  Outbound default = Block. Only whitelisted traffic leaves." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 3. Network protocol hardening (counters: SMB relay, LLMNR/NBT-NS poison,
#    WPAD hijack, SMBv1 exploits, remote-management takeover)
# ---------------------------------------------------------------------------
Write-Section "3. Network protocol hardening"
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Write-Host "  SMBv1 disabled, SMB signing required"

Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'DisableSmartNameResolution' 1
$nb = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
if (Test-Path $nb) {
    foreach ($p in (Get-ChildItem $nb | Where-Object { $_.PSChildName -match 'Interface' })) {
        Set-Reg $p.PSPath 'NetbiosOptions' 2
    }
}
Write-Host "  LLMNR, NetBIOS name resolution disabled"

Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinHttp\Proxy' 'AutoDetect' 0
Write-Host "  WPAD auto-detect disabled"

foreach ($svc in 'TermService','WinRM','RemoteRegistry','SSDPSRV','upnphost') {
    try {
        Stop-Service $svc -Force -ErrorAction SilentlyContinue
        Set-Service $svc -StartupType Disabled -ErrorAction Stop
        Write-Host ("  [svc] {0} disabled" -f $svc)
    } catch { Write-Host ("  [svc] {0}: {1}" -f $svc, $_.Exception.Message) }
}
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1

# ---------------------------------------------------------------------------
# 4. Script hosts, macros, PowerShell 2.0  (counters: WSH-based droppers,
#    internet-delivered VBS/JS payloads, legacy PowerShell downgrade attacks)
# ---------------------------------------------------------------------------
Write-Section "4. Script host & macro hardening"
# VBS/JS no longer run through Windows Script Host (breaks legacy .vbs/.js apps)
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled' 0
Set-Reg 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows Script Host\Settings' 'Enabled' 0
Write-Host "  Windows Script Host (WScript/CScript for VBS/JS) disabled"

# Office: block macros from the internet (VBAWarnings: 4 = force block)
foreach ($app in 'Word','Excel','PowerPoint','Outlook','Access','OneNote','Publisher','Project','Visio') {
    Set-Reg ("HKCU:\SOFTWARE\Microsoft\Office\16.0\{0}\Security" -f $app) 'VBAWarnings' 4
}
Write-Host "  Office macros from the internet force-blocked"

# PowerShell: remove legacy v2 engine (downgrade/CLS bypass), keep v5+ with logging
$ps2 = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' -ErrorAction SilentlyContinue
if ($ps2 -and $ps2.State -eq 'Enabled') {
    Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' -NoRestart | Out-Null
    Write-Host "  PowerShell 2.0 engine disabled"
}
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting' 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'OutputDirectory' 'C:\ProgramData\PSTranscripts'
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableInvocationHeader' 1
Write-Host "  PowerShell script-block logging + transcription enabled"

# ---------------------------------------------------------------------------
# 5. Credentials & UAC (counters: LSASS memory scraping, plaintext capture
#    via WDigest, token abuse, silent privilege escalation)
# ---------------------------------------------------------------------------
Write-Section "5. Credential & UAC hardening"
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
Write-Host "  LSA Protection (RunAsPPL), no LM hashes, WDigest plaintext off"

Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 2
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop' 1
Write-Host "  UAC: secure desktop, always prompt for elevation"

# SmartScreen on everything (string value!)
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled' 'Block'
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoAutoplayfornonVolume' 1
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableThirdPartySuggestions' 1
Write-Host "  SmartScreen = Block, AutoRun/AutoPlay disabled"

# ---------------------------------------------------------------------------
# 6. Audit policy (so anything that still gets through leaves traces)
# ---------------------------------------------------------------------------
Write-Section "6. Advanced audit policy"
# NOTE: auditpol subcategory NAMES are localized (French Windows expects
# "Création de processus", etc.) and English names fail with 0x00000057.
# GUIDs (from Ntsecapi.h auditing constants) work on any language.
try {
    $audit = @(
        @{ g = '{0cce922b-69ae-11d9-bed3-505054503030}'; n = 'Process Creation' },
        @{ g = '{0cce9215-69ae-11d9-bed3-505054503030}'; n = 'Logon' },
        @{ g = '{0cce9216-69ae-11d9-bed3-505054503030}'; n = 'Logoff' },
        @{ g = '{0cce921b-69ae-11d9-bed3-505054503030}'; n = 'Special Logon' },
        @{ g = '{0cce921c-69ae-11d9-bed3-505054503030}'; n = 'Other Logon/Logoff Events' },
        @{ g = '{0cce9210-69ae-11d9-bed3-505054503030}'; n = 'Security State Change' }
    )
    foreach ($a in $audit) {
        auditpol /set /subcategory:"$($a.g)" /success:enable /failure:enable | Out-Null
        Write-Host ("  [aud] {0} -> success+failure" -f $a.n)
    }
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
    Write-Host "  Process creation (with command line), logon events audited"
} catch { Write-Warning "Audit policy step failed: $_" }

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Section "Done"
if ($StrictFirewall) {
    Write-Host "  Strict mode: if an app loses internet, that is the allowlist working." -ForegroundColor Yellow
    Write-Host "  To re-allow an app: New-NetFirewallRule -DisplayName 'ALLOW x' -Direction Outbound -Action Allow -Program 'C:\path\to\app.exe'"
}
Write-Host "  Log saved to: $Log"
Write-Host "  Reboot recommended for all settings to take effect."
Stop-Transcript | Out-Null
Write-Host "`nReboot recommended. Gaming on Edge, WoW and HotS stays allowed." -ForegroundColor Green