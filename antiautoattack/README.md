# AiAttackCounter

A single PowerShell script that hardens and monitors a **Windows 11** machine against
[saltless-bruh/ai-auto-attack-framework](https://github.com/saltless-bruh/ai-auto-attack-framework),
an AI-orchestrated pentest framework, and against the toolchain it drives.

The framework plans an engagement with LLMs, then runs ordinary offensive tools through MCP servers.
`AiAttackCounter.ps1` does not try to recognize the AI. It breaks each stage of the kill chain the framework automates:

| Framework stage / tool | What the script does |
| --- | --- |
| Recon: nmap, masscan, dnsenum | Default-deny inbound on every firewall profile, blocks ICMP echo, disables NetBIOS / LLMNR / mDNS / SSDP / UPnP, disables discovery rule groups, logs dropped packets. **Monitor** parses that log and flags any source probing many ports (optionally auto-blocks it). |
| Vulnerability scanning: Nuclei, OpenVAS, sqlmap | Reports exposed listeners (including Ollama on 11434, databases, RDP, WinRM) and patch age, since unpatched CVEs are what scanners find first. |
| Exploitation: Metasploit | Defender real-time, behavior, cloud (high), PUA and network protection; Attack Surface Reduction rules (LSASS theft, PsExec/WMI, obfuscated scripts, Office/mail payloads, vulnerable drivers); system-wide DEP / SEHOP / ASLR; AutoRun off; SMBv1 off. |
| Credential attacks: Hydra, John | Account lockout (5 attempts / 30 min), 14-character minimum, NTLMv2-only, no LM hashes, no WDigest cleartext, LSA as protected process, blank-password and Guest checks. **Monitor** detects brute force and password spraying from event 4625 and raises a **critical** alert if the same source then logs on successfully. |
| Command execution: SSH (paramiko), WinRM (pywinrm) | Disables `sshd`, WinRM, inbound RDP and remote-management firewall groups (or scopes them to trusted addresses with `-KeepRemoteAdmin`), requires NLA, refuses Basic/unencrypted WinRM, blocks remote token abuse of local admins, requires SMB signing, disables the Server service unless `-KeepFileSharing`. |
| Lateral movement, persistence | **Monitor** alerts on PsExec/Metasploit-style service installs (event 7045), new local users, additions to Administrators, cleared security logs, Defender detections, offensive tools or the framework's own CLI/MCP servers running locally, and connections or listeners on common reverse-shell ports. |

## Requirements

- Windows 11, elevated PowerShell (Windows PowerShell 5.1 or PowerShell 7)
- Microsoft Defender as the active antivirus for the Defender/ASR section (use `-SkipDefender` otherwise)

## Usage

```powershell
# 1. See where you stand. Read-only.
.\AiAttackCounter.ps1

# 2. Preview every change Harden would make.
.\AiAttackCounter.ps1 -Action Harden -DryRun

# 3. Apply. Creates a restore point and journals every original value.
.\AiAttackCounter.ps1 -Action Harden

# 4. Turn on continuous detection (runs as SYSTEM every 5 minutes).
.\AiAttackCounter.ps1 -Action InstallMonitor -AutoBlock

# Revert everything Harden changed.
.\AiAttackCounter.ps1 -Action Undo
```

If the script is blocked by execution policy, run `powershell -ExecutionPolicy Bypass -File .\AiAttackCounter.ps1 ...`.

### Options

| Option | Effect |
| --- | --- |
| `-KeepRemoteAdmin` | Leave RDP / WinRM / SSH / WMI usable, restricted to `-TrustedAddresses`. |
| `-KeepFileSharing` | Leave SMB sharing usable, restricted to `-TrustedAddresses`. |
| `-TrustedAddresses` | Firewall address syntax, default `LocalSubnet`. Example: `192.168.1.0/24,10.0.0.5`. |
| `-AllowPing` | Do not block inbound ICMP echo. |
| `-AsrMode AuditMode` | Log ASR hits instead of blocking. Recommended for a first week on a machine you rely on. |
| `-SkipDefender`, `-SkipAccountPolicy` | Skip those sections. |
| `-AutoBlock`, `-BlockHours`, `-NeverBlock` | Monitor: add a temporary inbound block rule for attacking sources. The local host, gateways and DNS servers are never blocked. |
| `-ScanPortThreshold`, `-FailedLogonThreshold`, `-WindowMinutes` | Monitor sensitivity. Defaults: 15 ports, 5 failed logons, 15 minutes. |
| `-DryRun`, `-Force` | Preview only / skip the confirmation prompt. |

Alerts go to the console, `%ProgramData%\AiAttackCounter\alerts.jsonl`, and the Application event log
(source `AiAttackCounter`, IDs 4000 info, 4001 warning, 4002 critical).

## What to expect after Harden

- **Reboot** once: LSA protection and some service changes only apply after restart.
- This PC stops answering ping, no longer exposes SMB/RDP/SSH/WinRM, and no longer shows up in network discovery. Use the `-Keep*` switches if you need any of that on your LAN.
- Disabling the Server service removes SMB shares and admin shares (`C$`). Use `-KeepFileSharing` if you share files from this PC.
- The ASR PsExec/WMI rule breaks tools like SCCM that rely on remote process creation.
- Some NAS devices and old Samba servers fail when SMB signing is required.
- `Undo` restores registry values, service start modes, firewall profile/rule state, account policy, audit policy, Defender settings, ASR rules and exploit-protection settings from the journal at `%ProgramData%\AiAttackCounter\state.json`. Re-running Harden never overwrites the original values in that journal.

## Limits

- It cannot enable Defender **Tamper Protection**; the audit tells you to turn it on manually.
- Firewall rule groups are matched by their English display names. On other display languages the group rules are reported as not found; the explicit port block rules still apply.
- The audit-policy check reads `auditpol` output in English; on other languages Harden just re-applies the settings.
- Port-scan detection sees only packets the firewall **drops**. Scans of ports you deliberately keep open are not visible.
- This is hardening plus detection for one host. It does not replace patching, EDR, network segmentation or MFA.
- Written and unit-tested for logic on PowerShell 7 (Linux); the Windows-only cmdlets were reviewed but not executed on a live Windows 11 machine. Run `-DryRun` first and keep the restore point.

## Development

```powershell
pwsh -File tests/Test-Detection.ps1   # log parser, scan / brute-force detection, tool heuristics
pwsh -File tests/Test-Journal.ps1     # change journal and Undo with mocked registry
```

The script can be dot-sourced (`. .\AiAttackCounter.ps1`) to load its functions without running anything.
