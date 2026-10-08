# Anti-Auto-Attack for Windows 11

A single-file defensive PowerShell script that audits and hardens a Windows 11
machine against AI-orchestrated autonomous pentest frameworks such as
[saltless-bruh/ai-auto-attack-framework](https://github.com/saltless-bruh/ai-auto-attack-framework)
(recon → vuln scan → exploitation → lateral movement → data extraction).

No dependencies. No network calls. No telemetry. One file:
`Invoke-AntiAutoAttack.ps1`.

## What it counters

That framework orchestrates commodity tooling. This script closes the exact
doors those tools need on a Windows 11 workstation:

| Framework stage / tools | What this script does |
|---|---|
| Recon: `nmap`, `masscan`, `dnsenum`, OS/service fingerprinting | Firewall profiles ON + inbound Block, dropped-packet logging ON, listener audit (RDP/WinRM/SSH/C2 ports), established-C2 check |
| Vuln scanning: `nuclei`, `openvas` vs exposed SMB/RDP/WinRM/HTTP | Hotfix-recency check, SMBv1 OFF + SMB signing required, RDP NLA or OFF, minimal listener surface |
| Exploitation: `metasploit` (SMB/RDP/browser), malicious docs | Defender realtime+cloud+behavior+network ON, ASR rules (LSASS theft Block, Office/Adobe child-process Audit), SmartScreen check, HVCI/Memory-integrity check, AutoRun OFF |
| Credential attacks: `hydra`, `john` vs RDP/SMB/WinRM/SSH | Lockout 5/15/15, Guest OFF, admin-membership review, 4625 brute-force hunt grouped by IP, optional `-BlockBruteForcers` firewall block, RDP NLA enforcement |
| Lateral / exec: WinRM/`pywinrm`, SSH/`paramiko`, PsExec/WMI/tasks | WinRM + OpenSSH-Server + PS Remoting disabled unless `-KeepRemoteAccess`, WMI subscription hunt, scheduled-task + service + Run-key + Startup-folder hunts |
| Living-off-the-land + encoded payloads | ScriptBlock + Module logging ON, command-line in 4688 ON, Logon/Process/Account auditpol to Success+Failure, Sysmon presence check |
| Name-resolution poisoning (Responder-style) | LLMNR OFF via policy, NetBIOS Disable (2), WPAD/DNS/hosts-file review |
| C2 / exfil (reverse shells, DNS tunnel) | Suspicious-process hunt (nmap/masscan/nuclei/sqlmap/hydra/meterpreter/mimikatz/...), C2-port listener + established-link checks, DNS/hosts review, JSON+TXT report |

## Quick start (on Windows 11)

```powershell
# 1. Read-only audit first (run as Administrator for full coverage)
powershell -ExecutionPolicy Bypass -File .\Invoke-AntiAutoAttack.ps1 -Mode Audit

# 2. Preview hardening without changing anything
powershell -ExecutionPolicy Bypass -File .\Invoke-AntiAutoAttack.ps1 -Mode Harden -WhatIf

# 3. Safe hardening that keeps remote management working
powershell -ExecutionPolicy Bypass -File .\Invoke-AntiAutoAttack.ps1 -Mode Harden -KeepRemoteAccess -EnableASRRules

# 4. Full lockdown incl. RDP off + auto-block brute-force IPs (10+ failures/24h)
powershell -ExecutionPolicy Bypass -File .\Invoke-AntiAutoAttack.ps1 -Mode Harden -DisableRDP -BlockBruteForcers -EnableASRRules -Force
```

Reports land on the Desktop (fallback `$env:TEMP`):
`AntiAutoAttack-Report-<timestamp>.json` + `.txt`.

Exit codes: `1` = at least one FAIL finding, `0` = warnings-or-clean.

## Flags

- `-Mode Audit|Harden` — Audit changes nothing. Harden is idempotent, honors
  `-WhatIf`, logs every change, never forces a reboot.
- `-KeepRemoteAccess` — skip disabling WinRM / OpenSSH-Server / PS Remoting.
- `-DisableRDP` — turn RDP fully off (default just enforces NLA).
- `-EnableASRRules` — set 9 Defender ASR rules (3 Block: LSASS theft, USB
  unsigned, email executables; 6 Audit: Office/Adobe/WMI/JS-VBS). Without it,
  ASR is audit-only.
- `-BlockBruteForcers` — firewall-block IPs with 10+ Event 4625 in 24h.
- `-ReportPath <folder>` — where to write reports.
- `-Force` — skip the HARDEN confirmation prompt.

## Safety notes

- Audit mode is strictly read-only — safe to run on any machine.
- Harden mode needs Administrator, prompts for `HARDEN` confirmation (unless
  `-Force`/`-WhatIf`), and requires a reboot only for LSA Protection (PPL) to
  take effect.
- The script never installs Sysmon — it only checks for it. Install Sysmon with
  the SwiftOnSecurity config for the best detection of automated agents.
- Re-run Audit after Patch Tuesday, after enabling RDP/SSH, or after any
  FAIL finding is remediated.

## Files

- `Invoke-AntiAutoAttack.ps1` — the whole tool (comment-based help included;
  try `Get-Help .\Invoke-AntiAutoAttack.ps1 -Full`).
- `README.md` — this file.

Defensive use only: audit and harden systems you own or are authorized to
protect.
