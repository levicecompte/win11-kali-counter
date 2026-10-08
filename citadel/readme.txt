# Citadel for Windows 11

`Win11-Citadel.ps1` is a single-file PowerShell hardening, threat-hunting and rollback tool. It targets the host-side attack techniques collected in [blaCCkHatHacEEkr/PENTESTING-BIBLE](https://github.com/blaCCkHatHacEEkr/PENTESTING-BIBLE): credential dumping, NTLM relay and Responder, UAC bypasses, PowerShell and Office payloads, lateral movement, persistence, C2 channels, Wi-Fi and USB attacks.

It is written for Windows PowerShell 5.1 and PowerShell 7 on Windows 11. Run it from an elevated, 64-bit shell.

## What it does

| Mode | What happens |
| --- | --- |
| `Audit` (default) | Read-only. Grades the machine against about 80 controls and writes CSV and JSON reports. |
| `Apply` | Enforces every failing control. Each registry value, firewall rule, optional feature, account, audit policy and AppLocker policy it changes is recorded first. |
| `Scan` | Hunts for artefacts the attacks leave behind (see below). `-Remediate` removes UAC-bypass hijacks and malicious WMI subscriptions. |
| `Rollback` | Restores the pre-`Apply` state from the newest backup (or `-BackupFile`). |

Two levels: `Standard` (low breakage) and `Strict` (adds controls that can disrupt workflows: RDP off, USB storage off, Print Spooler/WinRM off, Windows Script Host off, script file types open in Notepad, Credential Guard and HVCI, Kerberos AES-only, TLS 1.0/1.1 off, ASR rules all in block mode, Controlled Folder Access in block mode).

```powershell
# 1. See where you stand (changes nothing)
.\Win11-Citadel.ps1

# 2. Preview, then harden, and install the hourly hunter
.\Win11-Citadel.ps1 -Mode Apply -WhatIf
.\Win11-Citadel.ps1 -Mode Apply -InstallSentinel

# Stricter, with AppLocker in audit mode first
.\Win11-Citadel.ps1 -Mode Apply -Level Strict -AppLocker Audit

# Threat hunt now (exit code 2 if any High finding)
.\Win11-Citadel.ps1 -Mode Scan

# Undo
.\Win11-Citadel.ps1 -Mode Rollback
```

Output lives in `C:\ProgramData\Citadel` (locked to SYSTEM and Administrators): `reports\`, `backup\`, `bin\` (sentinel copy). A restore point is attempted before `Apply`.

## Coverage map

| Bible topic | Controls (module) |
| --- | --- |
| NTDS.dit / SAM / hash extraction, Mimikatz, WDigest, LSASS | WDigest off, LSASS PPL, ASR "credential stealing from LSASS", Credential Guard (Strict), cached logons, remote SAM restriction, hunt for `ntdsutil`/`vssadmin`/`reg save`/`comsvcs MiniDump`/`sekurlsa` in 4688 command lines, rogue LSA packages (mimilib/memssp) |
| Responder, LLMNR/NBT-NS, SCF/Bad-PDF/Office UNC hash theft, NTLM relay, WPAD, mitm6 | LLMNR/mDNS/NetBIOS/WPAD off, SMB and LDAP signing, NTLMv2-only, NTLM auditing, outbound SMB/NetBIOS to the Internet blocked, DHCPv6 block (Strict), UNC hardening, WebClient off |
| UAC bypasses (eventvwr, sdclt, fodhelper, slui, disk cleanup, COM hijack) | UAC at maximum with secure desktop, token filtering, hunt and auto-remove of the HKCU class hijack keys, `%windir%` overrides and per-user COM hijacks |
| Windows privilege escalation (unquoted paths, AlwaysInstallElevated, weak ACLs, Potato, PrintNightmare, DLL hijacking) | Unquoted service paths fixed, AlwaysInstallElevated off, Spooler remote RPC and driver install locked down, DLL search hardening, AppInit_DLLs off, hunt for writable service binaries and PATH dirs, unattend credentials |
| PowerShell payloads, Empire, AMSI/AppLocker bypass, PowerShell without PowerShell | Script block, module and transcription logging, PowerShell 2.0 removed, ASR obfuscated-script and download rules, hunt for offensive script blocks and encoded cradles, LOLBin outbound block, AppLocker policy, Windows Script Host and script file association lockdown (Strict) |
| Office macros, DDE, Protected View, ActiveX, XLL, spear phishing, Evilginx | Internet macro block, VBA policy, DDE and ActiveX off, Outlook rule protection, ASR Office rules, Enhanced Phishing Protection, SmartScreen, Edge and Chrome policies |
| Lateral movement (DCOM, WMI, PsExec, WinRM, RDP pivoting, admin shares) | DCOM hardening, WinRM hardening, RDP NLA/TLS, admin shares off (Strict), firewall port blocks, ASR PsExec/WMI rule, hunt for PsExec-style service installs |
| Persistence (Run keys, startup, tasks, WMI, IFEO, Winlogon, sticky keys, BITS) | Sentinel hunts every one of these and auto-removes WMI consumers with `-Remediate`; WMI persistence ASR rule |
| C2 over DNS, WebDAV, WebSocket, HTTPS, WMI, Twitter, kernel | WebClient off, LOLBin egress block, Network Protection, DNS-Client logging plus DNS-tunnel heuristic, hunt for LOLBin outbound connections and attack-framework ports, vulnerable-driver blocklist and HVCI for kernel implants |
| Wi-Fi cracking, rogue AP (WiFi-Pumpkin), CoffeeMiner, Wi-Fi post-exploitation | Auto-connect to open networks disabled (or profiles deleted with `-PurgeOpenWifi`), Wi-Fi Sense off, TLS floor |
| USB Rubber Ducky, USBStealer, DMA, lock-screen clipboard | AutoRun/AutoPlay off, USB storage blocked (Strict), Kernel DMA and BitLocker DMA-under-lock, ASR untrusted-USB rule, lock-screen leak closures |
| Windows kernel exploits, ASLR bypass, memory hacking | System-wide DEP/SEHOP/ASLR, mandatory ASLR (Strict), HVCI, Windows Update posture check |
| Firewall monitoring | All profiles on, inbound default block, dropped-packet logging |
| FTP/Telnet/TFTP/SMBv1 | Services disabled and optional features removed |
| Web attacks on an IIS host (exposed `.git`, XSS/clickjacking headers, TRACE, directory browsing, double-escape WAF bypass) | IIS request filtering, hidden segments, security headers (when IIS is installed) |

## The sentinel

`-InstallSentinel` registers `\Citadel\Citadel Sentinel` (SYSTEM, hourly and at boot). It runs `-Mode Scan -Quiet`, writes a summary to the Application event log (source `Citadel`, event IDs 4100 high, 4101 medium, 4102 clean) and saves JSON reports. Add `-Remediate` when installing to make it auto-remove UAC hijacks and WMI persistence. Findings in the event log can be forwarded to your SIEM.

## Limits

No script can "counter all" attacks in that repository. It is mostly a link list of offensive articles, and a large share of it cannot be fixed from a Windows 11 endpoint:

- **Application-layer web bugs** (SQL injection, XSS, LFI/RCE, CSRF, SSRF, open redirects, password-reset and price-manipulation flaws, WordPress and Jenkins issues) are fixed in application code, with a WAF and secure deployment. The IIS module only covers server-level exposure.
- **Network-level attacks** (ARP spoofing, Wi-Fi handshake capture, email spoofing and open relays, SSH port relays) need switch, AP and mail-server controls such as port security, WPA3 or 802.1X, and SPF/DKIM/DMARC.
- **Active Directory server-side abuse** (DCSync, DNSAdmins, ACL abuse, trusts, BloodHound paths) needs domain-controller and tiering work. Client-side mitigations are included.
- **Human attacks** (phishing, OSINT) are reduced but not removed. Use phishing-resistant MFA (FIDO2) and user training.
- **Hardware-dependent controls** (Secure Boot, TPM, BitLocker, VBS/HVCI, Tamper Protection) are reported by the Posture checks. Some can't be enabled by script.
- A hardened endpoint still needs patching, EDR and monitoring. The hunts depend on the audit logging this script enables.

## Behaviour notes

- Audit-policy checks parse `auditpol` output in English.
- Strict mode can break things on purpose. Run `Audit` and use `-Level Standard` first. `-AppLocker Audit` logs would-be blocks (Event Viewer, AppLocker logs) before you switch to `Enforce`. AppLocker enforcement needs Windows 11 Enterprise or Education.
- Reboot after `Apply` for LSA PPL, VBS, HVCI, DMA, SCHANNEL and admin-share changes.
- `Rollback` does not undo Defender settings, event-log sizes, `net accounts` policy, exploit-mitigation defaults or the removed auto-logon password (it is deliberately never written to a backup file).
- Per-user (HKCU) settings apply to the account that runs the script.
- This was developed and statically checked on Linux (parser, PSScriptAnalyzer, fake-registry apply/rollback tests). Run `Audit`, then `Apply -WhatIf`, on a test Windows 11 machine before rolling it out.