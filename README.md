# Windows 11 countermeasures against pen-testing distributions

A PowerShell toolkit that hardens Windows 11 against the attack tooling shipped with Kali
Linux and similar distributions, and that sweeps the host for evidence such tooling is
already being used against it.

It is built around a catalogue of **73 controls**. Every control knows what tooling it
defeats, why it works, and what it costs you. Every change it makes is recorded so the
whole run can be undone with one command.

**BitLocker and every other volume-encryption setting are deliberately out of scope.** The
toolkit never reads or modifies them. That exclusion is enforced in the control model
itself and checked by a test that scans the source for BitLocker cmdlets.

> An "AI-assisted Kali" workflow does not change the defence. The operator gets faster at
> choosing and chaining tools; the tools still speak SMB, LLMNR, NTLM and RPC, and they
> still need LSASS, a service install or a named pipe. This toolkit closes those, so it
> applies the same either way.

---

## Quick start

Open PowerShell **as administrator**, then:

```powershell
# 1. See what the catalogue contains and what each control would cost you
.\Invoke-KaliCountermeasures.ps1 -Mode List

# 2. Check what this machine looks like today, changing nothing
.\Invoke-KaliCountermeasures.ps1 -Mode Audit -ReportPath .\audit.html

# 3. Preview every change before committing to it
.\Invoke-KaliCountermeasures.ps1 -Mode Apply -WhatIf

# 4. Apply
.\Invoke-KaliCountermeasures.ps1 -Mode Apply

# 5. Later: hunt for an attacker already on the network
.\Invoke-KaliCountermeasures.ps1 -Mode Sweep

# 6. If something broke, undo everything
.\Invoke-KaliCountermeasures.ps1 -Mode Rollback
```

Requires Windows 11 (Windows 10 works too) and Windows PowerShell 5.1 or PowerShell 7.
`Audit`, `Sweep` and `List` run unelevated but report less; `Apply` and `Rollback` need
administrator rights.

If the script will not run at all, PowerShell's execution policy is blocking it:

```powershell
Unblock-File .\Invoke-KaliCountermeasures.ps1 -ErrorAction SilentlyContinue
powershell -ExecutionPolicy Bypass -File .\Invoke-KaliCountermeasures.ps1 -Mode Audit
```

---

## Start here, not at the end

Do not apply the Aggressive tier to a machine you depend on without reading what it does
first. A realistic sequence for a personal workstation:

```powershell
# Safe on any machine. Closes the highest-value attack paths with almost no friction.
.\Invoke-KaliCountermeasures.ps1 -Mode Apply -Tier Baseline

# Use the machine normally for a while, then tighten.
.\Invoke-KaliCountermeasures.ps1 -Mode Apply -Tier Standard

# Only on a machine you can afford to break.
.\Invoke-KaliCountermeasures.ps1 -Mode Apply -Tier Aggressive -WhatIf
```

Some controls need a restart to take effect (LSA Protection, Credential Guard, NetBIOS,
SMBv1 and PowerShell 2.0 removal). The summary tells you when that applies.

---

## Tiers

| Tier | Controls | What it means |
|---|---|---|
| `Baseline` | 38 | High value, low friction. Appropriate for any Windows 11 machine. |
| `Standard` | 61 | The default. Adds controls with a small, documented cost. |
| `Aggressive` | 73 | Maximum attack-surface reduction, with real usability costs. |

Tiers are cumulative: `Standard` includes everything in `Baseline`.

You are not stuck with a tier. `-Include` cherry-picks a single control above the ceiling,
and `-Exclude` always wins:

```powershell
# Standard, but keep the printer working and keep RDP available
.\Invoke-KaliCountermeasures.ps1 -Mode Apply -Tier Standard -Exclude SVC-002,RMT-003

# Baseline, plus just the anti-mitm6 IPv6 controls from the Aggressive tier
.\Invoke-KaliCountermeasures.ps1 -Mode Apply -Tier Baseline -Include FWL-009,PRT-011

# Only the firewall work
.\Invoke-KaliCountermeasures.ps1 -Mode Apply -Category Firewall
```

---

## What it defends against

### Name-resolution poisoning — Responder, Inveigh, mitm6

Responder works because Windows broadcasts failed DNS lookups over LLMNR, NBT-NS and mDNS
and believes the first machine that answers. The answer harvests a NetNTLMv2 hash for
offline cracking or immediate relay.

The fix is to stop asking. `PRT-001`, `PRT-002` and `PRT-003` disable the three protocols,
`FWL-003` blocks the outbound queries at the firewall so a new network adapter cannot
quietly reintroduce them, and `PRT-004` disables WPAD and sinkholes the `wpad` and `isatap`
names in the hosts file. `FWL-009` and `PRT-011` close the IPv6 variant that mitm6 uses.

### Relay and lateral movement — ntlmrelayx, CrackMapExec, impacket, PsExec

`PRT-006` requires SMB signing on both the client and the server, which is the single
control that makes SMB relay fail outright. `SVC-001` disables the WebClient service, which
removes the WebDAV fallback that converts a coerced authentication into an HTTP relay — the
path that survives SMB signing. `RMT-006` removes the `ADMIN$` and `C$` shares that every
PsExec clone writes its service binary to. `PRT-008` refuses NTLMv1 and LM entirely.

### Credential theft — mimikatz, procdump, pypykatz, secretsdump

`CRD-002` turns on LSA Protection so LSASS runs as a protected process and a normal
administrator handle cannot read its memory. `CRD-001` pins WDigest off, which both removes
cleartext passwords from memory and acts as a tripwire — the sweep flags it as critical if
something turns it back on. `CRD-003` enables Credential Guard, which moves hashes and
tickets into a VBS-isolated process and defeats pass-the-hash rather than merely slowing it
down. `DEF-003` enables the ASR rule that blocks credential theft from LSASS outright.

### Enumeration — enum4linux, nmap, rpcclient, SharpHound

`CRD-004` refuses null sessions, `CRD-005` limits remote SAM enumeration to administrators
so a low-privilege account cannot harvest a user list for spraying, and `RMT-007` empties
the anonymous named-pipe and share lists. `FWL-001`, `FWL-002` and `FWL-004` take the host
off the fast nmap sweep entirely.

### Password guessing — hydra, CrackMapExec, kerbrute

`CRD-012` sets a lockout threshold, and `FWL-002` removes the RDP and WinRM surface the
guessing would target. `LOG-002` makes sure the attempts are actually recorded, which is
what the sweep reads.

### Post-exploitation — Metasploit, Empire, PowerSploit

`DEF-003` enables Attack Surface Reduction rules that block process creation from PsExec
and WMI, WMI event-subscription persistence, vulnerable signed drivers and obfuscated
scripts. `SVC-009` removes the PowerShell 2.0 engine, which otherwise lets
`powershell -version 2` bypass AMSI and script block logging with one flag. `LOG-006`
records deobfuscated script text before it executes.

---

## The threat sweep

`-Mode Sweep` is read-only. It changes nothing and looks for evidence of an attack in
progress:

| Finding | What it detects |
|---|---|
| `SWP-POISON-01` | Resolves a random hostname that cannot exist. An answer means a poisoner is live on the segment. |
| `SWP-ARP-01` | One MAC address claiming several IPs — the victim-side signature of arpspoof, ettercap and bettercap. |
| `SWP-ARP-02` | The default gateway answering from a different MAC than last time. |
| `SWP-DNS-01` | IPv6 DNS servers on an IPv4 network, which is what a successful mitm6 run leaves behind. |
| `SWP-SCAN-01` | A single source dropped across many distinct ports in the firewall log. |
| `SWP-AUTH-01` | Repeated failed logons from one source against several accounts. |
| `SWP-SVC-01` | A service installed from a temp directory or launching a script interpreter. |
| `SWP-PIPE-01` | A named pipe matching PsExec, PAExec, RemCom or a C2 framework. |
| `SWP-LISTEN-01` | A process accepting network connections, flagged when it runs from a user-writable path. |
| `SWP-TAMPER-01..04` | WDigest re-enabled, Defender switched off, new exclusions, or LSA Protection explicitly disabled. |

Two of these depend on controls being applied first: the port-scan detection reads the
firewall log that `FWL-011` turns on, and the failed-logon detection reads the auditing that
`LOG-002` turns on.

The poisoner probe is inert once `PRT-001` is applied — with LLMNR off, the host cannot
receive a poisoned answer. The sweep says so rather than reporting a false all-clear.

A good habit is a scheduled daily sweep:

```powershell
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Tools\KCM\Invoke-KaliCountermeasures.ps1" -Mode Sweep -JsonPath "C:\Tools\KCM\sweep.json"'
$trigger = New-ScheduledTaskTrigger -Daily -At 8am
Register-ScheduledTask -TaskName 'Kali countermeasure sweep' -Action $action -Trigger $trigger -RunLevel Highest
```

---

## Rollback

Every `Apply` run writes a journal to
`C:\ProgramData\KaliCountermeasures\rollback-<timestamp>.json` **before** making changes.
It records the previous value, whether the value existed, and whether the registry key
existed, so rollback can tell "restore to 0" apart from "this value was not there".

```powershell
# Undo the most recent Apply run
.\Invoke-KaliCountermeasures.ps1 -Mode Rollback

# Undo a specific run
.\Invoke-KaliCountermeasures.ps1 -Mode Rollback -StatePath C:\ProgramData\KaliCountermeasures\rollback-20260101-120000.json
```

Entries replay newest-first, so controls that touched the same key unwind in the opposite
order to the one they were applied in. A key is only deleted if this toolkit created it and
nothing else is left in it.

Two kinds of change cannot be reversed automatically and are reported as `manual:` lines
with the exact command to restore them: audit policy subcategories and event log sizes. The
WPAD hosts-file entries are also listed rather than removed, because editing a file someone
may have changed since is riskier than telling you which lines to delete.

---

## Control catalogue

| Prefix | Category | Count | Covers |
|---|---|---|---|
| `FWL` | Firewall | 12 | Inbound SMB/RPC/NetBIOS, RDP/WinRM, poisoning protocols, ICMP discovery, implant callback ports, profile defaults, drop logging |
| `PRT` | Protocols | 11 | LLMNR, NBT-NS, mDNS, WPAD, SMBv1, SMB signing, NTLMv2-only, DHCPv6 |
| `CRD` | Credentials | 13 | WDigest, LSA Protection, Credential Guard, null sessions, remote SAM, pass-the-hash, UAC, lockout policy |
| `RMT` | RemoteAccess | 9 | Remote Registry, WinRM, RDP and NLA, admin shares, anonymous pipes, Remote Assistance |
| `SVC` | Services | 12 | WebClient, Print Spooler, SSDP/UPnP/WSD, Secondary Logon, PowerShell 2.0, AutoRun, Windows Script Host |
| `DEF` | Defender | 7 | Real-time and cloud protection, network protection, 17 ASR rules, Tamper Protection, exclusion review |
| `LOG` | Telemetry | 9 | Audit policy, process command lines, PowerShell script block and module logging, transcription, log sizing |

`-Mode List` prints every control with the tooling it counters and its impact. Three
Defender controls are audit-only (`DEF-004`, `DEF-005`, `DEF-007`): Tamper Protection
deliberately cannot be enabled from a script, and removing a Defender exclusion that you
added on purpose is not a decision a script should make for you.

---

## Notable trade-offs

These are the controls most likely to surprise you. All of them are reversible.

| Control | What breaks |
|---|---|
| `FWL-001` | Incoming file and printer sharing on Private and Public networks. The Domain profile is untouched. |
| `FWL-003` | Single-label hostnames that only resolved by multicast. Use FQDNs or a hosts entry. |
| `FWL-004` | The machine stops replying to ping. |
| `FWL-009`, `PRT-011` | IPv6 addressing. Only use these on IPv4-only networks. |
| `PRT-010` | Any remote resource that authenticates with NTLM rather than Kerberos. Audit before enabling. |
| `RMT-006` | Backup and management tools that use `\\host\C$`. |
| `SVC-002` | All printing, including print-to-PDF. |
| `SVC-011` | Every `.vbs`, `.js` and `.wsf` script, including some installers and login scripts. |
| `CRD-010` | Saved RDP and network share credentials stop being remembered. |
| `DEF-006` | Controlled Folder Access has a high false-positive rate and needs manual allow-listing. |

---

## Running the tests

The control catalogue is pure declaration, so the whole suite runs on any platform
including Linux and macOS — no Windows and no registry required.

```powershell
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser
Install-Module PSScriptAnalyzer -Scope CurrentUser

Invoke-Pester ./tests -Output Detailed
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
```

113 tests cover the catalogue's structural integrity, the firewall rule specification, the
parsers that read Windows' locale-dependent command output, the detection heuristics, the
execution engine's error isolation and `-WhatIf` behaviour, and the rollback journal's
apply-and-restore round trip against a simulated registry.

The detection heuristics are tested against lists of real Windows service names, pipe names
and image paths. A false positive here would tell someone their machine is compromised when
it is not, which is worse than missing a detection, so those tests are deliberately broad.

---

## How it is put together

```
Invoke-KaliCountermeasures.ps1   Entry point: modes, filters, confirmation, reporting
src/
  Common.ps1                     Control model, registry/service seams, rollback journal,
                                 execution engine, BitLocker exclusion guard
  Controls.Firewall.ps1          Declarative firewall rule set + firewall controls
  Controls.Protocols.ps1         Name resolution, SMB and NTLM
  Controls.Credentials.ps1       Credential theft and enumeration
  Controls.RemoteAccess.ps1      Remote execution surface
  Controls.Services.ps1          Services, legacy engines, removable media
  Controls.Defender.ps1          Defender preferences and the ASR rule set
  Controls.Telemetry.ps1         Audit policy and PowerShell logging
  ThreatSweep.ps1                Read-only detection
  Rollback.ps1                   Journal replay
  Reporting.ps1                  Console summary, HTML and JSON reports
tests/                           Pester suite
```

A control is a declaration, not a script:

```powershell
New-RegistryControl -Id 'CRD-001' -Name 'WDigest plaintext credential caching disabled' `
    -Category 'Credentials' -Tier 'Baseline' `
    -Counters @('mimikatz sekurlsa::wdigest', 'LaZagne', 'pypykatz') `
    -Rationale '...' -Impact '...' `
    -Setting @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
           Name = 'UseLogonCredential'; Value = 0; Label = 'WDigest cleartext caching' }
    )
```

The engine audits it, applies it only if it has drifted, re-verifies it afterwards, and
records the prior state on the way through. A control whose test throws is reported and
skipped; it never stops the run, and a control is never applied blind when its current
state could not be read.

### Locale independence

Two Windows tools print localised text that cannot be parsed reliably on a non-English
install. Both are read through a numeric or non-localised path instead:

- Audit policy is read with `auditpol /backup`, which emits a numeric setting column, not
  `auditpol /get`, which prints translated strings like "Success and Failure".
- The local account policy is read from a `secedit` export rather than by parsing the
  output of `net accounts`.

Audit subcategories are also addressed by GUID rather than by name.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean. Everything selected is in the desired state and the sweep found nothing. |
| `1` | Could not run: wrong platform, or `Apply`/`Rollback` without administrator rights. |
| `2` | Drift remains, or the sweep produced findings above informational severity. |
| `3` | At least one control failed to apply, or a rollback entry could not be restored. |

---

## Scope and honest limits

This toolkit raises the cost of attacking a Windows 11 host from a pen-testing
distribution. It does not make the host unattackable.

- **It defends against tooling, not against a person.** A skilled operator who adapts will
  get through controls aimed at default configurations. `FWL-007` blocking port 4444 stops
  a tutorial payload and nothing more; it is noise reduction, not a control to rely on.
- **It is host-level only.** It does nothing about a compromised router, a malicious access
  point, or another machine on your network.
- **Detection is best-effort and bounded by what Windows recorded.** The sweep reads the
  firewall log and the Security log. If auditing was off while the attack happened, there is
  nothing to find. It is not an EDR, and it does not inspect memory.
- **Already-compromised hosts cannot be fixed by a script.** If the sweep reports a
  critical finding, the right response is to isolate the machine and rebuild it, not to
  apply hardening on top and hope.
- **BitLocker is excluded by design.** Nothing here protects data at rest or defends against
  an attacker with physical access and time. If you want that, enable BitLocker separately —
  this toolkit will not interfere with it either way.
# win11-kali-counter
