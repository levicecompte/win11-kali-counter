# Android countermeasures against pen-testing distributions

A Termux shell toolkit that hardens an Android phone against the tooling shipped with Kali
Linux and similar distributions, and that sweeps the device for evidence such tooling is
already being used against it.

It is built around a catalogue of **38 controls**. Every control knows what tooling it
defeats, why it works, and what it costs you. Every change it makes is recorded so the
whole run can be undone with one command.

**Device encryption and the lockscreen credential are deliberately out of scope**, carrying
over the BitLocker exclusion from the Windows toolkit in this repository. Android derives
its file-based encryption keys from the lockscreen credential, so a script that gets this
wrong costs you your data rather than a setting. The toolkit never reads or writes any of
it. The exclusion is enforced in the control model and checked by tests.

---

## Read this before anything else

Android is not Windows, and pretending otherwise would make this toolkit a liar.

On Windows, an administrator can change essentially anything. On Android, an ordinary
Termux process has **no authority over the system at all**. It cannot touch the packet
filter, cannot change a system setting, and cannot see another app's state. That is the
sandbox working as designed, and no script can argue with it.

So privilege is a first-class property of every control here. Each one declares whether it
needs nothing, shell-level access, or root, and the engine **reports what it cannot reach
instead of quietly failing or pretending to succeed**:

| Privilege | How you get it | Controls unlocked |
|---|---|---|
| **none** | Plain Termux, nothing to do | 15 |
| **shell** | [Shizuku](https://shizuku.rikka.app/) plus the `rish` helper, or run under `adb shell` | 12 |
| **root** | Magisk or KernelSU, with `su` granted to Termux | 11 |

Run it unrooted and you still get real value: the entire Termux pack, the live TLS
interception probe, the accessibility and sideload audits, the platform integrity checks and
most of the threat sweep. You do not get the firewall. There is no workaround for that, and
anything claiming otherwise on an unrooted phone is selling you a VPN-based filter, which is
a different thing with different trade-offs.

---

## Quick start

```bash
pkg install bash openssl-tool   # jq and iproute2 are optional but useful
cd android-termux

# 1. See the catalogue and what each control needs
bash kali-counter.sh -m list -t aggressive

# 2. Check the device as it is today, changing nothing
bash kali-counter.sh -m audit --html ~/audit.html

# 3. Preview every change before committing to it
bash kali-counter.sh -m apply -n

# 4. Apply
bash kali-counter.sh -m apply -t baseline

# 5. Later: hunt for an attack happening right now
bash kali-counter.sh -m sweep

# 6. If something broke, undo all of it
bash kali-counter.sh -m rollback
```

`audit` is the default mode and never writes anything, so running the script with no
arguments at all is safe.

### Getting shell-level access without root

This is the step most people skip, and it is where most of the value sits — ADB, Private
DNS and Play Protect all live behind it.

1. Install **Shizuku** from the Play Store or F-Droid.
2. Start it with wireless debugging (no PC needed on Android 11+) or over `adb`.
3. Install the `rish` helper into Termux following Shizuku's instructions, so that `rish`
   is on your `PATH`.
4. Re-run the toolkit. It detects `rish` automatically and the `shell` controls stop
   reporting as blocked.

---

## Tiers

```bash
# Safe on a phone you use normally. Closes the highest-value paths.
bash kali-counter.sh -m apply -t baseline      # 21 controls

# Adds controls that may interrupt things you actually use.
bash kali-counter.sh -m apply -t standard      # 35 controls

# Assumes the phone should be invisible on the network.
bash kali-counter.sh -m apply -t aggressive    # 38 controls
```

Tiers are cumulative and can be combined with filters:

```bash
# Standard, but leave Bluetooth alone
bash kali-counter.sh -m apply -t standard -x NET-005

# Only the Termux hardening, which needs no privilege at all
bash kali-counter.sh -m apply -c Termux

# Just the anti-mitm6 control from the aggressive tier
bash kali-counter.sh -m apply -i FW-009
```

---

## What it defends against

### Name-resolution poisoning — Responder, Inveigh, bettercap

Responder wins by answering broadcast name queries that nobody else claims. The defence is
to stop asking. `FW-003` drops LLMNR, mDNS, NBNS, SSDP and WS-Discovery **outbound** as well
as inbound, so there is no query left to poison.

### Machine-in-the-middle — ettercap, bettercap, mitm6, dnsspoof

`NET-001` pins DNS to an authenticated TLS resolver, which removes the DHCP-supplied
resolver as an attack surface. `FW-009` drops IPv6 router advertisements and DHCPv6, which
is what mitm6 relies on to become your router and DNS server on an IPv4-only network.
`CRT-001` performs a real TLS handshake and inspects who signed the certificate that comes
back, which catches a proxy regardless of how its CA reached the device.

### ADB abuse — PhoneSploit, `adb connect`, internet-wide 5555 scanning

This is the most direct remote compromise path on Android and it is countered twice on
purpose: `DEV-001` and `DEV-002` turn the settings off, and `FW-002` blocks the ports at the
packet filter so re-enabling the setting from the UI is not enough to reopen it.

### Network discovery — nmap, masscan, fping

`FW-001` sets a default-deny inbound policy after allowing loopback, established flows and
DHCP replies, so a scan from another host on the same Wi-Fi gets no response at all.
`FW-005` removes the phone from ping sweeps and `FW-006` drops the flag combinations that
NULL, FIN, Xmas and ACK scans use for fingerprinting.

### Credential guessing — hydra, medusa, ncrack, patator

Termux `sshd` accepts passwords by default, on a port attackers know, with a password typed
on a phone keyboard. `TMX-001` makes it key-only with `MaxAuthTries 3`, `TMX-002` binds it
to loopback, and `FW-007` rate-limits new inbound connections.

### Payloads and RATs — msfvenom APKs, AhMyth, L3MON, Metasploit handlers

`DEV-004` keeps Play Protect verification on. `PKG-001` and `PKG-002` list every
accessibility service and notification listener, which is how an Android RAT reads your
screen and your one-time codes without needing a single exploit. `FW-010` denies the default
handler ports. `TMX-004` looks for the `.bashrc` line a shell payload appends to survive a
reboot.

### Platform integrity — the thing no script can fix

`DEV-005` through `DEV-008` report bootloader lock state, verified boot state, SELinux mode
and security patch age. These are audit-only because only your vendor or a reflash can
change them, but every other control on the list is only as trustworthy as these answers.

> An "AI-assisted Kali" workflow does not change the defence. The operator gets faster at
> choosing and chaining tools; the tools still speak ARP, DNS, LLMNR, ADB and TLS, and they
> still need a reachable port, a poisoned answer or a trusted CA. This toolkit closes those,
> so it applies the same either way.

---

## The threat sweep

`-m sweep` changes nothing. It looks for an attack in progress:

| Finding | What it means |
|---|---|
| `SWP-ARP-01` | One MAC address is claiming several IPs — the signature of `arpspoof`, `ettercap` or `bettercap` sitting between you and the gateway |
| `SWP-ARP-02` | The gateway's MAC changed since the last sweep on this network |
| `SWP-DNS-01` | The resolver answered a random `.invalid` name that cannot exist, so something is answering every query |
| `SWP-DNS-02` | Plaintext DNS pointed at a device on the local network |
| `SWP-TLS-01` | The certificate chain leads to a proxy CA such as PortSwigger or mitmproxy |
| `SWP-PROXY-01/02` | A global HTTP proxy or proxy auto-config URL is set |
| `SWP-LISTEN-01` | A socket is accepting connections on a port that matters (ADB, sshd, a handler port) |
| `SWP-SCAN-01` | The firewall log shows one source probing many distinct ports |
| `SWP-ADB-01/02` | USB or wireless debugging is on right now |
| `SWP-CERT-01` | User-installed certificate authorities are present |
| `SWP-A11Y-01` | Accessibility services are bound and can read the screen |
| `SWP-PERSIST-01` | A shell startup file fetches and executes remote code |

Two deliberate choices in here:

**Informational findings do not fail the run.** The first sweep on a new network records the
gateway MAC and says so. That is reported but does not set a non-zero exit code, because
otherwise every new Wi-Fi network would look like an incident.

**Nothing is flagged by name.** The sweep does not guess that a package or service is
malicious because its name looks random. That heuristic was tried in the Windows toolkit in
this repository and removed: it flagged real Windows services as payloads. Telling someone
their phone is compromised when it is not is worse than missing a detection, so the weight
sits on behaviour — who signed the certificate, who answers DNS, what is listening, what a
startup file executes.

Some detections need `/proc/net` access, which Android 10 and later restrict to root. The
sweep says so explicitly rather than reporting a clean result it did not actually verify.

---

## Rollback

Apply writes a journal to `~/.kali-counter/journal.log` recording, for every change, the
previous value **and whether it existed at all**. That distinction matters: restoring a
setting to `0` is not the same as removing one that was never there.

```bash
bash kali-counter.sh -m rollback
bash kali-counter.sh -m rollback -j ~/.kali-counter/journal.log
```

Entries replay **newest first**, so when two controls touched the same key the value that
was there before the toolkit ran is the one that wins. Firewall chains are removed and the
original `INPUT` policy restored. Anything that cannot be undone automatically is printed as
a manual step, and those are never suppressed, even with `-q`.

Once a rollback completes cleanly the journal is archived so it cannot be replayed twice.

---

## Control catalogue

| Category | Count | What it covers |
|---|---|---|
| Firewall | 10 | Default-deny inbound, ADB ports, poisoning egress, scan resistance, rate limits, drop logging, mitm6, handler ports |
| Device | 8 | USB and wireless debugging, developer options, Play Protect, bootloader, verified boot, SELinux, patch level |
| Network | 6 | DNS over TLS, Wi-Fi and BLE background scanning, charge-time screen lock, Bluetooth, resolver audit |
| Packages | 6 | Accessibility services, notification listeners, sideload inventory, install and overlay permissions, device admins |
| Termux | 6 | sshd key-only auth, loopback binding, key permissions, startup-file integrity, PATH hygiene, writable binaries |
| Certificates | 2 | Live interception probe, user CA store |

15 of the 38 are **audit-only**. They report and explain but never change anything, either
because the fix is a human decision (revoking an accessibility service can lock someone out
of their phone) or because no script can make it (patch level, bootloader state).

---

## Notable trade-offs

| Control | Tier | What it costs you |
|---|---|---|
| `FW-009` | aggressive | Blocks IPv6 router advertisements, which breaks genuine IPv6 connectivity |
| `FW-007` | standard | Rate-limits new inbound connections, which can slow legitimate local services |
| `NET-005` | aggressive | Turns Bluetooth off, disconnecting headphones, watches and car audio |
| `NET-002` | standard | Disables always-on Wi-Fi scanning, which degrades location accuracy |
| `NET-004` | standard | The screen stops staying awake while charging |
| `TMX-002` | standard | `sshd` becomes unreachable from your laptop |
| `DEV-003` | standard | Developer options disappear, so re-enabling them is a deliberate act |

---

## Running the tests

The catalogue is pure declaration and the analysers are pure functions, so the entire suite
runs on an ordinary Linux machine with no Android device involved.

```bash
bats tests/                                      # 85 tests
shellcheck -S style -x kali-counter.sh lib/*.sh  # 0 findings
```

The suite covers the analysers against both real attack output and ordinary output that must
not be flagged, the catalogue's structure including all three layers of the encryption
exclusion, and the full apply/journal/rollback cycle against a simulated settings provider.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Everything the selected tier covers is in the desired state |
| 1 | The toolkit could not run |
| 2 | Drift, actionable findings, or controls needing review |
| 3 | A control failed to apply |

Stable enough to drive from `cron` or Termux:Tasker:

```bash
bash kali-counter.sh -m sweep -q --json ~/sweep.json || echo "sweep found something"
```

---

## Architecture

```
kali-counter.sh       Entry point: argument parsing, mode dispatch, exit codes
lib/common.sh         Control registry, capability detection, system seams, journal
lib/controls_*.sh     The catalogue, as declaration
lib/sweep.sh          Read-only detections and their pure analysers
lib/rollback.sh       Journal replay
lib/report.sh         Terminal, HTML and JSON output
tests/                bats suites
```

Everything that touches the device goes through the `sys_*` seam functions at the top of
`lib/common.sh`. Nothing else shells out. That keeps the OS-touching surface small enough to
review in one sitting, and it is what lets the test suite run the whole engine with those
seams replaced by fakes.

---

## Honest limits

- **Unrooted, the firewall pack cannot run.** Eleven controls will report as blocked. That
  is Android's design, not a gap in the toolkit.
- **This hardens the device; it does not make it invisible.** An attacker with physical
  access, or an app you have already granted accessibility to, is outside what settings and
  packet filters can address.
- **Device encryption is out of scope by design**, so offline attacks against the storage of
  a powered-off phone are not covered here.
- **`/proc/net` restrictions** on Android 10+ limit ARP and socket detection without root.
  The sweep tells you when that happens instead of reporting a clean result.
- **An unlocked bootloader or a failed verified-boot state defeats everything above.**
  `DEV-005` and `DEV-006` will tell you; only a reflash fixes it.
