# counter-guard

A single bash script for Termux + `tsu` on a rooted Android device (Magisk or KernelSU).
It detects and neutralises the following tools on your own phone.

| Tool | What counter-guard looks for | What `fix` does |
|---|---|---|
| [sim-spoof](https://github.com/otilrac/sim-spoof) | `ReBullet-*` and other boot scripts in `/data/adb/service.d`, Magisk modules; `iptables` TTL/HL rewrites; port-53 DNAT; `gsm.operator.numeric` that disagrees with the registered network; `private_dns_mode=off` | quarantines scripts (or disables the module), deletes the rules, restores the operator prop, sets Private DNS back to opportunistic |
| [Android-Daemon](https://github.com/DevL0rd/Android-Daemon) | wireless debugging, `adbd` TCP port (5555), scrcpy server process/binary, trusted ADB hosts, RNDIS/NCM USB function | turns wireless ADB off, resets the port props, kills scrcpy, `--strict` also disables USB debugging and revokes ADB keys, `--block-tether` resets the USB function |
| [CastDrive](https://github.com/RSR-Projects/CastDrive) | package `com.aistudio.automirror.cxkmv`, its accessibility/MediaProjection services (also repackaged builds by class name) | force-stops, revokes mic and `PROJECT_MEDIA`, removes the accessibility entry, disables (or `--remove-apps` uninstalls) |
| [auto-usb-tether](https://github.com/riteshgharti333/auto-usb-tether) | package `com.aistudio.usbtether.vxkqz`, `UsbTetherAccessibilityService` | same as above |
| [hotspot-ttl](https://github.com/pratikbin/hotspot-ttl) | tether clients sending TTL/HL 65 (so the phone forwards them at 64) | installs a `COUNTER_GUARD` mangle chain on tether interfaces that counts TTL/HL 65 packets and normalises them to 64 (`--monitor-only` just counts) |

## Setup

```bash
pkg install tsu
cp counter-guard.sh ~/ && chmod +x ~/counter-guard.sh
```

## Usage

```bash
./counter-guard.sh                      # audit only, exit 1 if anything is found
./counter-guard.sh fix                  # neutralise everything found
./counter-guard.sh fix --dry-run        # show what would change
./counter-guard.sh fix --strict --block-tether --remove-apps
./counter-guard.sh watch 30             # re-check and re-fix every 30s (termux-notification if available)
./counter-guard.sh install --strict     # fix + Magisk/KSU service.d autostart of watch mode
./counter-guard.sh install --termux-boot  # additionally add a Termux:Boot entry
./counter-guard.sh status
./counter-guard.sh uninstall            # remove autostart and the firewall chain
```

The script re-launches itself through `tsu` (or `su`) if it is not root.
Anything removed is moved to `~/.counter-guard/quarantine`; activity is logged to `~/.counter-guard/guard.log`.

## Notes

- Props such as the SIM operator/timezone are fully restored by a reboot once the spoof scripts are gone.
- The TTL guard needs `xt_ttl`/`xt_hl` and `xt_comment` in the kernel. If they are missing the script says so and does not install it.
- Normalising to 64 means forwarded tether traffic leaves the phone at 63. The firewall guard only touches packets arriving on tether interfaces.
- `--strict` turns off USB debugging. Do not use it if you rely on `adb`.
- Detection is signature based (package IDs, class names, rule/script patterns). A renamed build of a tool may need `EXTRA_PKGS="com.example.app" ./counter-guard.sh`.
