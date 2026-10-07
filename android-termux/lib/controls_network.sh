#!/usr/bin/env bash
# Network-stack controls. These close the openings a machine-in-the-middle on
# the same Wi-Fi relies on: plaintext DNS, opportunistic radio scanning, and a
# screen that stays unlocked while charging.

KCM_PRIVATE_DNS_HOST="${KCM_PRIVATE_DNS_HOST:-dns.quad9.net}"

register_setting_control \
    --id NET-001 \
    --name 'Force DNS over TLS (Private DNS)' \
    --category Network \
    --tier baseline \
    --capability shell \
    --counters 'dnsspoof, ettercap, bettercap dns.spoof, rogue DHCP DNS, captive-portal injection' \
    --rationale "Pins resolution to an authenticated TLS resolver instead of whatever the network hands out over DHCP. DNS spoofing is the first move in most phone-targeting attacks because it redirects traffic before any certificate check happens. Resolver: $KCM_PRIVATE_DNS_HOST" \
    --tags 'network dns mitm' \
    --data "settings=global private_dns_mode hostname
global private_dns_specifier $KCM_PRIVATE_DNS_HOST"

register_setting_control \
    --id NET-002 \
    --name 'Disable always-on Wi-Fi scanning' \
    --category Network \
    --tier standard \
    --capability shell \
    --counters 'wifiphisher, airodump-ng probe harvesting, evil-twin targeting, bettercap wifi.recon' \
    --rationale 'With scanning always on the phone broadcasts probe requests naming networks it has joined before. That list is what an evil twin needs to impersonate a network you trust.' \
    --tags 'network wifi tracking' \
    --data 'settings=global wifi_scan_always_enabled 0'

register_setting_control \
    --id NET-003 \
    --name 'Disable always-on Bluetooth LE scanning' \
    --category Network \
    --tier standard \
    --capability shell \
    --counters 'bettercap ble.recon, BLE proximity tracking, Sniffle' \
    --rationale 'Background BLE scanning keeps the radio advertising and responding when no app is actively using it, which gives a nearby attacker a persistent handle on the device.' \
    --tags 'network bluetooth tracking' \
    --data 'settings=global ble_scan_always_enabled 0'

register_setting_control \
    --id NET-004 \
    --name 'Do not keep the screen on while charging' \
    --category Network \
    --tier standard \
    --capability shell \
    --counters 'opportunistic physical access, juice-jacking follow-through, shoulder surfing' \
    --rationale 'stay_on_while_plugged_in keeps an unlocked device unlocked for as long as it is plugged in. Charging in a public place is exactly when that matters.' \
    --tags 'network physical' \
    --data 'settings=global stay_on_while_plugged_in 0'

register_setting_control \
    --id NET-005 \
    --name 'Turn the Bluetooth radio off' \
    --category Network \
    --tier aggressive \
    --capability shell \
    --counters 'bluesnarfing, BlueBorne-class bugs, bettercap BLE attacks, KNOB' \
    --rationale 'The most reliable defence against the Bluetooth stack is not running it. Aggressive tier because it disconnects headphones, watches and car audio.' \
    --tags 'network bluetooth' \
    --data 'settings=global bluetooth_on 0'

# ---------------------------------------------------------------------------
# NET-006  Resolver audit (works without any privilege)
# ---------------------------------------------------------------------------

net_resolver_test() {
    local dns1 dns2 mode
    dns1="$(sys_getprop net.dns1)"
    dns2="$(sys_getprop net.dns2)"
    mode="$(sys_settings_get global private_dns_mode)"

    if [ "$mode" = 'hostname' ]; then
        verdict_ok "Private DNS is pinned to $(sys_settings_get global private_dns_specifier)"
        return 0
    fi

    local detail
    detail="resolvers: $(printf '%s %s' "${dns1:-unknown}" "${dns2:-}" | sed 's/[[:space:]]*$//')"
    if is_private_address "$dns1"; then
        verdict_bad "plaintext DNS pointed at a device on the local network - $detail. On an untrusted network this is indistinguishable from a spoofed resolver."
    else
        verdict_bad "DNS is not using TLS - $detail"
    fi
}

is_private_address() {
    # RFC1918 and link-local. Pure function, covered by the test suite.
    case "$1" in
        10.*|192.168.*|169.254.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        fe80:*|fc??:*|fd??:*) return 0 ;;
        *) return 1 ;;
    esac
}

register_control \
    --id NET-006 \
    --name 'Audit the resolvers currently in use' \
    --category Network \
    --tier baseline \
    --capability none \
    --test net_resolver_test \
    --audit-only \
    --counters 'rogue DHCP, ettercap, responder-supplied resolvers' \
    --rationale 'Reports which DNS servers the device is actually using right now and whether they sit on the local network. Read-only: fixing it is what NET-001 does.' \
    --tags 'network dns audit'
