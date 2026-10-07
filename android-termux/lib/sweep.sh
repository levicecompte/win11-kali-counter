#!/usr/bin/env bash
# Read-only detection pass.
#
# Hardening tells you what the device looks like. The sweep tells you what the
# network is doing to it right now. Nothing in this file changes any state.
#
# The analysers are written as pure functions that take text and print findings,
# so each one is unit tested against captured output instead of needing a live
# attack to verify.

KCM_STATE_DIR="${KCM_STATE_DIR:-${KCM_HOME_DIR:-$HOME}/.kali-counter}"

# ---------------------------------------------------------------------------
# Pure analysers
# ---------------------------------------------------------------------------

hex_to_ipv4() {
    # /proc/net/* stores addresses as little-endian hex.
    local h="$1"
    [ "${#h}" -eq 8 ] || { printf ''; return 0; }
    printf '%d.%d.%d.%d' \
        "$((16#${h:6:2}))" "$((16#${h:4:2}))" "$((16#${h:2:2}))" "$((16#${h:0:2}))"
}

parse_default_gateway() {
    # Reads /proc/net/route content on stdin, prints the default gateway IPv4.
    local iface dest gw
    while read -r iface dest gw _; do
        [ "$iface" = 'Iface' ] && continue
        [ "$dest" = '00000000' ] || continue
        [ -n "$gw" ] || continue
        hex_to_ipv4 "$gw"
        printf '\n'
        return 0
    done
    return 0
}

parse_proc_net_arp() {
    # Prints "ip<TAB>mac<TAB>device" for every complete entry.
    local ip mac dev
    while read -r ip _ _ mac _ dev; do
        [ "$ip" = 'IP' ] && continue
        [ -n "$mac" ] || continue
        # 0x0 means the entry is incomplete; the MAC is all zeroes.
        [ "$mac" = '00:00:00:00:00:00' ] && continue
        printf '%s\t%s\t%s\n' "$ip" "$mac" "$dev"
    done
}

find_arp_anomaly() {
    # Input: output of parse_proc_net_arp. Prints one line per MAC that claims
    # more than one address, which is what arpspoof and ettercap produce while
    # they sit between you and the gateway.
    awk -F'\t' '
        { seen[$2] = seen[$2] " " $1; count[$2]++ }
        END {
            for (mac in count) {
                if (count[mac] > 1) printf "%s\t%d\t%s\n", mac, count[mac], substr(seen[mac], 2)
            }
        }
    ' | sort
}

parse_proc_net_tcp() {
    # Prints "ip<TAB>port" for sockets in the LISTEN state (st == 0A).
    local local_addr st
    while read -r _ local_addr _ st _; do
        [ "$st" = '0A' ] || continue
        local hexip="${local_addr%%:*}" hexport="${local_addr##*:}"
        local ip
        if [ "${#hexip}" -eq 8 ]; then
            ip="$(hex_to_ipv4 "$hexip")"
        else
            ip='[v6]'
        fi
        printf '%s\t%d\n' "$ip" "$((16#${hexport}))"
    done
}

classify_listening_port() {
    # Prints a severity and an explanation for a port that is accepting
    # connections, or nothing when the port carries no particular risk.
    case "$1" in
        5555)  printf 'critical\twireless ADB. Anyone who can reach this port can install applications and run shell commands as the shell user.' ;;
        5037)  printf 'high\tthe ADB server control port is listening.' ;;
        8022)  printf 'high\tTermux sshd. Confirm it requires a key and is bound to loopback (TMX-001, TMX-002).' ;;
        22)    printf 'high\tan SSH server is listening on the standard port.' ;;
        4444|4445|1337|31337) printf 'critical\tthis is a default Metasploit or Netcat handler port. A listener here is very unlikely to be something you started deliberately.' ;;
        23)    printf 'critical\ttelnet. Credentials cross the network in plaintext.' ;;
        139|445) printf 'high\tSMB. This is what enum4linux and CrackMapExec look for.' ;;
        1716)  printf 'medium\tKDE Connect, which exposes file transfer and remote input to the local network.' ;;
        8080|8081|3000|5000) printf 'medium\ta development web server is listening and reachable.' ;;
        *) printf '' ;;
    esac
}

parse_firewall_drop_line() {
    # Extracts "src<TAB>dport" from a kernel KCM-DROP log line.
    local line="$1" src dpt
    case "$line" in
        *KCM-DROP*) ;;
        *) return 0 ;;
    esac
    src="$(printf '%s' "$line" | grep -oE 'SRC=[0-9a-fA-F.:]+' | head -1)"
    dpt="$(printf '%s' "$line" | grep -oE 'DPT=[0-9]+' | head -1)"
    [ -n "$src" ] && [ -n "$dpt" ] || return 0
    printf '%s\t%s\n' "${src#SRC=}" "${dpt#DPT=}"
}

find_port_scan_source() {
    # Input: "src<TAB>port" lines. $1 = distinct-port threshold.
    # Prints "src<TAB>distinct_ports" for sources above the threshold.
    local threshold="${1:-8}"
    sort -u | awk -F'\t' -v t="$threshold" '
        { count[$1]++ }
        END {
            for (src in count) {
                if (count[src] >= t) printf "%s\t%d\n", src, count[src]
            }
        }
    ' | sort -k2 -rn
}

random_label() {
    # A hostname nothing can legitimately resolve. Any answer means something
    # on the path is inventing one.
    local chars='abcdefghijklmnopqrstuvwxyz0123456789' out=''
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
        out="$out${chars:$((RANDOM % ${#chars})):1}"
    done
    printf 'kcm-%s' "$out"
}

# ---------------------------------------------------------------------------
# Detections
# ---------------------------------------------------------------------------

sweep_arp() {
    local arp parsed anomalies gw baseline current
    arp="$(sys_read_file /proc/net/arp)"
    if [ -z "$arp" ]; then
        add_finding 'SWP-ARP-00' 'info' 'ARP table not readable' \
            'Android 10 and later restrict /proc/net to the app that owns the sockets. Run the sweep with root to enable ARP spoofing detection.'
        return 0
    fi

    parsed="$(printf '%s\n' "$arp" | parse_proc_net_arp)"
    anomalies="$(printf '%s\n' "$parsed" | find_arp_anomaly)"

    if [ -n "$anomalies" ]; then
        local mac count ips
        while IFS=$'\t' read -r mac count ips; do
            [ -n "$mac" ] || continue
            add_finding 'SWP-ARP-01' 'critical' 'ARP table shows one MAC claiming several addresses' \
                "$mac is answering for $count addresses ($ips). That is the signature of arpspoof, ettercap or bettercap placing itself between this device and the gateway. Treat traffic on this network as read."
        done <<< "$anomalies"
    fi

    gw="$(printf '%s\n' "$(sys_read_file /proc/net/route)" | parse_default_gateway)"
    [ -n "$gw" ] || return 0
    current="$(printf '%s\n' "$parsed" | awk -F'\t' -v g="$gw" '$1==g {print $2; exit}')"
    [ -n "$current" ] || return 0

    local baseline_file="$KCM_STATE_DIR/gateway-$gw.mac"
    baseline="$(sys_read_file "$baseline_file")"
    if [ -z "$baseline" ]; then
        mkdir -p "$KCM_STATE_DIR" 2>/dev/null || true
        printf '%s' "$current" > "$baseline_file" 2>/dev/null || true
        add_finding 'SWP-ARP-02' 'info' 'Gateway MAC recorded' \
            "First sweep on this network. Gateway $gw is at $current; later sweeps will report if that changes."
    elif [ "$baseline" != "$current" ]; then
        add_finding 'SWP-ARP-02' 'high' 'Gateway MAC address changed' \
            "Gateway $gw was $baseline and is now $current. A replaced router or a new access point explains this innocently; so does an attacker impersonating the gateway."
    fi
}

sweep_dns_hijack() {
    local probe answer
    probe="$(random_label).invalid"
    answer="$(sys_resolve_host "$probe")"

    if [ -n "$answer" ]; then
        add_finding 'SWP-DNS-01' 'high' 'DNS resolver answers names that cannot exist' \
            "Resolving $probe returned $(printf '%s' "$answer" | tr '\n' ' '). A .invalid name must never resolve. Something on the path is answering every query, which is how dnsspoof, ettercap and captive portals redirect traffic."
    fi

    local mode
    mode="$(sys_settings_get global private_dns_mode)"
    if [ "$mode" != 'hostname' ]; then
        local dns1
        dns1="$(sys_getprop net.dns1)"
        if [ -n "$dns1" ] && is_private_address "$dns1"; then
            add_finding 'SWP-DNS-02' 'medium' 'Plaintext DNS pointed at a local address' \
                "Queries go to $dns1 in the clear. On a network you do not control, that device decides what every hostname resolves to. NET-001 fixes this."
        fi
    fi
}

sweep_tls() {
    local raw issuer class
    raw="$(sys_tls_issuer "$KCM_TLS_PROBE_HOST")"
    [ -n "$raw" ] || return 0
    issuer="${raw#issuer=}"
    class="$(classify_tls_issuer "$issuer")"

    case "$class" in
        interception)
            add_finding 'SWP-TLS-01' 'critical' 'TLS is being intercepted' \
                "The certificate for $KCM_TLS_PROBE_HOST was issued by '$issuer', a proxy CA. Everything this device has sent over HTTPS on this network should be considered read. Remove the CA under Settings > Security > Trusted credentials > User."
            ;;
        unrecognised)
            add_finding 'SWP-TLS-02' 'medium' 'TLS certificate from an unrecognised authority' \
                "The certificate for $KCM_TLS_PROBE_HOST was issued by '$issuer'. That is normal behind managed corporate inspection and unexpected anywhere else."
            ;;
    esac
}

sweep_proxy() {
    local proxy pac
    proxy="$(sys_settings_get global http_proxy)"
    pac="$(sys_settings_get global global_proxy_pac_url)"

    if [ -n "$proxy" ] && [ "$proxy" != ':0' ]; then
        add_finding 'SWP-PROXY-01' 'high' 'A global HTTP proxy is configured' \
            "All HTTP traffic is being sent through $proxy. Unless you set this deliberately, it is a redirect through someone else's machine."
    fi
    if [ -n "$pac" ]; then
        add_finding 'SWP-PROXY-02' 'high' 'A proxy auto-config URL is set' \
            "Proxy configuration is being fetched from $pac, which lets whoever serves that file re-route traffic at will."
    fi
}

sweep_listeners() {
    local raw parsed ip port class sev note
    for src in /proc/net/tcp /proc/net/tcp6; do
        raw="$(sys_read_file "$src")"
        [ -n "$raw" ] || continue
        parsed="$(printf '%s\n' "$raw" | parse_proc_net_tcp)"
        while IFS=$'\t' read -r ip port; do
            [ -n "$port" ] || continue
            class="$(classify_listening_port "$port")"
            [ -n "$class" ] || continue
            sev="${class%%$'\t'*}"
            note="${class##*$'\t'}"
            # Loopback-only listeners are not reachable from the network.
            if [ "$ip" = '127.0.0.1' ]; then
                sev='low'
                note="$note (bound to loopback, so not reachable from the network)"
            fi
            add_finding 'SWP-LISTEN-01' "$sev" "Listening socket on port $port" "$ip:$port - $note"
        done <<< "$parsed"
    done
}

sweep_scan_log() {
    local logs hits sources src count
    if ! sys_have dmesg; then
        return 0
    fi
    logs="$(sys_privileged_run dmesg 2>/dev/null | grep 'KCM-DROP' || true)"
    [ -n "$logs" ] || return 0

    hits=''
    local line parsed
    while IFS= read -r line; do
        parsed="$(parse_firewall_drop_line "$line")"
        [ -n "$parsed" ] && hits="$hits$parsed"$'\n'
    done <<< "$logs"
    [ -n "$hits" ] || return 0

    sources="$(printf '%s' "$hits" | find_port_scan_source 8)"
    [ -n "$sources" ] || return 0

    while IFS=$'\t' read -r src count; do
        [ -n "$src" ] || continue
        add_finding 'SWP-SCAN-01' 'high' 'Port scan recorded by the firewall' \
            "$src probed $count distinct ports on this device. The packets were dropped by FW-001, so the scan learned nothing, but someone on this network is looking."
    done <<< "$sources"
}

sweep_adb() {
    local adb wifi_adb
    adb="$(sys_settings_get global adb_enabled)"
    wifi_adb="$(sys_settings_get global adb_wifi_enabled)"

    if [ "$adb" = '1' ]; then
        add_finding 'SWP-ADB-01' 'critical' 'USB debugging is enabled' \
            'Anyone who can plug a cable into this phone and get the authorisation prompt accepted has a shell on it. DEV-001 turns this off.'
    fi
    if [ "$wifi_adb" = '1' ]; then
        add_finding 'SWP-ADB-02' 'critical' 'Wireless debugging is enabled' \
            'ADB is reachable over the network rather than over a cable. This is the most direct remote compromise path on Android. DEV-002 turns this off.'
    fi
}

sweep_certs() {
    local dir entries count=0 found=''
    for dir in $KCM_USER_CA_PATHS; do
        sys_file_exists "$dir" || continue
        entries="$(sys_privileged_run ls -1 "$dir" 2>/dev/null || true)"
        [ -n "$entries" ] || continue
        count=$((count + $(printf '%s\n' "$entries" | grep -c . || true)))
        found="$found $dir"
    done
    [ "$count" -gt 0 ] || return 0
    add_finding 'SWP-CERT-01' 'high' 'User-installed certificate authorities present' \
        "$count certificate(s) under$found. Each one can sign a certificate for any website, which is exactly what a Burp or mitmproxy setup installs."
}

sweep_accessibility() {
    local services list count
    services="$(sys_settings_get secure enabled_accessibility_services)"
    [ -n "$services" ] || return 0
    list="$(split_colon_list "$services")"
    count="$(printf '%s\n' "$list" | grep -c . || true)"
    add_finding 'SWP-A11Y-01' 'medium' 'Accessibility services are bound' \
        "$count service(s): $(printf '%s' "$list" | tr '\n' ' '). These can read the screen and inject input. Confirm every one is something you installed on purpose."
}

sweep_rc_files() {
    local file line n=0 sample=''
    for file in "$KCM_HOME_DIR/.bashrc" "$KCM_HOME_DIR/.bash_profile" "$KCM_HOME_DIR/.profile" "$KCM_HOME_DIR/.zshrc"; do
        sys_file_exists "$file" || continue
        while IFS= read -r line; do
            if rc_line_is_suspicious "$line"; then
                n=$((n + 1))
                [ -z "$sample" ] && sample="$file: $(printf '%s' "$line" | cut -c1-120)"
            fi
        done <<< "$(sys_read_file "$file")"
    done
    [ "$n" -gt 0 ] || return 0
    add_finding 'SWP-PERSIST-01' 'critical' 'Shell startup file executes remote code' \
        "$n line(s) found. First: $sample. This is how a shell payload survives closing Termux."
}

run_sweep() {
    kcm_log info 'Running read-only threat sweep'
    sweep_arp
    sweep_dns_hijack
    sweep_tls
    sweep_proxy
    sweep_listeners
    sweep_scan_log
    sweep_adb
    sweep_certs
    sweep_accessibility
    sweep_rc_files
}
