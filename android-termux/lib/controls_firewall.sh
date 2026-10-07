#!/usr/bin/env bash
# Netfilter controls. Root only: Android gives an unrooted process no way to
# touch the packet filter, and there is no supported workaround.
#
# Each control owns its own chain (KCM-<ID>) which is jumped from INPUT or
# OUTPUT. One chain per control means applying, re-applying, and rolling back a
# single control never disturbs the others, and it avoids depending on the
# iptables comment module, which is missing from a fair number of Android
# kernels.

fw_chain_name() { printf 'KCM-%s' "$1"; }

fw_binaries_for_family() {
    case "$1" in
        v4)   printf 'iptables' ;;
        v6)   printf 'ip6tables' ;;
        both) printf 'iptables\nip6tables' ;;
    esac
}

fw_chain_exists() {
    # $1 = binary, $2 = chain
    sys_iptables "$1" -n -L "$2" >/dev/null 2>&1
}

fw_chain_rule_count() {
    # $1 = binary, $2 = chain. Prints the number of rules in the chain.
    local out
    out="$(sys_iptables "$1" -S "$2" 2>/dev/null || true)"
    [ -n "$out" ] || { printf '0'; return 0; }
    # -S prints one "-N CHAIN" line followed by one line per rule.
    printf '%s' "$(printf '%s\n' "$out" | grep -c -- '^-A ' || true)"
}

fw_jump_exists() {
    # $1 = binary, $2 = hook, $3 = chain
    sys_iptables "$1" -C "$2" -j "$3" >/dev/null 2>&1
}

fw_control_families() {
    # Distinct binaries a control needs, derived from its rule list.
    local id="$1" rules line fam
    rules="$(control_data "$id" rules)"
    {
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            fam="${line%% *}"
            fw_binaries_for_family "$fam"
        done <<< "$rules"
    } | sort -u
}

fw_expected_rule_count() {
    # Rules that will land in this control's chain for a given binary.
    local id="$1" bin="$2" rules line fam n=0
    rules="$(control_data "$id" rules)"
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        fam="${line%% *}"
        case "$fam" in
            both) n=$((n + 1)) ;;
            v4) [ "$bin" = 'iptables' ] && n=$((n + 1)) ;;
            v6) [ "$bin" = 'ip6tables' ] && n=$((n + 1)) ;;
        esac
    done <<< "$rules"
    printf '%s' "$n"
}

fw_test() {
    local id="$1" chain hook bin expected actual missing=''
    chain="$(fw_chain_name "$id")"
    hook="$(control_data "$id" hook)"

    while IFS= read -r bin; do
        [ -n "$bin" ] || continue
        if ! sys_have "$bin"; then
            verdict_unknown "$bin is not available on this device"
            return 0
        fi
        if ! fw_chain_exists "$bin" "$chain"; then
            missing="$missing $bin:chain"
            continue
        fi
        expected="$(fw_expected_rule_count "$id" "$bin")"
        actual="$(fw_chain_rule_count "$bin" "$chain")"
        if [ "$actual" != "$expected" ]; then
            missing="$missing $bin:rules($actual/$expected)"
            continue
        fi
        fw_jump_exists "$bin" "$hook" "$chain" || missing="$missing $bin:jump"
    done <<< "$(fw_control_families "$id")"

    if [ -n "$missing" ]; then
        verdict_bad "not installed:${missing}"
    else
        verdict_ok "chain $chain active on $hook"
    fi
}

fw_apply() {
    local id="$1" chain hook bin rules line fam args
    chain="$(fw_chain_name "$id")"
    hook="$(control_data "$id" hook)"
    rules="$(control_data "$id" rules)"

    while IFS= read -r bin; do
        [ -n "$bin" ] || continue
        sys_have "$bin" || continue

        if [ "$KCM_DRYRUN" -eq 1 ]; then
            kcm_log change "would create $bin chain $chain and hook it into $hook"
            continue
        fi

        if ! fw_chain_exists "$bin" "$chain"; then
            sys_iptables "$bin" -N "$chain" >/dev/null 2>&1 || true
            journal_append fwchain "$id" "bin=$bin" "chain=$chain" "hook=$hook"
        fi
        sys_iptables "$bin" -F "$chain" >/dev/null 2>&1 || true

        while IFS= read -r line; do
            [ -n "$line" ] || continue
            fam="${line%% *}"
            args="${line#* }"
            case "$fam" in
                both) ;;
                v4) [ "$bin" = 'iptables' ]  || continue ;;
                v6) [ "$bin" = 'ip6tables' ] || continue ;;
            esac
            # Word splitting is intended here: the rule string is an argv.
            # shellcheck disable=SC2086
            sys_iptables "$bin" -A "$chain" $args >/dev/null 2>&1 || true
        done <<< "$rules"

        if ! fw_jump_exists "$bin" "$hook" "$chain"; then
            sys_iptables "$bin" -I "$hook" 1 -j "$chain" >/dev/null 2>&1 || true
        fi
    done <<< "$(fw_control_families "$id")"
}

register_firewall_control() {
    # Thin wrapper so the catalogue below reads as data.
    register_control --capability root --test fw_test --apply fw_apply "$@"
}

# ---------------------------------------------------------------------------
# FW-001  Default-deny inbound
# ---------------------------------------------------------------------------
# The single highest-value control here. An nmap sweep from a Kali box on the
# same Wi-Fi learns nothing from a phone that answers nothing. Loopback and
# established flows are accepted first so outbound traffic and Termux's own
# local services keep working.

fw_base_test() {
    local bin policy ok=1 detail=''
    for bin in iptables ip6tables; do
        sys_have "$bin" || continue
        policy="$(sys_iptables "$bin" -S INPUT 2>/dev/null | head -1 || true)"
        case "$policy" in
            *'-P INPUT DROP'*) detail="$detail $bin:drop" ;;
            *) ok=0; detail="$detail $bin:${policy:-unknown}" ;;
        esac
    done
    if ! fw_chain_exists iptables "$(fw_chain_name KCM-FW-001)"; then
        ok=0
    fi
    if [ "$ok" -eq 1 ]; then
        verdict_ok "inbound default policy is DROP"
    else
        verdict_bad "inbound default policy is not DROP:${detail}"
    fi
}

fw_base_apply() {
    local id="$1" chain bin policy
    chain="$(fw_chain_name "$id")"

    for bin in iptables ip6tables; do
        sys_have "$bin" || continue

        if [ "$KCM_DRYRUN" -eq 1 ]; then
            kcm_log change "would set $bin INPUT policy to DROP with loopback and established traffic allowed"
            continue
        fi

        policy="$(sys_iptables "$bin" -S INPUT 2>/dev/null | head -1 || true)"
        policy="${policy##* }"

        if ! fw_chain_exists "$bin" "$chain"; then
            sys_iptables "$bin" -N "$chain" >/dev/null 2>&1 || true
            journal_append fwchain "$id" "bin=$bin" "chain=$chain" "hook=INPUT"
        fi
        sys_iptables "$bin" -F "$chain" >/dev/null 2>&1 || true
        sys_iptables "$bin" -A "$chain" -i lo -j ACCEPT >/dev/null 2>&1 || true
        sys_iptables "$bin" -A "$chain" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || true
        # DHCP replies, without which the device cannot get a lease on Wi-Fi.
        sys_iptables "$bin" -A "$chain" -p udp --sport 67 --dport 68 -j ACCEPT >/dev/null 2>&1 || true

        fw_jump_exists "$bin" INPUT "$chain" || sys_iptables "$bin" -I INPUT 1 -j "$chain" >/dev/null 2>&1 || true

        journal_append fwpolicy "$id" "bin=$bin" "chain=INPUT" "policy=${policy:-ACCEPT}"
        sys_iptables "$bin" -P INPUT DROP >/dev/null 2>&1 || true
    done
}

register_control \
    --id FW-001 \
    --name 'Default-deny inbound packet filter' \
    --category Firewall \
    --tier baseline \
    --capability root \
    --test fw_base_test \
    --apply fw_base_apply \
    --counters 'nmap, masscan, unauthenticated service discovery' \
    --rationale 'Accepts loopback, established flows and DHCP replies, then drops everything else arriving from the network. A scan from another host on the same Wi-Fi gets no response at all.' \
    --tags 'firewall netfilter scanning'

register_firewall_control \
    --id FW-002 \
    --name 'Block inbound ADB (5555/5037)' \
    --category Firewall \
    --tier baseline \
    --counters 'adb connect, Metasploit android/meterpreter via adb, PhoneSploit' \
    --rationale 'Wireless debugging on port 5555 is the most direct remote takeover path against an Android phone and is routinely scanned for. This blocks it at the filter even if the setting gets re-enabled.' \
    --tags 'firewall adb' \
    --data 'hook=INPUT' \
    --data 'rules=both -p tcp --dport 5555 -j DROP
both -p tcp --dport 5037 -j DROP'

register_firewall_control \
    --id FW-003 \
    --name 'Block name-resolution poisoning (LLMNR/mDNS/NBNS/SSDP)' \
    --category Firewall \
    --tier baseline \
    --counters 'Responder, Inveigh, bettercap, evil-twin credential capture' \
    --rationale 'Drops broadcast name resolution in both directions. Responder works by answering queries nobody else claims, so a device that never asks cannot be answered.' \
    --tags 'firewall poisoning responder' \
    --data 'hook=OUTPUT' \
    --data 'rules=both -p udp --dport 5355 -j DROP
v4 -p udp --dport 5353 -j DROP
v6 -p udp --dport 5353 -j DROP
v4 -p udp --dport 137 -j DROP
v4 -p udp --dport 138 -j DROP
v4 -p udp --dport 1900 -j DROP
both -p udp --dport 3702 -j DROP'

register_firewall_control \
    --id FW-004 \
    --name 'Block inbound Termux and sideloaded service ports' \
    --category Firewall \
    --tier baseline \
    --counters 'hydra, medusa, ncrack, evil-winrm style brute force, KDE Connect abuse' \
    --rationale 'Termux sshd defaults to 8022 and people leave web servers on 8080/8081. These stay reachable on loopback for local use but are dropped from the network.' \
    --tags 'firewall termux bruteforce' \
    --data 'hook=INPUT' \
    --data 'rules=both ! -i lo -p tcp --dport 8022 -j DROP
both ! -i lo -p tcp --dport 8080 -j DROP
both ! -i lo -p tcp --dport 8081 -j DROP
both ! -i lo -p tcp --dport 1716 -j DROP
both ! -i lo -p udp --dport 1716 -j DROP'

register_firewall_control \
    --id FW-005 \
    --name 'Drop ICMP echo and timestamp probes' \
    --category Firewall \
    --tier standard \
    --counters 'nmap -sn host discovery, fping, ICMP timestamp fingerprinting' \
    --rationale 'Removes the phone from ping sweeps. Destination-unreachable and packet-too-big are left alone because dropping those breaks path MTU discovery.' \
    --tags 'firewall scanning' \
    --data 'hook=INPUT' \
    --data 'rules=v4 -p icmp --icmp-type echo-request -j DROP
v4 -p icmp --icmp-type timestamp-request -j DROP
v6 -p icmpv6 --icmpv6-type echo-request -j DROP'

register_firewall_control \
    --id FW-006 \
    --name 'Drop malformed and out-of-state TCP probes' \
    --category Firewall \
    --tier standard \
    --counters 'nmap -sN, -sF, -sX, -sA, OS fingerprinting' \
    --rationale 'NULL, FIN and Xmas scans rely on how a host responds to flag combinations no real connection produces. Dropping them silently removes the fingerprinting signal.' \
    --tags 'firewall scanning fingerprinting' \
    --data 'hook=INPUT' \
    --data 'rules=both -p tcp --tcp-flags ALL NONE -j DROP
both -p tcp --tcp-flags ALL ALL -j DROP
both -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
both -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
both -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
both -m conntrack --ctstate INVALID -j DROP'

register_firewall_control \
    --id FW-007 \
    --name 'Rate-limit new inbound connections' \
    --category Firewall \
    --tier standard \
    --counters 'hydra, patator, slow port sweeps' \
    --rationale 'Caps how fast an attacker can open new connections, which turns a fast credential-stuffing run against any listening service into something that takes long enough to notice.' \
    --tags 'firewall bruteforce' \
    --data 'hook=INPUT' \
    --data 'rules=both -p tcp --syn -m limit --limit 12/minute --limit-burst 20 -j RETURN
both -p tcp --syn -j DROP'

register_firewall_control \
    --id FW-008 \
    --name 'Log dropped inbound packets' \
    --category Firewall \
    --tier standard \
    --counters 'provides the evidence trail the sweep uses to spot a scan in progress' \
    --rationale 'Rate-limited kernel logging with a KCM-DROP prefix. Sweep mode parses these to reconstruct which source addresses probed how many distinct ports.' \
    --tags 'firewall logging telemetry' \
    --data 'hook=INPUT' \
    --data 'rules=both -m limit --limit 6/minute --limit-burst 12 -j LOG --log-prefix KCM-DROP  --log-level 4'

register_firewall_control \
    --id FW-009 \
    --name 'Block IPv6 router advertisements and DHCPv6' \
    --category Firewall \
    --tier aggressive \
    --counters 'mitm6, IPv6 SLAAC takeover, rogue DNS via RDNSS' \
    --rationale 'mitm6 wins by advertising itself as the IPv6 router and DNS server on a network that only really uses IPv4. Blocking RA and DHCPv6 removes the opening. This breaks genuine IPv6 connectivity, which is why it is aggressive tier.' \
    --tags 'firewall ipv6 mitm' \
    --data 'hook=INPUT' \
    --data 'rules=v6 -p icmpv6 --icmpv6-type router-advertisement -j DROP
v6 -p udp --sport 547 --dport 546 -j DROP'

register_firewall_control \
    --id FW-010 \
    --name 'Block outbound handler and implant callback ports' \
    --category Firewall \
    --tier aggressive \
    --counters 'Metasploit multi/handler, msfvenom android payloads, Empire, Villain' \
    --rationale 'Default listener ports for the common frameworks. A competent operator will move off them, but payloads generated with defaults are extremely common and this costs nothing to deny.' \
    --tags 'firewall c2 egress' \
    --data 'hook=OUTPUT' \
    --data 'rules=both -p tcp --dport 4444 -j REJECT
both -p tcp --dport 4445 -j REJECT
both -p tcp --dport 1337 -j REJECT
both -p tcp --dport 8443 -j REJECT
both -p tcp --dport 9001 -j REJECT
both -p tcp --dport 31337 -j REJECT'
