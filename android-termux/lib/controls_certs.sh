#!/usr/bin/env bash
# TLS interception detection.
#
# Installing a CA certificate on the target phone and pointing it at a proxy is
# the standard way a Kali box reads a phone's traffic, and it is the attack most
# people never check for because nothing on the device looks wrong afterwards.

KCM_TLS_PROBE_HOST="${KCM_TLS_PROBE_HOST:-www.google.com}"

# ---------------------------------------------------------------------------
# Pure helpers (unit tested)
# ---------------------------------------------------------------------------

tls_issuer_is_interceptor() {
    # Names that proxies put in their generated CA. Matching is on the product
    # name, which these tools do not bother to change by default.
    printf '%s' "$1" | grep -qiE '(portswigger|burp|mitmproxy|charles proxy|fiddler|ettercap|bettercap|sslsplit|zap root ca|owasp zap|squid|mitm)'
}

tls_issuer_is_known_ca() {
    printf '%s' "$1" | grep -qiE "(digicert|let's encrypt|isrg|globalsign|sectigo|comodo|amazon|google trust services|gts ca|entrust|godaddy|starfield|certum|buypass|identrust|baltimore|quovadis|thawte|verisign|microsoft (azure )?(rsa|ecc)? ?tls|apple public server)"
}

classify_tls_issuer() {
    # Prints: interception | trusted | unrecognised
    local issuer="$1"
    if [ -z "$issuer" ]; then
        printf 'unrecognised'
    elif tls_issuer_is_interceptor "$issuer"; then
        printf 'interception'
    elif tls_issuer_is_known_ca "$issuer"; then
        printf 'trusted'
    else
        printf 'unrecognised'
    fi
}

# ---------------------------------------------------------------------------
# CRT-001  Live interception probe
# ---------------------------------------------------------------------------

crt_probe_test() {
    local raw issuer verdict
    raw="$(sys_tls_issuer "$KCM_TLS_PROBE_HOST")"

    if [ -z "$raw" ]; then
        verdict_unknown "could not complete a TLS handshake with $KCM_TLS_PROBE_HOST (offline, or openssl is not installed)"
        return 0
    fi
    issuer="${raw#issuer=}"
    verdict="$(classify_tls_issuer "$issuer")"

    case "$verdict" in
        trusted)
            verdict_ok "$KCM_TLS_PROBE_HOST is served by a public CA ($issuer)"
            ;;
        interception)
            verdict_bad "TLS to $KCM_TLS_PROBE_HOST is being intercepted. The certificate was issued by '$issuer', which is a proxy CA, not a public one. Assume everything this device has sent on this network has been read."
            ;;
        *)
            verdict_bad "the certificate for $KCM_TLS_PROBE_HOST was issued by '$issuer', which is not a CA this toolkit recognises. That is expected on a corporate network with managed inspection and suspicious anywhere else."
            ;;
    esac
}

register_control \
    --id CRT-001 \
    --name 'Live TLS interception probe' \
    --category Certificates \
    --tier baseline \
    --capability none \
    --test crt_probe_test \
    --audit-only \
    --counters 'Burp Suite, mitmproxy, bettercap https proxy, sslsplit, SSL stripping setups' \
    --rationale 'Performs one real handshake and inspects who signed the certificate that came back. This is the check that notices a proxy regardless of how its CA got onto the device.' \
    --tags 'certificates mitm audit'

# ---------------------------------------------------------------------------
# CRT-002  User-installed certificate authorities
# ---------------------------------------------------------------------------

KCM_USER_CA_PATHS='/data/misc/user/0/cacerts-added /data/misc/keychain/cacerts-added /data/misc/user/0/cacerts'

crt_userca_test() {
    local dir found='' count=0 entries
    for dir in $KCM_USER_CA_PATHS; do
        sys_file_exists "$dir" || continue
        entries="$(sys_privileged_run ls -1 "$dir" 2>/dev/null || true)"
        [ -n "$entries" ] || continue
        count=$((count + $(printf '%s\n' "$entries" | grep -c . || true)))
        found="$found $dir"
    done

    if [ "$count" -eq 0 ]; then
        verdict_ok 'no user-installed certificate authorities'
    else
        verdict_bad "$count user-installed CA(s) under:$found. Android shows a persistent warning for these, but people dismiss it. Any one of them can sign a certificate for any site."
    fi
}

register_control \
    --id CRT-002 \
    --name 'User-installed certificate authorities' \
    --category Certificates \
    --tier baseline \
    --capability root \
    --test crt_userca_test \
    --audit-only \
    --counters 'Burp CA installation, mitmproxy cert, corporate inspection certificates' \
    --rationale 'Enumerates the user CA store directly. Needs root because that directory is not readable by an app. Review in Settings > Security > Encryption & credentials > Trusted credentials > User if you do not have root.' \
    --tags 'certificates mitm audit'
