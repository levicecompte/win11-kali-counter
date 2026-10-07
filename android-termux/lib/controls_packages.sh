#!/usr/bin/env bash
# Installed-application exposure.
#
# Android malware delivered by a pen-test framework does not need a kernel bug.
# It asks for accessibility, gets granted it, and from then on can read the
# screen and synthesise taps. Every control here is audit-only: the toolkit
# reports what holds dangerous authority and leaves revocation to you, because
# disabling the wrong accessibility service can lock a user out of their phone.

# ---------------------------------------------------------------------------
# Pure helpers (unit tested)
# ---------------------------------------------------------------------------

parse_pm_package_line() {
    # Turns "package:com.foo.bar installer=com.android.vending" into
    # "com.foo.bar<TAB>com.android.vending". Prints nothing for other lines.
    local line="$1" pkg installer=''
    case "$line" in
        package:*) ;;
        *) return 0 ;;
    esac
    line="${line#package:}"
    pkg="${line%% *}"
    case "$line" in
        *installer=*)
            installer="${line##*installer=}"
            installer="${installer%% *}"
            ;;
    esac
    [ "$installer" = 'null' ] && installer=''
    printf '%s\t%s\n' "$pkg" "$installer"
}

installer_is_sideload() {
    # An app installed by the package installer UI, by adb, or with no recorded
    # installer did not come from a vetted store.
    case "$1" in
        com.android.vending|com.google.android.feedback) return 1 ;;
        com.amazon.venezia|com.sec.android.app.samsungapps) return 1 ;;
        org.fdroid.fdroid|com.aurora.store) return 1 ;;
        *) return 0 ;;
    esac
}

split_colon_list() {
    # Android stores multi-value secure settings as colon-separated lists.
    printf '%s' "$1" | tr ':' '\n' | grep -v '^[[:space:]]*$' || true
}

component_package() {
    # "com.foo/.Service" -> "com.foo"
    printf '%s' "${1%%/*}"
}

# ---------------------------------------------------------------------------
# PKG-001  Accessibility services
# ---------------------------------------------------------------------------

pkg_accessibility_test() {
    local enabled services count list
    if ! sys_have settings; then
        verdict_unknown 'the settings provider is not reachable, so bound services cannot be listed'
        return 0
    fi
    enabled="$(sys_settings_get secure accessibility_enabled)"
    services="$(sys_settings_get secure enabled_accessibility_services)"

    if [ -z "$enabled" ] && [ -z "$services" ]; then
        verdict_ok 'no accessibility services are enabled'
        return 0
    fi
    if [ -z "$services" ]; then
        verdict_ok 'accessibility is on but no third-party service is bound'
        return 0
    fi

    list="$(split_colon_list "$services")"
    count="$(printf '%s\n' "$list" | grep -c . || true)"
    verdict_bad "$count accessibility service(s) bound: $(printf '%s' "$list" | tr '\n' ' '). An accessibility service can read everything on screen and inject taps, which is how Android RATs operate without any exploit. Confirm you recognise each one."
}

register_control \
    --id PKG-001 \
    --name 'Accessibility services in use' \
    --category Packages \
    --tier baseline \
    --capability none \
    --test pkg_accessibility_test \
    --audit-only \
    --counters 'AhMyth, L3MON, Cerberus-class RATs, overlay credential theft' \
    --rationale 'The highest-value permission on Android and the one social-engineering payloads always ask for. Reported, never revoked automatically: screen readers are also accessibility services and turning one off blindly can lock someone out of their device.' \
    --tags 'packages accessibility audit'

# ---------------------------------------------------------------------------
# PKG-002  Notification listeners
# ---------------------------------------------------------------------------

pkg_notification_test() {
    local listeners list count
    if ! sys_have settings; then
        verdict_unknown 'the settings provider is not reachable, so notification listeners cannot be listed'
        return 0
    fi
    listeners="$(sys_settings_get secure enabled_notification_listeners)"
    if [ -z "$listeners" ]; then
        verdict_ok 'no app is reading your notifications'
        return 0
    fi
    list="$(split_colon_list "$listeners")"
    count="$(printf '%s\n' "$list" | grep -c . || true)"
    verdict_bad "$count notification listener(s): $(printf '%s' "$list" | tr '\n' ' '). A notification listener sees SMS and authenticator codes as they arrive, which defeats SMS-based second factors."
}

register_control \
    --id PKG-002 \
    --name 'Notification listeners in use' \
    --category Packages \
    --tier baseline \
    --capability none \
    --test pkg_notification_test \
    --audit-only \
    --counters 'OTP interception, SMS-based 2FA bypass, banking trojans' \
    --rationale 'Notification access is how a malicious app reads one-time codes without ever requesting the SMS permission.' \
    --tags 'packages notifications audit'

# ---------------------------------------------------------------------------
# PKG-003  Sideloaded application inventory
# ---------------------------------------------------------------------------

pkg_sideload_test() {
    local raw line parsed pkg installer hits='' count=0
    raw="$(sys_pm_list_packages)"
    if [ -z "$raw" ]; then
        verdict_unknown 'the package manager did not return an inventory from this shell'
        return 0
    fi

    while IFS= read -r line; do
        parsed="$(parse_pm_package_line "$line")"
        [ -n "$parsed" ] || continue
        pkg="${parsed%%$'\t'*}"
        installer="${parsed##*$'\t'}"
        if installer_is_sideload "$installer"; then
            count=$((count + 1))
            [ "$count" -le 25 ] && hits="$hits ${pkg}[${installer:-no installer}]"
        fi
    done <<< "$raw"

    if [ "$count" -eq 0 ]; then
        verdict_ok 'every installed package came from a known store'
    else
        verdict_bad "$count package(s) were not installed from a store:$hits"
    fi
}

register_control \
    --id PKG-003 \
    --name 'Sideloaded application inventory' \
    --category Packages \
    --tier baseline \
    --capability none \
    --test pkg_sideload_test \
    --audit-only \
    --counters 'msfvenom APKs, adb install payloads, repackaged trojans' \
    --rationale 'A payload installed over adb or from a downloaded APK records no store as its installer. This lists them so an unexpected entry stands out; it does not judge them by name, because the name is whatever the attacker chose.' \
    --tags 'packages sideload audit'

# ---------------------------------------------------------------------------
# PKG-004/005  App operations that need shell access to enumerate
# ---------------------------------------------------------------------------

pkg_appop_test() {
    local id="$1" op out count
    op="$(control_data "$id" op)"

    if ! sys_have cmd; then
        verdict_unknown 'the cmd binary is not reachable from this shell'
        return 0
    fi
    out="$(sys_privileged_run cmd appops query-op "$op" allow 2>/dev/null || true)"
    if [ -z "$out" ]; then
        verdict_ok "no app holds $op"
        return 0
    fi
    count="$(printf '%s\n' "$out" | grep -c . || true)"
    verdict_bad "$count app(s) hold $op: $(printf '%s' "$out" | tr '\n' ' ')"
}

register_control \
    --id PKG-004 \
    --name 'Apps allowed to install other apps' \
    --category Packages \
    --tier standard \
    --capability shell \
    --test pkg_appop_test \
    --audit-only \
    --counters 'dropper APKs, second-stage payload installation' \
    --rationale 'REQUEST_INSTALL_PACKAGES is what lets an already-installed app install the next one without you going near a store. Browsers and file managers legitimately hold it; anything else is worth a look.' \
    --tags 'packages appops audit' \
    --data 'op=REQUEST_INSTALL_PACKAGES'

register_control \
    --id PKG-005 \
    --name 'Apps allowed to draw over other apps' \
    --category Packages \
    --tier standard \
    --capability shell \
    --test pkg_appop_test \
    --audit-only \
    --counters 'tapjacking, overlay phishing, Cloak and Dagger style attacks' \
    --rationale 'Overlay permission lets an app paint a fake login box on top of a real one. Combined with accessibility it is a complete credential-theft chain that needs no exploit.' \
    --tags 'packages appops overlay audit' \
    --data 'op=SYSTEM_ALERT_WINDOW'

# ---------------------------------------------------------------------------
# PKG-006  Device administrators
# ---------------------------------------------------------------------------

pkg_deviceadmin_test() {
    local out admins count
    out="$(sys_dumpsys device_policy)"
    if [ -z "$out" ]; then
        verdict_unknown 'device policy state needs shell access to read'
        return 0
    fi
    admins="$(printf '%s\n' "$out" | grep -oE 'ComponentInfo\{[^}]+\}' | sed 's/ComponentInfo{//; s/}//' | sort -u || true)"
    count="$(printf '%s\n' "$admins" | grep -c . || true)"

    if [ "${count:-0}" -eq 0 ]; then
        verdict_ok 'no device administrator is active'
    else
        verdict_bad "$count device administrator(s): $(printf '%s' "$admins" | tr '\n' ' '). A device admin can lock or wipe the phone and resists uninstallation, which is why malware requests it."
    fi
}

register_control \
    --id PKG-006 \
    --name 'Device administrator applications' \
    --category Packages \
    --tier standard \
    --capability shell \
    --test pkg_deviceadmin_test \
    --audit-only \
    --counters 'ransomware lock screens, uninstall-resistant RATs' \
    --rationale 'Device admin status is what stops you uninstalling a malicious app the normal way. Expect your employer MDM here and little else.' \
    --tags 'packages deviceadmin audit'
