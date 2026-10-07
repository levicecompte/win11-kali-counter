#!/usr/bin/env bats
# Structural tests over the control catalogue. These run without an Android
# device because the catalogue is pure declaration: registering a control does
# not touch the system.

setup() {
    load "$BATS_TEST_DIRNAME/helper.bash"
    load_toolkit
}

# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------

@test "the catalogue registers controls and every id is unique" {
    [ "${#KCM_CONTROL_IDS[@]}" -gt 30 ]
    local unique
    unique="$(printf '%s\n' "${KCM_CONTROL_IDS[@]}" | sort -u | wc -l)"
    [ "$unique" -eq "${#KCM_CONTROL_IDS[@]}" ]
}

@test "every control declares a name, category, test function and rationale" {
    local id
    for id in "${KCM_CONTROL_IDS[@]}"; do
        [ -n "$(kcm_control_field "$id" name)" ]      || { echo "$id has no name"; return 1; }
        [ -n "$(kcm_control_field "$id" category)" ]  || { echo "$id has no category"; return 1; }
        [ -n "$(kcm_control_field "$id" test)" ]      || { echo "$id has no test"; return 1; }
        [ -n "$(kcm_control_field "$id" rationale)" ] || { echo "$id has no rationale"; return 1; }
        [ -n "$(kcm_control_field "$id" counters)" ]  || { echo "$id names no tooling"; return 1; }
    done
}

@test "every test and apply function actually exists" {
    local id fn
    for id in "${KCM_CONTROL_IDS[@]}"; do
        fn="$(kcm_control_field "$id" test)"
        declare -F "$fn" >/dev/null || { echo "$id references missing test function $fn"; return 1; }
        fn="$(kcm_control_field "$id" apply)"
        if [ -n "$fn" ]; then
            declare -F "$fn" >/dev/null || { echo "$id references missing apply function $fn"; return 1; }
        fi
    done
}

@test "every control has a valid tier and capability" {
    local id tier cap
    for id in "${KCM_CONTROL_IDS[@]}"; do
        tier="$(kcm_control_field "$id" tier)"
        cap="$(kcm_control_field "$id" capability)"
        case "$tier" in baseline|standard|aggressive) ;; *) echo "$id tier=$tier"; return 1 ;; esac
        case "$cap" in none|shell|root) ;; *) echo "$id capability=$cap"; return 1 ;; esac
    done
}

@test "a control either has an apply function or is marked audit-only" {
    local id
    for id in "${KCM_CONTROL_IDS[@]}"; do
        if [ -z "$(kcm_control_field "$id" apply)" ]; then
            [ "$(kcm_control_field "$id" audit_only)" = '1' ] || { echo "$id has neither"; return 1; }
        fi
    done
}

@test "control ids follow the CATEGORY-NNN convention" {
    local id
    for id in "${KCM_CONTROL_IDS[@]}"; do
        printf '%s' "$id" | grep -qE '^(FW|NET|DEV|TMX|PKG|CRT)-[0-9]{3}$' \
            || { echo "unexpected id format: $id"; return 1; }
    done
}

# ---------------------------------------------------------------------------
# Encryption exclusion
# ---------------------------------------------------------------------------
# The user asked for everything except BitLocker. On Android the equivalent is
# device encryption and the lockscreen credential that protects its keys. The
# exclusion is enforced three ways and all three are tested.

@test "no registered control carries an excluded subsystem tag" {
    local id tag excluded
    for id in "${KCM_CONTROL_IDS[@]}"; do
        for tag in $(kcm_control_field "$id" tags); do
            for excluded in $KCM_EXCLUDED_TAGS; do
                if [ "$tag" = "$excluded" ]; then
                    echo "$id is tagged $tag"
                    return 1
                fi
            done
        done
    done
}

@test "register_control refuses a control tagged with an excluded subsystem" {
    run register_control --id ZZZ-999 --name 'should not register' \
        --category Device --test dev_selinux_test --audit-only \
        --rationale 'x' --counters 'x' --tags 'device fbe'
    [ "$status" -ne 0 ]
    printf '%s' "$output" | grep -qi 'excluded subsystem'
}

@test "register_control refuses the lockscreen credential tag specifically" {
    run register_control --id ZZZ-998 --name 'should not register' \
        --category Device --test dev_selinux_test --audit-only \
        --rationale 'x' --counters 'x' --tags 'lockscreen-credential'
    [ "$status" -ne 0 ]
}

@test "no source file invokes an encryption or lockscreen-credential command" {
    # Matches the commands themselves, not the words: "cryptfs" appears in the
    # exclusion tag list and must stay there.
    local hits
    hits="$(grep -rnE '\b(locksettings|fscryptctl|manage-bde)\b|vdc[[:space:]]+cryptfs|cmd[[:space:]]+lock_settings|[[:space:]]set-(pin|password|pattern)\b|[A-Za-z]+-BitLocker\b' \
        "$TOOLKIT_ROOT/lib" "$TOOLKIT_ROOT/kali-counter.sh" 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        echo "$hits"
        return 1
    fi
}

@test "the exclusion list still contains the subsystems it is meant to cover" {
    local required tag
    for required in bitlocker fbe fde cryptfs lockscreen-credential; do
        printf '%s' "$KCM_EXCLUDED_TAGS" | tr ' ' '\n' | grep -qx "$required" \
            || { echo "$required dropped out of the exclusion list"; return 1; }
    done
    # Keep the list itself honest: it is referenced by the register guard.
    for tag in $KCM_EXCLUDED_TAGS; do
        [ -n "$tag" ]
    done
}

# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

@test "tiers are cumulative" {
    local b s a
    b="$(select_controls baseline '' '' '' | wc -l)"
    s="$(select_controls standard '' '' '' | wc -l)"
    a="$(select_controls aggressive '' '' '' | wc -l)"
    [ "$b" -lt "$s" ]
    [ "$s" -lt "$a" ]
    [ "$a" -eq "${#KCM_CONTROL_IDS[@]}" ]
}

@test "baseline is a strict subset of aggressive" {
    local id
    while IFS= read -r id; do
        [ -n "$id" ] || continue
        select_controls aggressive '' '' '' | grep -qx "$id" || { echo "$id missing"; return 1; }
    done <<< "$(select_controls baseline '' '' '')"
}

@test "category filtering is case-insensitive and selects only that category" {
    local out id
    out="$(select_controls aggressive 'firewall' '' '')"
    [ -n "$out" ]
    while IFS= read -r id; do
        [ -n "$id" ] || continue
        [ "$(kcm_control_field "$id" category)" = 'Firewall' ] || { echo "$id leaked in"; return 1; }
    done <<< "$out"
}

@test "multiple categories can be selected at once" {
    local out
    out="$(select_controls aggressive 'Termux,Certificates' '' '')"
    printf '%s' "$out" | grep -qx 'TMX-001'
    printf '%s' "$out" | grep -qx 'CRT-001'
    ! printf '%s' "$out" | grep -qx 'FW-001'
}

@test "include overrides the tier so a single control can be run on its own" {
    local out
    out="$(select_controls baseline '' 'FW-009' '')"
    [ "$out" = 'FW-009' ]
}

@test "exclude removes a control even when include asked for it" {
    [ -z "$(select_controls baseline '' 'FW-001' 'FW-001')" ]
}

@test "exclude removes a control selected by tier" {
    ! select_controls aggressive '' '' 'FW-001' | grep -qx 'FW-001'
    select_controls aggressive '' '' 'FW-001' | grep -qx 'FW-002'
}

# ---------------------------------------------------------------------------
# Pack-specific declarations
# ---------------------------------------------------------------------------

@test "every firewall rule names a valid address family and a hook" {
    local id rules line fam hook
    for id in "${KCM_CONTROL_IDS[@]}"; do
        rules="$(control_data "$id" rules)"
        [ -n "$rules" ] || continue
        hook="$(control_data "$id" hook)"
        case "$hook" in INPUT|OUTPUT) ;; *) echo "$id hook=$hook"; return 1 ;; esac
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            fam="${line%% *}"
            case "$fam" in v4|v6|both) ;; *) echo "$id rule family '$fam'"; return 1 ;; esac
            [ "${line#* }" != "$line" ] || { echo "$id has a rule with no arguments"; return 1; }
        done <<< "$rules"
    done
}

@test "every firewall rule ends in a target" {
    local id rules line
    for id in "${KCM_CONTROL_IDS[@]}"; do
        rules="$(control_data "$id" rules)"
        [ -n "$rules" ] || continue
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            printf '%s' "$line" | grep -qE '\-j (DROP|REJECT|ACCEPT|RETURN|LOG)\b' \
                || { echo "$id rule has no target: $line"; return 1; }
        done <<< "$rules"
    done
}

@test "firewall controls all require root and say so" {
    local id
    for id in "${KCM_CONTROL_IDS[@]}"; do
        [ "$(kcm_control_field "$id" category)" = 'Firewall' ] || continue
        [ "$(kcm_control_field "$id" capability)" = 'root' ] \
            || { echo "$id does not require root"; return 1; }
    done
}

@test "every settings control targets a real settings namespace" {
    local id settings line ns
    for id in "${KCM_CONTROL_IDS[@]}"; do
        settings="$(control_data "$id" settings)"
        [ -n "$settings" ] || continue
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            ns="${line%% *}"
            case "$ns" in global|secure|system) ;; *) echo "$id namespace=$ns"; return 1 ;; esac
            # namespace, key and value must all be present
            [ "$(printf '%s' "$line" | wc -w)" -ge 3 ] || { echo "$id incomplete: $line"; return 1; }
        done <<< "$settings"
    done
}

@test "chain names stay inside the iptables length limit" {
    local id chain
    for id in "${KCM_CONTROL_IDS[@]}"; do
        [ "$(kcm_control_field "$id" category)" = 'Firewall' ] || continue
        chain="$(fw_chain_name "$id")"
        [ "${#chain}" -le 28 ] || { echo "$chain is too long for iptables"; return 1; }
    done
}

@test "ADB is countered at both the setting and the packet filter" {
    # Belt and braces on purpose: the setting can be turned back on from the UI,
    # the firewall rule survives that.
    printf '%s' "$(control_data DEV-002 settings)" | grep -q 'adb_wifi_enabled 0'
    printf '%s' "$(control_data FW-002 rules)" | grep -q 'dport 5555'
}

@test "the anti-poisoning firewall control blocks outbound, not just inbound" {
    # Responder answers queries. The defence is to stop asking, which only
    # works on the OUTPUT chain.
    [ "$(control_data FW-003 hook)" = 'OUTPUT' ]
    printf '%s' "$(control_data FW-003 rules)" | grep -q 'dport 5355'
}
