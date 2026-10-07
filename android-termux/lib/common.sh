#!/usr/bin/env bash
# Core engine: control registry, capability detection, system seams, journal.
#
# Every control is a pair of shell functions (test + apply) registered against an
# id. The engine runs the test, decides what to do, and records anything it
# changed in a journal so `-m rollback` can put the device back.
#
# All interaction with the device goes through the sys_* seam functions near the
# top of this file. Nothing else shells out directly. That keeps the OS-touching
# surface small enough to review, and lets the test suite run the whole engine on
# a Linux box with the seams replaced by fakes.

# Read by report.sh and the entry point; shellcheck cannot see across files.
# shellcheck disable=SC2034
KCM_VERSION='1.0.0'

# ---------------------------------------------------------------------------
# Excluded subsystems
# ---------------------------------------------------------------------------
# Device encryption is deliberately out of scope, carried over from the Windows
# toolkit's BitLocker exclusion. On Android that means file-based encryption,
# full-disk encryption, vold/cryptfs, and the lockscreen credential (which is
# what the FBE class keys are derived from). This toolkit never reads or writes
# any of it: a wrong move there costs the user their data, not just a setting.
KCM_EXCLUDED_TAGS='bitlocker disk-encryption volume-encryption fbe fde cryptfs vold lockscreen-credential'

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
# Declared with -g so the registry survives being sourced from inside a
# function, which is how the test suite loads the toolkit. Without it, every
# control would register into a local array that disappears on return.
declare -gA KCM_CONTROL=()
declare -ga KCM_CONTROL_IDS=()
declare -ga KCM_RESULT_IDS=()
# shellcheck disable=SC2034  # consumed by report.sh
declare -gA KCM_RESULT=()
declare -ga KCM_FINDINGS=()

KCM_CAPABILITY='none'
KCM_JOURNAL=''
KCM_DRYRUN=0
KCM_COLOR=1
KCM_QUIET=0

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
kcm_init_color() {
    if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
        KCM_COLOR=0
    fi
}

kcm_c() {
    # $1 = colour name, $2 = text
    if [ "$KCM_COLOR" -eq 0 ]; then
        printf '%s' "$2"
        return
    fi
    local code
    case "$1" in
        red)    code='1;31' ;;
        green)  code='1;32' ;;
        yellow) code='1;33' ;;
        blue)   code='1;34' ;;
        cyan)   code='1;36' ;;
        grey)   code='0;90' ;;
        bold)   code='1'    ;;
        *)      code='0'    ;;
    esac
    printf '\033[%sm%s\033[0m' "$code" "$2"
}

kcm_log() {
    # $1 = level, $2 = message
    #
    # Quiet mode suppresses everything except errors and manual steps. A manual
    # step is work the toolkit could not do for you, so hiding it would leave
    # someone believing a rollback finished when part of it did not.
    case "$1" in
        error|manual) ;;
        *) [ "$KCM_QUIET" -eq 1 ] && return 0 ;;
    esac
    local tag
    case "$1" in
        ok)     tag="$(kcm_c green '  ok  ')" ;;
        warn)   tag="$(kcm_c yellow ' warn ')" ;;
        manual) tag="$(kcm_c yellow 'manual')" ;;
        error)  tag="$(kcm_c red ' fail ')" ;;
        info)   tag="$(kcm_c blue ' info ')" ;;
        change) tag="$(kcm_c cyan ' set  ')" ;;
        skip)   tag="$(kcm_c grey ' skip ')" ;;
        detail) printf '         %s\n' "$2" >&2; return 0 ;;
        *)      tag='      ' ;;
    esac
    printf '[%s] %s\n' "$tag" "$2" >&2
}

kcm_die() {
    kcm_log error "$1"
    exit "${2:-1}"
}

# ---------------------------------------------------------------------------
# System seams
# ---------------------------------------------------------------------------
# These are the only functions that touch the device. Tests replace them.

sys_have() {
    command -v "$1" >/dev/null 2>&1
}

sys_read_file() {
    # Prints file contents, or nothing if unreadable. Never fails the caller.
    [ -r "$1" ] || return 0
    cat -- "$1" 2>/dev/null || true
}

sys_file_exists() {
    [ -e "$1" ]
}

sys_write_file() {
    # $1 = path, stdin = content
    local dir
    dir="$(dirname -- "$1")"
    [ -d "$dir" ] || mkdir -p -- "$dir"
    cat > "$1"
}

sys_getprop() {
    sys_have getprop || return 0
    getprop "$1" 2>/dev/null || true
}

sys_settings_get() {
    # $1 = namespace (global|secure|system), $2 = key
    # Prints the value, or nothing when unset. Android prints the literal
    # string "null" for an unset key, which is normalised away here.
    sys_have settings || return 0
    local v
    v="$(settings get "$1" "$2" 2>/dev/null || true)"
    [ "$v" = 'null' ] && v=''
    printf '%s' "$v"
}

sys_settings_put() {
    # $1 = namespace, $2 = key, $3 = value
    sys_privileged_run settings put "$1" "$2" "$3"
}

sys_settings_delete() {
    # $1 = namespace, $2 = key
    sys_privileged_run settings delete "$1" "$2"
}

sys_privileged_run() {
    # Runs a command with the highest privilege currently available.
    case "$KCM_CAPABILITY" in
        root)
            if [ "$(id -u)" = '0' ]; then
                "$@"
            else
                su -c "$(kcm_quote_args "$@")"
            fi
            ;;
        shell)
            if sys_have rish; then
                rish -c "$(kcm_quote_args "$@")"
            else
                "$@"
            fi
            ;;
        *)
            return 1
            ;;
    esac
}

sys_run() {
    "$@"
}

sys_pm_list_packages() {
    sys_have pm || return 0
    pm list packages -i -u 2>/dev/null || true
}

sys_dumpsys() {
    sys_have dumpsys || return 0
    dumpsys "$@" 2>/dev/null || true
}

sys_iptables() {
    # $1 = binary (iptables|ip6tables), rest = arguments
    local bin="$1"; shift
    sys_privileged_run "$bin" "$@"
}

sys_resolve_host() {
    # Returns resolved addresses for a hostname, one per line, or nothing.
    local host="$1"
    if sys_have getent; then
        getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u || true
    elif sys_have dig; then
        dig +short +time=2 +tries=1 "$host" 2>/dev/null || true
    fi
}

sys_tls_issuer() {
    # Prints the issuer line of the certificate presented for $1:443.
    sys_have openssl || return 0
    printf '' | timeout 12 openssl s_client -connect "$1:443" -servername "$1" 2>/dev/null \
        | openssl x509 -noout -issuer 2>/dev/null || true
}

sys_epoch() {
    date +%s
}

kcm_quote_args() {
    # Builds a shell-safe single string for su -c / rish -c.
    local out='' a
    for a in "$@"; do
        out="$out $(printf '%q' "$a")"
    done
    printf '%s' "${out# }"
}

# ---------------------------------------------------------------------------
# Capability detection
# ---------------------------------------------------------------------------
# Android gives an unrooted shell almost no authority over the system. Rather
# than pretend otherwise, every control declares the privilege it needs and the
# engine reports the ones it cannot reach instead of failing them.

kcm_detect_capability() {
    if [ -n "${KCM_FORCE_CAPABILITY:-}" ]; then
        KCM_CAPABILITY="$KCM_FORCE_CAPABILITY"
        return 0
    fi

    if [ "$(id -u 2>/dev/null || echo 9999)" = '0' ]; then
        KCM_CAPABILITY='root'
        return 0
    fi
    if sys_have su && timeout 8 su -c 'id -u' 2>/dev/null | grep -q '^0$'; then
        KCM_CAPABILITY='root'
        return 0
    fi
    # uid 2000 is the Android shell user, i.e. this is running under adb.
    if [ "$(id -u 2>/dev/null || echo 9999)" = '2000' ] || sys_have rish; then
        KCM_CAPABILITY='shell'
        return 0
    fi
    KCM_CAPABILITY='none'
}

kcm_capability_rank() {
    case "$1" in
        none)  printf '0' ;;
        shell) printf '1' ;;
        root)  printf '2' ;;
        *)     printf '9' ;;
    esac
}

kcm_capability_hint() {
    case "$1" in
        shell)
            printf '%s' 'needs shell-level access: install Shizuku and the rish helper, or run this under "adb shell"'
            ;;
        root)
            printf '%s' 'needs root: Magisk or KernelSU, with su granted to Termux'
            ;;
        *)
            printf '%s' ''
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Control registry
# ---------------------------------------------------------------------------

kcm_control_field() {
    # $1 = id, $2 = field
    printf '%s' "${KCM_CONTROL[$1|$2]-}"
}

control_data() {
    # Reads a control's data bag. Controls receive their id as $1 and pull
    # parameters from here, rather than closing over variables at registration
    # time, so a control is fully described by what the registry holds.
    printf '%s' "${KCM_CONTROL[$1|data.$2]-}"
}

register_control() {
    local id='' name='' category='' tier='standard' capability='none'
    local test_fn='' apply_fn='' counters='' tags='' audit_only=0 needs_reboot=0
    local rationale=''
    declare -a data_pairs=()

    while [ $# -gt 0 ]; do
        case "$1" in
            --id)         id="$2"; shift 2 ;;
            --name)       name="$2"; shift 2 ;;
            --category)   category="$2"; shift 2 ;;
            --tier)       tier="$2"; shift 2 ;;
            --capability) capability="$2"; shift 2 ;;
            --test)       test_fn="$2"; shift 2 ;;
            --apply)      apply_fn="$2"; shift 2 ;;
            --counters)   counters="$2"; shift 2 ;;
            --rationale)  rationale="$2"; shift 2 ;;
            --tags)       tags="$2"; shift 2 ;;
            --data)       data_pairs+=("$2"); shift 2 ;;
            --audit-only) audit_only=1; shift ;;
            --reboot)     needs_reboot=1; shift ;;
            *) kcm_die "register_control: unknown argument '$1'" ;;
        esac
    done

    [ -n "$id" ]       || kcm_die 'register_control: --id is required'
    [ -n "$name" ]     || kcm_die "register_control: --name is required for $id"
    [ -n "$test_fn" ]  || kcm_die "register_control: --test is required for $id"
    [ -n "$category" ] || kcm_die "register_control: --category is required for $id"

    case "$tier" in
        baseline|standard|aggressive) ;;
        *) kcm_die "register_control: $id has unknown tier '$tier'" ;;
    esac
    case "$capability" in
        none|shell|root) ;;
        *) kcm_die "register_control: $id has unknown capability '$capability'" ;;
    esac

    if [ -n "${KCM_CONTROL[$id|name]-}" ]; then
        kcm_die "register_control: duplicate control id '$id'"
    fi

    # Encryption guard. A control that tries to reach into device encryption or
    # the lockscreen credential is refused at registration, so the exclusion
    # cannot be undone by adding a control later without also deleting this.
    local tag excluded
    for tag in $tags; do
        for excluded in $KCM_EXCLUDED_TAGS; do
            if [ "$tag" = "$excluded" ]; then
                kcm_die "register_control: '$id' is tagged '$tag', an excluded subsystem. Device encryption and the lockscreen credential are deliberately out of scope."
            fi
        done
    done

    if [ "$audit_only" -eq 0 ] && [ -z "$apply_fn" ]; then
        kcm_die "register_control: $id needs either --apply or --audit-only"
    fi

    KCM_CONTROL[$id|name]="$name"
    KCM_CONTROL[$id|category]="$category"
    KCM_CONTROL[$id|tier]="$tier"
    KCM_CONTROL[$id|capability]="$capability"
    KCM_CONTROL[$id|test]="$test_fn"
    KCM_CONTROL[$id|apply]="$apply_fn"
    KCM_CONTROL[$id|counters]="$counters"
    KCM_CONTROL[$id|rationale]="$rationale"
    KCM_CONTROL[$id|tags]="$tags"
    KCM_CONTROL[$id|audit_only]="$audit_only"
    KCM_CONTROL[$id|reboot]="$needs_reboot"

    local pair
    for pair in ${data_pairs[@]+"${data_pairs[@]}"}; do
        KCM_CONTROL[$id|data.${pair%%=*}]="${pair#*=}"
    done

    KCM_CONTROL_IDS+=("$id")
}

# ---------------------------------------------------------------------------
# Verdict helpers
# ---------------------------------------------------------------------------
# Test functions print one line: STATE|detail. Returning non-zero means the
# control could not be evaluated at all, which the engine reports as an error
# rather than silently treating as non-compliant.

verdict_ok()      { printf 'COMPLIANT|%s\n' "$1"; }
verdict_bad()     { printf 'NONCOMPLIANT|%s\n' "$1"; }
verdict_unknown() { printf 'UNKNOWN|%s\n' "$1"; }

kcm_verdict_state()  { printf '%s' "${1%%|*}"; }
kcm_verdict_detail() { local d="${1#*|}"; printf '%s' "$d"; }

# ---------------------------------------------------------------------------
# Journal
# ---------------------------------------------------------------------------
# Values are base64 encoded so arbitrary content (paths with spaces, rule text,
# multi-line file bodies) survives a line-oriented format without quoting rules.

kcm_b64() { printf '%s' "$1" | base64 | tr -d '\n'; }
kcm_unb64() { printf '%s' "$1" | base64 -d 2>/dev/null || true; }

journal_append() {
    # $1 = kind, $2 = control id, remaining args = key=value pairs
    [ -n "$KCM_JOURNAL" ] || return 0
    [ "$KCM_DRYRUN" -eq 1 ] && return 0

    local dir line kind="$1" cid="$2"
    shift 2
    dir="$(dirname -- "$KCM_JOURNAL")"
    [ -d "$dir" ] || mkdir -p -- "$dir"

    line="ts=$(sys_epoch) kind=$kind id=$cid"
    local pair
    for pair in "$@"; do
        line="$line f_${pair%%=*}=$(kcm_b64 "${pair#*=}")"
    done
    printf '%s\n' "$line" >> "$KCM_JOURNAL"
}

journal_parse_line() {
    # Prints decoded "key<TAB>value" pairs for one journal line. Pure: used by
    # rollback and by the tests.
    local line="$1" token key value
    for token in $line; do
        key="${token%%=*}"
        value="${token#*=}"
        case "$key" in
            ts|kind|id) printf '%s\t%s\n' "$key" "$value" ;;
            f_*)        printf '%s\t%s\n' "${key#f_}" "$(kcm_unb64 "$value")" ;;
        esac
    done
}

journal_field() {
    # $1 = parsed output, $2 = key
    printf '%s' "$(printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k {print $2; exit}')"
}

# ---------------------------------------------------------------------------
# Guarded mutators
# ---------------------------------------------------------------------------

guarded_settings_put() {
    # $1 = control id, $2 = namespace, $3 = key, $4 = value
    local cid="$1" ns="$2" key="$3" value="$4" old existed=0
    old="$(sys_settings_get "$ns" "$key")"
    [ -n "$old" ] && existed=1

    if [ "$KCM_DRYRUN" -eq 1 ]; then
        kcm_log change "would set $ns/$key = $value (currently '${old:-unset}')"
        return 0
    fi

    journal_append setting "$cid" "ns=$ns" "key=$key" "existed=$existed" "old=$old"
    sys_settings_put "$ns" "$key" "$value"
}

guarded_write_file() {
    # $1 = control id, $2 = path, stdin = new content
    local cid="$1" path="$2" old='' existed=0
    if sys_file_exists "$path"; then
        existed=1
        old="$(sys_read_file "$path")"
    fi

    if [ "$KCM_DRYRUN" -eq 1 ]; then
        kcm_log change "would write $path"
        cat >/dev/null
        return 0
    fi

    journal_append file "$cid" "path=$path" "existed=$existed" "old=$old"
    sys_write_file "$path"
}

# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

kcm_tier_rank() {
    case "$1" in
        baseline)   printf '0' ;;
        standard)   printf '1' ;;
        aggressive) printf '2' ;;
        *)          printf '9' ;;
    esac
}

select_controls() {
    # $1 = max tier, $2 = category filter (empty = all),
    # $3 = include csv (empty = all), $4 = exclude csv
    local max_tier="$1" cat_filter="$2" include="$3" exclude="$4"
    local max_rank id

    max_rank="$(kcm_tier_rank "$max_tier")"

    for id in ${KCM_CONTROL_IDS[@]+"${KCM_CONTROL_IDS[@]}"}; do
        if [ -n "$include" ]; then
            kcm_csv_contains "$include" "$id" || continue
        else
            [ "$(kcm_tier_rank "$(kcm_control_field "$id" tier)")" -le "$max_rank" ] || continue
            if [ -n "$cat_filter" ]; then
                kcm_csv_contains_ci "$cat_filter" "$(kcm_control_field "$id" category)" || continue
            fi
        fi
        if [ -n "$exclude" ]; then
            kcm_csv_contains "$exclude" "$id" && continue
        fi
        printf '%s\n' "$id"
    done
}

kcm_csv_contains() {
    # $1 = comma separated list, $2 = needle (exact match)
    local item
    local IFS=','
    for item in $1; do
        [ "$item" = "$2" ] && return 0
    done
    return 1
}

kcm_csv_contains_ci() {
    local item needle
    needle="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
    local IFS=','
    for item in $1; do
        [ "$(printf '%s' "$item" | tr '[:upper:]' '[:lower:]')" = "$needle" ] && return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

kcm_record_result() {
    # $1 = id, $2 = status, $3 = detail, $4 = changed
    KCM_RESULT[$1|status]="$2"
    KCM_RESULT[$1|detail]="$3"
    KCM_RESULT[$1|changed]="$4"
    KCM_RESULT_IDS+=("$1")
}

run_controls() {
    # $1 = "apply" or "audit", remaining = control ids on stdin
    local mode="$1" id
    local cap_rank_current
    cap_rank_current="$(kcm_capability_rank "$KCM_CAPABILITY")"

    while IFS= read -r id; do
        [ -n "$id" ] || continue

        local name cap need_rank status detail changed=0
        name="$(kcm_control_field "$id" name)"
        cap="$(kcm_control_field "$id" capability)"
        need_rank="$(kcm_capability_rank "$cap")"

        if [ "$need_rank" -gt "$cap_rank_current" ]; then
            kcm_record_result "$id" 'Blocked' "$(kcm_capability_hint "$cap")" 0
            kcm_log skip "$(kcm_c bold "$id") $name - $(kcm_capability_hint "$cap")"
            continue
        fi

        local raw rc=0
        raw="$("$(kcm_control_field "$id" test)" "$id" 2>/dev/null)" || rc=$?
        if [ "$rc" -ne 0 ] || [ -z "$raw" ]; then
            kcm_record_result "$id" 'Error' 'the control could not be evaluated on this device' 0
            kcm_log error "$(kcm_c bold "$id") $name - could not be evaluated"
            continue
        fi

        local state
        state="$(kcm_verdict_state "$raw")"
        detail="$(kcm_verdict_detail "$raw")"

        case "$state" in
            COMPLIANT)
                kcm_record_result "$id" 'Compliant' "$detail" 0
                kcm_log ok "$(kcm_c bold "$id") $name"
                continue
                ;;
            UNKNOWN)
                kcm_record_result "$id" 'Unknown' "$detail" 0
                kcm_log warn "$(kcm_c bold "$id") $name - $detail"
                continue
                ;;
        esac

        if [ "$(kcm_control_field "$id" audit_only)" = '1' ]; then
            kcm_record_result "$id" 'Review' "$detail" 0
            kcm_log warn "$(kcm_c bold "$id") $name - $detail"
            continue
        fi

        if [ "$mode" != 'apply' ]; then
            kcm_record_result "$id" 'Drift' "$detail" 0
            kcm_log warn "$(kcm_c bold "$id") $name - $detail"
            continue
        fi

        local arc=0
        "$(kcm_control_field "$id" apply)" "$id" >/dev/null 2>&1 || arc=$?
        if [ "$arc" -ne 0 ]; then
            kcm_record_result "$id" 'Failed' "apply returned $arc; $detail" 0
            kcm_log error "$(kcm_c bold "$id") $name - apply failed"
            continue
        fi
        changed=1

        if [ "$KCM_DRYRUN" -eq 1 ]; then
            kcm_record_result "$id" 'DryRun' "$detail" 1
            kcm_log change "$(kcm_c bold "$id") $name - would change"
            continue
        fi

        local recheck rrc=0
        recheck="$("$(kcm_control_field "$id" test)" "$id" 2>/dev/null)" || rrc=$?
        if [ "$rrc" -eq 0 ] && [ "$(kcm_verdict_state "$recheck")" = 'COMPLIANT' ]; then
            status='Remediated'
            kcm_log change "$(kcm_c bold "$id") $name"
        elif [ "$(kcm_control_field "$id" reboot)" = '1' ]; then
            status='PendingReboot'
            kcm_log warn "$(kcm_c bold "$id") $name - applied, needs a restart"
        else
            status='Failed'
            kcm_log error "$(kcm_c bold "$id") $name - still non-compliant after apply"
        fi
        kcm_record_result "$id" "$status" "$detail" "$changed"
    done
}

# ---------------------------------------------------------------------------
# Settings controls
# ---------------------------------------------------------------------------
# Most of Android's security surface lives in the settings provider. A control
# declares its desired state as newline-separated "<namespace> <key> <value>"
# lines, which keeps the catalogue declarative and lets the tests construct and
# verify every control without an Android device present.

setting_test() {
    local id="$1" line ns key want actual bad='' unset_ok
    unset_ok="$(control_data "$id" unset_ok)"

    if ! sys_have settings; then
        verdict_unknown 'the settings provider is not reachable from this shell'
        return 0
    fi

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        ns="${line%% *}"
        line="${line#* }"
        key="${line%% *}"
        want="${line#* }"
        actual="$(sys_settings_get "$ns" "$key")"

        if [ -z "$actual" ] && [ "$unset_ok" = '1' ]; then
            continue
        fi
        if [ "$actual" != "$want" ]; then
            bad="$bad $ns/$key=${actual:-unset} (want $want)"
        fi
    done <<< "$(control_data "$id" settings)"

    if [ -n "$bad" ]; then
        verdict_bad "${bad# }"
    else
        verdict_ok 'all values match'
    fi
}

setting_apply() {
    local id="$1" line ns key want
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        ns="${line%% *}"
        line="${line#* }"
        key="${line%% *}"
        want="${line#* }"
        guarded_settings_put "$id" "$ns" "$key" "$want"
    done <<< "$(control_data "$id" settings)"
}

register_setting_control() {
    register_control --test setting_test --apply setting_apply "$@"
}

# ---------------------------------------------------------------------------
# Findings (used by the sweep)
# ---------------------------------------------------------------------------

add_finding() {
    # $1 = id, $2 = severity, $3 = title, $4 = detail
    KCM_FINDINGS+=("$1|$2|$3|$4")
}
