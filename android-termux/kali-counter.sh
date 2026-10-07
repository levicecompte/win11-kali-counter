#!/usr/bin/env bash
#
# kali-counter.sh - Android/Termux countermeasures against pen-testing distributions
#
# Audits and hardens an Android phone against the tooling that ships with Kali
# Linux and similar distributions: network scanners, name-resolution poisoners,
# machine-in-the-middle proxies, ADB abuse and payload frameworks.
#
# Device encryption and the lockscreen credential are deliberately out of scope.
#
# Run:  bash kali-counter.sh --help
#
# shellcheck source=/dev/null

set -uo pipefail

KCM_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

for _lib in common.sh controls_firewall.sh controls_network.sh controls_device.sh \
            controls_termux.sh controls_packages.sh controls_certs.sh \
            sweep.sh rollback.sh report.sh; do
    # shellcheck disable=SC1090
    . "$KCM_ROOT/lib/$_lib"
done
unset _lib

MODE='audit'
TIER='standard'
CATEGORY=''
INCLUDE=''
EXCLUDE=''
HTML_PATH=''
JSON_PATH=''
WITH_SWEEP=0
ASSUME_YES=0

usage() {
    cat <<'HELPTEXT'
kali-counter.sh - Android countermeasures against pen-testing distributions

USAGE
    bash kali-counter.sh [options]

MODES  (-m, --mode)
    audit      Report what is wrong. Changes nothing. This is the default.
    apply      Fix what can be fixed at the selected tier, recording an undo journal.
    sweep      Read-only hunt for an attack happening right now.
    rollback   Undo everything recorded in the journal, newest change first.
    list       Print the control catalogue and exit.

OPTIONS
    -t, --tier TIER        baseline | standard | aggressive   (default: standard)
    -c, --category LIST    Comma-separated: Firewall,Network,Device,Termux,Packages,Certificates
    -i, --include LIST     Comma-separated control ids; overrides tier and category
    -x, --exclude LIST     Comma-separated control ids to skip
    -j, --journal PATH     Undo journal location (default: ~/.kali-counter/journal.log)
        --html PATH        Write a self-contained HTML report
        --json PATH        Write machine-readable JSON
        --sweep            Also run the threat sweep after audit or apply
    -n, --dry-run          Show what apply would change without changing it
    -y, --yes              Do not prompt before applying
    -q, --quiet            Only print errors
    -h, --help             This text

TIERS
    baseline     Safe on a phone you use normally.
    standard     Adds controls that may interrupt background scanning and remote
                 access you actually use. Includes baseline.
    aggressive   Assumes the phone should be invisible on the network. Disables
                 Bluetooth and IPv6 autoconfiguration. Includes standard.

EXIT CODES
    0  everything the selected tier covers is in the desired state
    1  the toolkit could not run
    2  drift, findings, or controls needing review
    3  a control failed to apply
HELPTEXT
}

while [ $# -gt 0 ]; do
    case "$1" in
        -m|--mode)     MODE="$2"; shift 2 ;;
        -t|--tier)     TIER="$2"; shift 2 ;;
        -c|--category) CATEGORY="$2"; shift 2 ;;
        -i|--include)  INCLUDE="$2"; shift 2 ;;
        -x|--exclude)  EXCLUDE="$2"; shift 2 ;;
        -j|--journal)  KCM_JOURNAL="$2"; shift 2 ;;
        --html)        HTML_PATH="$2"; shift 2 ;;
        --json)        JSON_PATH="$2"; shift 2 ;;
        --sweep)       WITH_SWEEP=1; shift ;;
        -n|--dry-run)  KCM_DRYRUN=1; shift ;;
        -y|--yes)      ASSUME_YES=1; shift ;;
        -q|--quiet)    KCM_QUIET=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        *) printf 'unknown option: %s\n\n' "$1" >&2; usage >&2; exit 1 ;;
    esac
done

case "$MODE" in
    audit|apply|sweep|rollback|list) ;;
    *) printf 'unknown mode: %s\n' "$MODE" >&2; exit 1 ;;
esac
case "$TIER" in
    baseline|standard|aggressive) ;;
    *) printf 'unknown tier: %s\n' "$TIER" >&2; exit 1 ;;
esac

kcm_init_color
[ -n "$KCM_JOURNAL" ] || KCM_JOURNAL="$KCM_STATE_DIR/journal.log"
kcm_detect_capability

print_banner() {
    [ "$KCM_QUIET" -eq 1 ] && return 0
    printf '\n'
    printf '  %s\n' "$(kcm_c bold 'kali-counter') $(kcm_c grey "v$KCM_VERSION")"
    printf '  %s\n' "$(kcm_c grey 'Android countermeasures against pen-testing distributions')"
    printf '\n'
    printf '  %-12s %s\n' 'mode' "$MODE"
    [ "$MODE" = 'audit' ] || [ "$MODE" = 'apply' ] || [ "$MODE" = 'list' ] && \
        printf '  %-12s %s\n' 'tier' "$TIER"
    printf '  %-12s %s\n' 'privilege' "$(kcm_capability_label)"
    printf '  %-12s %s\n' 'journal' "$KCM_JOURNAL"
    printf '  %-12s %s\n' 'excluded' 'device encryption, lockscreen credential'
    [ "$KCM_DRYRUN" -eq 1 ] && printf '  %-12s %s\n' 'dry run' "$(kcm_c yellow 'no changes will be made')"
    printf '\n'
    return 0
}

kcm_capability_label() {
    case "$KCM_CAPABILITY" in
        root)  printf 'root (everything available)' ;;
        shell) printf 'shell (system settings available, packet filter is not)' ;;
        *)     printf 'unprivileged (Termux controls only)' ;;
    esac
}

confirm_apply() {
    [ "$ASSUME_YES" -eq 1 ] && return 0
    [ "$KCM_DRYRUN" -eq 1 ] && return 0
    [ -t 0 ] || return 0

    printf '  %s\n' "$(kcm_c yellow 'Apply mode will change device settings.')"
    printf '  %s\n' 'An undo journal is written, and -m rollback replays it.'
    printf '  %s ' 'Continue? [y/N]'
    local answer=''
    read -r answer || true
    case "$answer" in
        y|Y|yes|YES) printf '\n'; return 0 ;;
        *) kcm_log info 'Nothing was changed.'; exit 0 ;;
    esac
}

list_controls() {
    local id
    printf '  %-9s %-13s %-11s %-6s %s\n' 'ID' 'CATEGORY' 'TIER' 'NEEDS' 'CONTROL'
    printf '  %s\n' '-------------------------------------------------------------------------------'
    while IFS= read -r id; do
        [ -n "$id" ] || continue
        printf '  %-9s %-13s %-11s %-6s %s\n' \
            "$id" \
            "$(kcm_control_field "$id" category)" \
            "$(kcm_control_field "$id" tier)" \
            "$(kcm_control_field "$id" capability)" \
            "$(kcm_control_field "$id" name)"
    done <<< "$(select_controls "$TIER" "$CATEGORY" "$INCLUDE" "$EXCLUDE")"
    printf '\n'
    printf '  %s controls selected of %s in the catalogue\n' \
        "$(select_controls "$TIER" "$CATEGORY" "$INCLUDE" "$EXCLUDE" | grep -c . || true)" \
        "${#KCM_CONTROL_IDS[@]}"
}

main() {
    print_banner

    case "$MODE" in
        list)
            list_controls
            exit 0
            ;;
        rollback)
            restore_journal "$KCM_JOURNAL" || exit 3
            exit 0
            ;;
        sweep)
            run_sweep
            print_findings
            [ -n "$JSON_PATH" ] && export_json "$JSON_PATH"
            [ -n "$HTML_PATH" ] && export_html "$HTML_PATH"
            [ "$(findings_actionable_count)" -gt 0 ] && exit 2
            exit 0
            ;;
    esac

    local selected
    selected="$(select_controls "$TIER" "$CATEGORY" "$INCLUDE" "$EXCLUDE")"
    if [ -z "$selected" ]; then
        kcm_die 'no controls matched the selected tier, category and filters'
    fi

    [ "$MODE" = 'apply' ] && confirm_apply

    # A here-string, not a pipe: a piped loop runs in a subshell and the result
    # arrays it fills would be discarded when that subshell exits.
    run_controls "$MODE" <<< "$selected"

    if [ "$WITH_SWEEP" -eq 1 ]; then
        printf '\n'
        run_sweep
    fi

    print_summary
    [ "$WITH_SWEEP" -eq 1 ] && print_findings

    [ -n "$JSON_PATH" ] && export_json "$JSON_PATH"
    [ -n "$HTML_PATH" ] && export_html "$HTML_PATH"

    if [ "$MODE" = 'apply' ] && [ "$KCM_DRYRUN" -eq 0 ] && [ -f "$KCM_JOURNAL" ]; then
        printf '\n'
        kcm_log info "Undo journal: $KCM_JOURNAL"
        kcm_log detail "revert with: bash kali-counter.sh -m rollback -j $KCM_JOURNAL"
    fi

    # Exit codes are stable so this can be driven from cron or Termux:Tasker.
    local failed problems
    failed="$(summarise_results | awk '$1=="Failed" || $1=="Error" {s+=$2} END {print s+0}')"
    problems="$(summarise_results | awk '$1=="Drift" || $1=="Review" {s+=$2} END {print s+0}')"

    [ "$failed" -gt 0 ] && exit 3
    { [ "$problems" -gt 0 ] || [ "$(findings_actionable_count)" -gt 0 ]; } && exit 2
    exit 0
}

main
