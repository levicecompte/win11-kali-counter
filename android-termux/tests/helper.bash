#!/usr/bin/env bash
# Shared setup for the bats suites.
#
# The toolkit is deliberately built so the whole catalogue and every analyser
# can be loaded on an ordinary Linux machine with no Android present. Tests
# point the Termux paths at a scratch directory and replace the sys_* seams
# where a test needs to simulate a device.

TOOLKIT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export TOOLKIT_ROOT

load_toolkit() {
    local scratch="${BATS_TEST_TMPDIR:-${BATS_TMPDIR:-/tmp}}"
    export KCM_PREFIX="$scratch/prefix"
    export KCM_HOME_DIR="$scratch/home"
    export KCM_STATE_DIR="$scratch/state"
    mkdir -p "$KCM_PREFIX/bin" "$KCM_PREFIX/etc/ssh" "$KCM_HOME_DIR" "$KCM_STATE_DIR"

    local lib
    for lib in common.sh controls_firewall.sh controls_network.sh controls_device.sh \
               controls_termux.sh controls_packages.sh controls_certs.sh \
               sweep.sh rollback.sh report.sh; do
        # shellcheck disable=SC1090
        . "$TOOLKIT_ROOT/lib/$lib"
    done

    KCM_COLOR=0
    KCM_QUIET=1
    KCM_JOURNAL="$scratch/journal.log"
}

# Loads only the files that hold pure functions, so an analyser test cannot
# accidentally depend on the catalogue having been registered.
load_analysers() {
    local scratch="${BATS_TEST_TMPDIR:-${BATS_TMPDIR:-/tmp}}"
    export KCM_PREFIX="$scratch/prefix"
    export KCM_HOME_DIR="$scratch/home"
    export KCM_STATE_DIR="$scratch/state"
    mkdir -p "$KCM_PREFIX/bin" "$KCM_PREFIX/etc/ssh" "$KCM_HOME_DIR" "$KCM_STATE_DIR"
    load_toolkit
}

# A settings provider backed by an associative array instead of Android.
install_fake_settings() {
    declare -gA FAKE_SETTINGS=()

    sys_have() {
        case "$1" in
            settings|cmd) return 0 ;;
            *) return 1 ;;
        esac
    }
    sys_settings_get() { printf '%s' "${FAKE_SETTINGS[$1/$2]-}"; }
    sys_settings_put() { FAKE_SETTINGS[$1/$2]="$3"; return 0; }
    sys_settings_delete() { unset "FAKE_SETTINGS[$1/$2]"; return 0; }
}
