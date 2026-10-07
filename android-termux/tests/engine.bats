#!/usr/bin/env bats
# Engine behaviour: how the run loop classifies results, what it writes to the
# journal, and whether rollback puts things back. The settings provider is
# replaced with an associative array so the whole apply/rollback cycle runs
# here with no Android involved.

setup() {
    load "$BATS_TEST_DIRNAME/helper.bash"
    load_toolkit
    install_fake_settings
    KCM_CAPABILITY='shell'
    KCM_JOURNAL="$BATS_TEST_TMPDIR/journal.log"
}

register_probe() {
    # A one-setting control used as the subject of most tests below.
    register_setting_control \
        --id "${1:-TST-001}" \
        --name 'test probe' \
        --category Device \
        --tier baseline \
        --capability shell \
        --counters 'test' \
        --rationale 'test' \
        --tags 'test' \
        --data "settings=global ${2:-probe_key} ${3:-1}"
}

status_of() { printf '%s' "${KCM_RESULT[$1|status]}"; }

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

@test "a matching setting is reported compliant and nothing is written" {
    register_probe
    FAKE_SETTINGS[global/probe_key]='1'

    run_controls audit <<< 'TST-001'

    [ "$(status_of TST-001)" = 'Compliant' ]
    [ ! -f "$KCM_JOURNAL" ]
}

@test "audit mode reports drift and changes nothing" {
    register_probe
    FAKE_SETTINGS[global/probe_key]='0'

    run_controls audit <<< 'TST-001'

    [ "$(status_of TST-001)" = 'Drift' ]
    [ "${FAKE_SETTINGS[global/probe_key]}" = '0' ]
    [ ! -f "$KCM_JOURNAL" ]
}

@test "apply mode fixes the setting and records it as remediated" {
    register_probe
    FAKE_SETTINGS[global/probe_key]='0'

    run_controls apply <<< 'TST-001'

    [ "$(status_of TST-001)" = 'Remediated' ]
    [ "${FAKE_SETTINGS[global/probe_key]}" = '1' ]
    [ "${KCM_RESULT[TST-001|changed]}" = '1' ]
}

@test "an unset value is treated as compliant when the control allows it" {
    register_setting_control --id TST-010 --name 'unset ok' --category Device \
        --tier baseline --capability shell --counters t --rationale t --tags test \
        --data 'settings=global absent_key 0' --data 'unset_ok=1'

    run_controls audit <<< 'TST-010'

    [ "$(status_of TST-010)" = 'Compliant' ]
}

@test "a control needing more privilege than the shell has is blocked, not failed" {
    register_setting_control --id TST-002 --name 'needs root' --category Firewall \
        --tier baseline --capability root --counters t --rationale t --tags test \
        --data 'settings=global probe_key 1'

    run_controls apply <<< 'TST-002'

    [ "$(status_of TST-002)" = 'Blocked' ]
    printf '%s' "${KCM_RESULT[TST-002|detail]}" | grep -q 'needs root'
}

@test "an audit-only control is reported for review and never applied" {
    probe_test() { verdict_bad 'something to look at'; }
    register_control --id TST-003 --name 'audit only' --category Packages \
        --tier baseline --capability none --test probe_test --audit-only \
        --counters t --rationale t --tags test

    run_controls apply <<< 'TST-003'

    [ "$(status_of TST-003)" = 'Review' ]
    [ "${KCM_RESULT[TST-003|changed]}" = '0' ]
}

@test "an unknown verdict is surfaced rather than treated as a failure" {
    probe_test() { verdict_unknown 'not readable here'; }
    register_control --id TST-004 --name 'unknown' --category Device \
        --tier baseline --capability none --test probe_test --audit-only \
        --counters t --rationale t --tags test

    run_controls audit <<< 'TST-004'

    [ "$(status_of TST-004)" = 'Unknown' ]
}

@test "a control whose test function errors does not stop the rest of the run" {
    broken_test() { return 7; }
    register_control --id TST-005 --name 'broken' --category Device \
        --tier baseline --capability none --test broken_test --audit-only \
        --counters t --rationale t --tags test
    register_probe TST-006
    FAKE_SETTINGS[global/probe_key]='1'

    run_controls audit <<< "$(printf 'TST-005\nTST-006\n')"

    [ "$(status_of TST-005)" = 'Error' ]
    [ "$(status_of TST-006)" = 'Compliant' ]
}

@test "a control that stays non-compliant after apply is reported failed" {
    stuck_test() { verdict_bad 'will not change'; }
    noop_apply() { return 0; }
    register_control --id TST-007 --name 'stuck' --category Device \
        --tier baseline --capability none --test stuck_test --apply noop_apply \
        --counters t --rationale t --tags test

    run_controls apply <<< 'TST-007'

    [ "$(status_of TST-007)" = 'Failed' ]
}

@test "a reboot-flagged control that stays non-compliant is pending, not failed" {
    stuck_test() { verdict_bad 'needs a restart first'; }
    noop_apply() { return 0; }
    register_control --id TST-008 --name 'needs reboot' --category Termux \
        --tier baseline --capability none --test stuck_test --apply noop_apply --reboot \
        --counters t --rationale t --tags test

    run_controls apply <<< 'TST-008'

    [ "$(status_of TST-008)" = 'PendingReboot' ]
}

@test "an apply function that returns an error is reported failed" {
    bad_test() { verdict_bad 'no'; }
    failing_apply() { return 4; }
    register_control --id TST-009 --name 'apply fails' --category Device \
        --tier baseline --capability none --test bad_test --apply failing_apply \
        --counters t --rationale t --tags test

    run_controls apply <<< 'TST-009'

    [ "$(status_of TST-009)" = 'Failed' ]
    printf '%s' "${KCM_RESULT[TST-009|detail]}" | grep -q 'returned 4'
}

# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------

@test "dry run leaves the device alone and writes no journal" {
    register_probe
    FAKE_SETTINGS[global/probe_key]='0'
    KCM_DRYRUN=1

    run_controls apply <<< 'TST-001'

    [ "$(status_of TST-001)" = 'DryRun' ]
    [ "${FAKE_SETTINGS[global/probe_key]}" = '0' ]
    [ ! -f "$KCM_JOURNAL" ]
}

# ---------------------------------------------------------------------------
# Journal
# ---------------------------------------------------------------------------

@test "applying writes a journal entry holding the previous value" {
    register_probe
    FAKE_SETTINGS[global/probe_key]='0'

    run_controls apply <<< 'TST-001'

    [ -f "$KCM_JOURNAL" ]
    local parsed
    parsed="$(journal_parse_line "$(head -1 "$KCM_JOURNAL")")"
    [ "$(journal_field "$parsed" kind)" = 'setting' ]
    [ "$(journal_field "$parsed" id)" = 'TST-001' ]
    [ "$(journal_field "$parsed" key)" = 'probe_key' ]
    [ "$(journal_field "$parsed" existed)" = '1' ]
    [ "$(journal_field "$parsed" old)" = '0' ]
}

@test "the journal distinguishes a value that was absent from one that was zero" {
    register_probe TST-011 absent_key 1
    run_controls apply <<< 'TST-011'

    local parsed
    parsed="$(journal_parse_line "$(head -1 "$KCM_JOURNAL")")"
    [ "$(journal_field "$parsed" existed)" = '0' ]
}

@test "journal fields survive values containing spaces and punctuation" {
    register_probe TST-012 dns_host 'dns.quad9.net, backup=1'
    run_controls apply <<< 'TST-012'

    local parsed
    parsed="$(journal_parse_line "$(tail -1 "$KCM_JOURNAL")")"
    [ "$(journal_field "$parsed" key)" = 'dns_host' ]
    [ "${FAKE_SETTINGS[global/dns_host]}" = 'dns.quad9.net, backup=1' ]
}

# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------

@test "rollback restores the value that was there before apply" {
    register_probe
    FAKE_SETTINGS[global/probe_key]='0'
    run_controls apply <<< 'TST-001'
    [ "${FAKE_SETTINGS[global/probe_key]}" = '1' ]

    restore_journal "$KCM_JOURNAL"

    [ "${FAKE_SETTINGS[global/probe_key]}" = '0' ]
}

@test "rollback removes a key that did not exist before apply" {
    register_probe TST-013 brand_new_key 1
    run_controls apply <<< 'TST-013'
    [ "${FAKE_SETTINGS[global/brand_new_key]}" = '1' ]

    restore_journal "$KCM_JOURNAL"

    [ -z "${FAKE_SETTINGS[global/brand_new_key]-}" ]
}

@test "rollback replays newest first so the original value wins" {
    # Two controls write the same key in sequence. Replaying oldest-first would
    # leave the intermediate value behind instead of the original.
    register_probe TST-014 shared_key 1
    register_probe TST-015 shared_key 2
    FAKE_SETTINGS[global/shared_key]='original'

    run_controls apply <<< "$(printf 'TST-014\nTST-015\n')"
    [ "${FAKE_SETTINGS[global/shared_key]}" = '2' ]

    restore_journal "$KCM_JOURNAL"

    [ "${FAKE_SETTINGS[global/shared_key]}" = 'original' ]
}

@test "rollback archives the journal so it cannot be replayed twice" {
    register_probe
    FAKE_SETTINGS[global/probe_key]='0'
    run_controls apply <<< 'TST-001'

    restore_journal "$KCM_JOURNAL"

    [ ! -f "$KCM_JOURNAL" ]
    ls "$KCM_JOURNAL".*.done >/dev/null
}

@test "rollback on a missing journal reports the problem instead of claiming success" {
    run restore_journal "$BATS_TEST_TMPDIR/nope.log"
    [ "$status" -ne 0 ]
}

@test "rollback surfaces manual notes rather than silently dropping them" {
    journal_append note 'TST-016' 'text=restore this by hand'
    run restore_journal "$KCM_JOURNAL"
    printf '%s' "$output" | grep -q 'restore this by hand'
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

@test "summarise_results tallies statuses" {
    register_probe TST-017 key_a 1
    register_probe TST-018 key_b 1
    FAKE_SETTINGS[global/key_a]='1'
    FAKE_SETTINGS[global/key_b]='0'

    run_controls audit <<< "$(printf 'TST-017\nTST-018\n')"

    local out
    out="$(summarise_results)"
    printf '%s' "$out" | grep -qx 'Compliant 1'
    printf '%s' "$out" | grep -qx 'Drift 1'
}

@test "informational findings do not count as actionable" {
    add_finding 'SWP-X' 'info' 'just a note' 'detail'
    [ "$(findings_actionable_count)" -eq 0 ]
    add_finding 'SWP-Y' 'critical' 'real problem' 'detail'
    [ "$(findings_actionable_count)" -eq 1 ]
}

@test "the JSON report is valid and carries the exclusion statement" {
    register_probe
    FAKE_SETTINGS[global/probe_key]='1'
    run_controls audit <<< 'TST-001'
    add_finding 'SWP-TLS-01' 'critical' 'TLS intercepted' 'issuer "PortSwigger" & <proxy>'

    export_json "$BATS_TEST_TMPDIR/report.json"

    jq -e '.controls[0].id == "TST-001"' "$BATS_TEST_TMPDIR/report.json" >/dev/null
    jq -e '.findings[0].severity == "critical"' "$BATS_TEST_TMPDIR/report.json" >/dev/null
    jq -e '.excludedSubsystems | index("device-encryption")' "$BATS_TEST_TMPDIR/report.json" >/dev/null
}

@test "the HTML report escapes device-supplied text" {
    register_probe
    FAKE_SETTINGS[global/probe_key]='1'
    run_controls audit <<< 'TST-001'
    add_finding 'SWP-X' 'high' '<script>alert(1)</script>' 'detail & more'

    export_html "$BATS_TEST_TMPDIR/report.html"

    grep -q '&lt;script&gt;' "$BATS_TEST_TMPDIR/report.html"
    ! grep -q '<script>alert' "$BATS_TEST_TMPDIR/report.html"
    grep -q 'out of scope' "$BATS_TEST_TMPDIR/report.html"
}
