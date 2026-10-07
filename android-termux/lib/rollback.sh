#!/usr/bin/env bash
# Undo, driven by the journal written during apply.
#
# Entries replay newest first. If two controls touched the same setting, the
# oldest entry holds the value that was there before this toolkit ran at all,
# so applying the newest first and letting the oldest win leaves the device in
# its original state rather than in an intermediate one.

restore_journal() {
    local journal="$1" restored=0 skipped=0 manual=0
    local line parsed kind cid

    if [ ! -f "$journal" ]; then
        kcm_log error "no journal at $journal; there is nothing recorded to undo"
        return 1
    fi

    kcm_log info "Replaying $(grep -c . "$journal" || true) journal entries from $journal"

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        parsed="$(journal_parse_line "$line")"
        kind="$(journal_field "$parsed" kind)"
        cid="$(journal_field "$parsed" id)"

        case "$kind" in
            setting)
                local ns key existed old
                ns="$(journal_field "$parsed" ns)"
                key="$(journal_field "$parsed" key)"
                existed="$(journal_field "$parsed" existed)"
                old="$(journal_field "$parsed" old)"
                if [ "$existed" = '1' ]; then
                    if sys_settings_put "$ns" "$key" "$old" >/dev/null 2>&1; then
                        kcm_log change "$cid restored $ns/$key = $old"
                    else
                        kcm_log error "$cid could not restore $ns/$key"
                        skipped=$((skipped + 1))
                        continue
                    fi
                else
                    if sys_settings_delete "$ns" "$key" >/dev/null 2>&1; then
                        kcm_log change "$cid removed $ns/$key, which did not exist before"
                    else
                        kcm_log error "$cid could not remove $ns/$key"
                        skipped=$((skipped + 1))
                        continue
                    fi
                fi
                restored=$((restored + 1))
                ;;

            file)
                local path existed_f old_f
                path="$(journal_field "$parsed" path)"
                existed_f="$(journal_field "$parsed" existed)"
                old_f="$(journal_field "$parsed" old)"
                if [ "$existed_f" = '1' ]; then
                    if printf '%s' "$old_f" | sys_write_file "$path"; then
                        kcm_log change "$cid restored $path"
                    fi
                elif rm -f -- "$path" 2>/dev/null; then
                    kcm_log change "$cid removed $path, which this toolkit created"
                fi
                restored=$((restored + 1))
                ;;

            fwchain)
                local bin chain hook
                bin="$(journal_field "$parsed" bin)"
                chain="$(journal_field "$parsed" chain)"
                hook="$(journal_field "$parsed" hook)"
                sys_iptables "$bin" -D "$hook" -j "$chain" >/dev/null 2>&1 || true
                sys_iptables "$bin" -F "$chain" >/dev/null 2>&1 || true
                sys_iptables "$bin" -X "$chain" >/dev/null 2>&1 || true
                kcm_log change "$cid removed $bin chain $chain"
                restored=$((restored + 1))
                ;;

            fwpolicy)
                local pbin pchain policy
                pbin="$(journal_field "$parsed" bin)"
                pchain="$(journal_field "$parsed" chain)"
                policy="$(journal_field "$parsed" policy)"
                if sys_iptables "$pbin" -P "$pchain" "$policy" >/dev/null 2>&1; then
                    kcm_log change "$cid restored $pbin $pchain policy to $policy"
                fi
                restored=$((restored + 1))
                ;;

            note)
                manual=$((manual + 1))
                kcm_log manual "$cid needs a manual step: $(journal_field "$parsed" text)"
                ;;

            *)
                skipped=$((skipped + 1))
                kcm_log warn "unrecognised journal entry of kind '$kind', left alone"
                ;;
        esac
    done <<< "$(tac "$journal" 2>/dev/null || sed '1!G;h;$!d' "$journal")"

    kcm_log info "Rollback complete: $restored restored, $skipped could not be restored, $manual need manual attention"

    if [ "$restored" -gt 0 ] && [ "$skipped" -eq 0 ]; then
        mv -- "$journal" "${journal}.$(sys_epoch).done" 2>/dev/null || true
        kcm_log info 'The journal has been archived so it cannot be replayed twice'
    fi

    [ "$skipped" -eq 0 ]
}
