#!/usr/bin/env bash
# Output: terminal summary, self-contained HTML, and JSON for pipelines.

html_escape() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' \
        | awk 'BEGIN{ORS=""} {if (NR>1) printf "\\n"; print}'
}

status_symbol() {
    case "$1" in
        Compliant|Remediated) printf 'ok' ;;
        Drift|Review|Unknown|PendingReboot|DryRun) printf 'warn' ;;
        Failed|Error) printf 'bad' ;;
        Blocked) printf 'blocked' ;;
        *) printf 'warn' ;;
    esac
}

summarise_results() {
    # Prints "status count" lines in a stable order.
    local id s
    declare -A tally=()
    for id in ${KCM_RESULT_IDS[@]+"${KCM_RESULT_IDS[@]}"}; do
        s="${KCM_RESULT[$id|status]}"
        tally[$s]=$(( ${tally[$s]:-0} + 1 ))
    done
    for s in Compliant Remediated Drift Review PendingReboot DryRun Blocked Unknown Failed Error; do
        [ -n "${tally[$s]:-}" ] && printf '%s %s\n' "$s" "${tally[$s]}"
    done
    return 0
}

print_summary() {
    local line status count total=0
    printf '\n'
    printf '%s\n' "$(kcm_c bold '  Summary')"
    printf '  %s\n' '--------------------------------------------'

    while read -r status count; do
        [ -n "$status" ] || continue
        total=$((total + count))
        case "$(status_symbol "$status")" in
            ok)      printf '  %-16s %s\n' "$status" "$(kcm_c green "$count")" ;;
            bad)     printf '  %-16s %s\n' "$status" "$(kcm_c red "$count")" ;;
            blocked) printf '  %-16s %s\n' "$status" "$(kcm_c grey "$count")" ;;
            *)       printf '  %-16s %s\n' "$status" "$(kcm_c yellow "$count")" ;;
        esac
    done <<< "$(summarise_results)"

    printf '  %s\n' '--------------------------------------------'
    printf '  %-16s %s\n' 'Controls' "$total"
    printf '  %-16s %s\n' 'Privilege' "$KCM_CAPABILITY"

    local blocked
    blocked="$(summarise_results | awk '$1=="Blocked" {print $2}')"
    if [ -n "$blocked" ]; then
        printf '\n'
        kcm_log info "$blocked control(s) need more privilege than this shell has."
        kcm_log detail "shell access: install Shizuku, then the rish helper, and launch Termux from Shizuku"
        kcm_log detail "root access:  Magisk or KernelSU, with su granted to Termux"
    fi

    local pending=''
    local id
    for id in ${KCM_RESULT_IDS[@]+"${KCM_RESULT_IDS[@]}"}; do
        if [ "${KCM_RESULT[$id|status]}" = 'PendingReboot' ] || \
           { [ "${KCM_RESULT[$id|changed]}" = '1' ] && [ "$(kcm_control_field "$id" reboot)" = '1' ]; }; then
            pending="$pending$id $(kcm_control_field "$id" name)"$'\n'
        fi
    done
    if [ -n "$pending" ]; then
        printf '\n'
        kcm_log warn 'Restart the affected service or the device before these take effect:'
        while IFS= read -r line; do
            [ -n "$line" ] && kcm_log detail "$line"
        done <<< "$pending"
    fi
}

print_findings() {
    local entry id sev title detail n=0
    [ "${#KCM_FINDINGS[@]}" -eq 0 ] && { kcm_log ok 'Sweep found nothing to report'; return 0; }

    printf '\n'
    printf '%s\n' "$(kcm_c bold '  Threat sweep')"
    printf '  %s\n' '--------------------------------------------'

    for entry in "${KCM_FINDINGS[@]}"; do
        id="${entry%%|*}"; entry="${entry#*|}"
        sev="${entry%%|*}"; entry="${entry#*|}"
        title="${entry%%|*}"
        detail="${entry#*|}"
        n=$((n + 1))

        case "$sev" in
            critical) printf '  %s  %s %s\n' "$(kcm_c red "[$sev]")" "$(kcm_c bold "$id")" "$title" ;;
            high)     printf '  %s  %s %s\n' "$(kcm_c red "[$sev]")" "$(kcm_c bold "$id")" "$title" ;;
            medium)   printf '  %s  %s %s\n' "$(kcm_c yellow "[$sev]")" "$(kcm_c bold "$id")" "$title" ;;
            *)        printf '  %s  %s %s\n' "$(kcm_c grey "[$sev]")" "$(kcm_c bold "$id")" "$title" ;;
        esac
        printf '          %s\n' "$detail"
    done
    printf '  %s\n' '--------------------------------------------'
    if [ "$n" -eq 1 ]; then
        printf '  1 finding\n'
    else
        printf '  %s findings\n' "$n"
    fi
}

findings_actionable_count() {
    # Informational findings (such as recording a gateway MAC for the first
    # time) are reported but must not make the exit code non-zero, or every
    # first run on a new network looks like an incident.
    local entry sev n=0
    for entry in ${KCM_FINDINGS[@]+"${KCM_FINDINGS[@]}"}; do
        entry="${entry#*|}"
        sev="${entry%%|*}"
        case "$sev" in
            critical|high|medium) n=$((n + 1)) ;;
        esac
    done
    printf '%s' "$n"
}

export_json() {
    local path="$1" id first=1
    {
        printf '{\n'
        printf '  "tool": "kali-counter-android",\n'
        printf '  "version": "%s",\n' "$KCM_VERSION"
        printf '  "generated": "%s",\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf '  "capability": "%s",\n' "$KCM_CAPABILITY"
        printf '  "excludedSubsystems": ["device-encryption", "lockscreen-credential"],\n'
        printf '  "controls": [\n'
        for id in ${KCM_RESULT_IDS[@]+"${KCM_RESULT_IDS[@]}"}; do
            [ "$first" -eq 1 ] || printf ',\n'
            first=0
            printf '    {"id": "%s", "name": "%s", "category": "%s", "tier": "%s", "capability": "%s", "status": "%s", "changed": %s, "detail": "%s", "counters": "%s"}' \
                "$id" \
                "$(json_escape "$(kcm_control_field "$id" name)")" \
                "$(kcm_control_field "$id" category)" \
                "$(kcm_control_field "$id" tier)" \
                "$(kcm_control_field "$id" capability)" \
                "${KCM_RESULT[$id|status]}" \
                "$([ "${KCM_RESULT[$id|changed]}" = '1' ] && printf 'true' || printf 'false')" \
                "$(json_escape "${KCM_RESULT[$id|detail]}")" \
                "$(json_escape "$(kcm_control_field "$id" counters)")"
        done
        printf '\n  ],\n'
        printf '  "findings": [\n'
        first=1
        local entry fid sev title detail
        for entry in ${KCM_FINDINGS[@]+"${KCM_FINDINGS[@]}"}; do
            fid="${entry%%|*}"; entry="${entry#*|}"
            sev="${entry%%|*}"; entry="${entry#*|}"
            title="${entry%%|*}"
            detail="${entry#*|}"
            [ "$first" -eq 1 ] || printf ',\n'
            first=0
            printf '    {"id": "%s", "severity": "%s", "title": "%s", "detail": "%s"}' \
                "$fid" "$sev" "$(json_escape "$title")" "$(json_escape "$detail")"
        done
        printf '\n  ]\n'
        printf '}\n'
    } > "$path"
    kcm_log info "JSON written to $path"
}

export_html() {
    local path="$1" id entry
    {
        cat <<'HTMLHEAD'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Android countermeasure report</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 24px 16px 64px; background: #0f1115; color: #e6e9ef;
         font: 14px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  .wrap { max-width: 1120px; margin: 0 auto; }
  h1 { font-size: 22px; margin: 0 0 4px; letter-spacing: -0.01em; }
  .sub { color: #8b93a7; margin: 0 0 24px; font-size: 13px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(132px, 1fr)); gap: 10px; margin-bottom: 26px; }
  .card { background: #171a21; border: 1px solid #242938; border-radius: 10px; padding: 12px 14px; }
  .card .n { font-size: 24px; font-weight: 650; line-height: 1.1; }
  .card .l { color: #8b93a7; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; margin-top: 2px; }
  h2 { font-size: 15px; margin: 28px 0 10px; color: #c7cddb; }
  table { width: 100%; border-collapse: collapse; table-layout: fixed; background: #141720;
          border: 1px solid #242938; border-radius: 10px; overflow: hidden; }
  col.c-id { width: 86px; } col.c-name { width: 28%; } col.c-cat { width: 110px; }
  col.c-tier { width: 92px; } col.c-cap { width: 86px; } col.c-status { width: 104px; }
  col.c-detail { width: auto; }
  th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .06em;
       color: #8b93a7; padding: 9px 10px; border-bottom: 1px solid #242938; font-weight: 600; }
  td { padding: 9px 10px; border-bottom: 1px solid #1c202b; vertical-align: top; font-size: 13px; }
  tr:last-child td { border-bottom: none; }
  td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; white-space: nowrap; }
  td.muted { color: #99a1b3; font-size: 12px; overflow-wrap: anywhere; }
  .pill { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; white-space: nowrap; }
  .ok { background: #10301f; color: #5ddc9a; } .warn { background: #352a10; color: #e7b85c; }
  .bad { background: #3a1517; color: #f3756f; } .blocked { background: #20242e; color: #8b93a7; }
  .sev-critical { background: #3a1517; color: #f3756f; } .sev-high { background: #3a2015; color: #f09a62; }
  .sev-medium { background: #352a10; color: #e7b85c; } .sev-low, .sev-info { background: #20242e; color: #8b93a7; }
  footer { margin-top: 32px; color: #6a7285; font-size: 12px; border-top: 1px solid #242938; padding-top: 14px; }
  @media (max-width: 760px) {
    table, thead, tbody, tr, td, th { display: block; width: 100%; }
    thead { display: none; }
    tr { border-bottom: 1px solid #242938; padding: 6px 0; }
    td { border: none; padding: 3px 10px; }
    td.mono { white-space: normal; }
  }
</style>
</head>
<body><div class="wrap">
HTMLHEAD

        printf '<h1>Android countermeasure report</h1>\n'
        printf '<p class="sub">Generated %s &middot; privilege level <strong>%s</strong> &middot; toolkit %s</p>\n' \
            "$(date -u '+%Y-%m-%d %H:%M UTC')" "$KCM_CAPABILITY" "$KCM_VERSION"

        printf '<div class="cards">\n'
        local status count
        while read -r status count; do
            [ -n "$status" ] || continue
            printf '<div class="card"><div class="n">%s</div><div class="l">%s</div></div>\n' "$count" "$status"
        done <<< "$(summarise_results)"
        printf '</div>\n'

        if [ "${#KCM_FINDINGS[@]}" -gt 0 ]; then
            printf '<h2>Threat sweep findings</h2>\n<table><colgroup><col class="c-id"><col class="c-tier"><col class="c-name"><col class="c-detail"></colgroup>\n'
            printf '<thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Detail</th></tr></thead><tbody>\n'
            local fid sev title detail
            for entry in "${KCM_FINDINGS[@]}"; do
                fid="${entry%%|*}"; entry="${entry#*|}"
                sev="${entry%%|*}"; entry="${entry#*|}"
                title="${entry%%|*}"
                detail="${entry#*|}"
                printf '<tr><td class="mono">%s</td><td><span class="pill sev-%s">%s</span></td><td>%s</td><td class="muted">%s</td></tr>\n' \
                    "$(html_escape "$fid")" "$sev" "$sev" "$(html_escape "$title")" "$(html_escape "$detail")"
            done
            printf '</tbody></table>\n'
        fi

        printf '<h2>Controls</h2>\n<table><colgroup><col class="c-id"><col class="c-name"><col class="c-cat"><col class="c-tier"><col class="c-cap"><col class="c-status"><col class="c-detail"></colgroup>\n'
        printf '<thead><tr><th>ID</th><th>Control</th><th>Category</th><th>Tier</th><th>Needs</th><th>Status</th><th>Detail</th></tr></thead><tbody>\n'
        for id in ${KCM_RESULT_IDS[@]+"${KCM_RESULT_IDS[@]}"}; do
            printf '<tr><td class="mono">%s</td><td>%s</td><td class="muted">%s</td><td class="muted">%s</td><td class="muted">%s</td><td><span class="pill %s">%s</span></td><td class="muted">%s</td></tr>\n' \
                "$(html_escape "$id")" \
                "$(html_escape "$(kcm_control_field "$id" name)")" \
                "$(html_escape "$(kcm_control_field "$id" category)")" \
                "$(html_escape "$(kcm_control_field "$id" tier)")" \
                "$(html_escape "$(kcm_control_field "$id" capability)")" \
                "$(status_symbol "${KCM_RESULT[$id|status]}")" \
                "$(html_escape "${KCM_RESULT[$id|status]}")" \
                "$(html_escape "${KCM_RESULT[$id|detail]}")"
        done
        printf '</tbody></table>\n'

        printf '<footer>Device encryption and the lockscreen credential are deliberately out of scope and are never read or modified by this toolkit.</footer>\n'
        printf '</div></body></html>\n'
    } > "$path"
    kcm_log info "HTML report written to $path"
}
