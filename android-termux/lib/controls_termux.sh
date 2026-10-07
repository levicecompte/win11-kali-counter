#!/usr/bin/env bash
# Termux's own attack surface.
#
# This is the pack that matters most on an unrooted phone, because it is the
# only one that needs no privilege at all. It is also the pack most people skip:
# a Termux install with sshd on 8022 and password authentication is a far softer
# target than anything in the Android system, and hydra will find it in minutes.

KCM_PREFIX="${KCM_PREFIX:-${PREFIX:-/data/data/com.termux/files/usr}}"
KCM_HOME_DIR="${KCM_HOME_DIR:-${HOME:-/data/data/com.termux/files/home}}"

# ---------------------------------------------------------------------------
# Pure helpers (unit tested)
# ---------------------------------------------------------------------------

set_config_directive() {
    # Prints $1 with every occurrence of directive $2 (commented or not)
    # removed and a single "$2 $3" appended. Deterministic, so re-applying a
    # control never accumulates duplicate directives.
    local content="$1" key="$2" value="$3"
    printf '%s\n' "$content" \
        | grep -viE "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]" \
        | sed -e :a -e '/^\n*$/{$d;N;};/\n$/ba'
    printf '%s %s\n' "$key" "$value"
}

config_directive_value() {
    # Prints the effective (last uncommented) value of directive $2 in $1.
    printf '%s\n' "$1" \
        | grep -iE "^[[:space:]]*${2}[[:space:]]" \
        | tail -1 \
        | awk '{$1=""; sub(/^ /,""); print}'
}

rc_line_is_suspicious() {
    # Flags shell-startup lines that fetch and execute code, or open a shell
    # over a socket. Matching is on the dangerous construct itself, never on
    # program names: plenty of legitimate rc files call curl, python or eval,
    # and a false positive here tells someone their phone is backdoored when
    # it is not.
    local line="$1"

    case "$line" in
        \#*|'') return 1 ;;
    esac

    # Download piped straight into an interpreter.
    printf '%s' "$line" | grep -qE '\b(curl|wget|fetch)\b[^|;]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|k|da)?sh\b' && return 0
    # Base64 or hex blob decoded into an interpreter.
    printf '%s' "$line" | grep -qE '\b(base64|xxd|openssl[[:space:]]+enc)\b[^|;]*\|[[:space:]]*(ba|z|k|da)?sh\b' && return 0
    # Reverse shell via bash's network redirection.
    printf '%s' "$line" | grep -qE '/dev/(tcp|udp)/' && return 0
    # netcat with command execution.
    printf '%s' "$line" | grep -qE '\bn(c|cat|etcat)([.-][a-z]+)?\b[^|;]*[[:space:]]-[a-zA-Z]*e[[:space:]]' && return 0
    # An interpreter handed an encoded one-liner.
    printf '%s' "$line" | grep -qE '\b(python[23]?|perl|ruby|php)\b[[:space:]]+-c[[:space:]]+.{0,40}(socket|SOCK_STREAM|b64decode|decodestring)' && return 0

    return 1
}

path_entry_is_unsafe() {
    # An empty or relative PATH entry means the current directory is searched
    # for commands, which turns any writable directory you cd into a code
    # execution primitive.
    local entry="$1"
    [ -z "$entry" ] && return 0
    [ "$entry" = '.' ] && return 0
    case "$entry" in
        /*) return 1 ;;
        *)  return 0 ;;
    esac
}

find_unsafe_path_entries() {
    # $1 = PATH string. Prints each unsafe entry.
    local entry
    local IFS=':'
    for entry in $1; do
        path_entry_is_unsafe "$entry" && printf '%s\n' "${entry:-<empty>}"
    done
    # A trailing colon produces an empty final field that the loop above drops.
    case "$1" in
        *:) printf '%s\n' '<empty>' ;;
    esac
}

# ---------------------------------------------------------------------------
# TMX-001/002  sshd configuration
# ---------------------------------------------------------------------------

tmx_sshd_config_path() { printf '%s/etc/ssh/sshd_config' "$KCM_PREFIX"; }

tmx_sshd_test() {
    local id="$1" path content key want actual bad=''
    path="$(tmx_sshd_config_path)"

    if ! sys_file_exists "$path"; then
        verdict_ok 'openssh is not installed, so there is nothing listening'
        return 0
    fi
    content="$(sys_read_file "$path")"

    local line
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        key="${line%% *}"
        want="${line#* }"
        actual="$(config_directive_value "$content" "$key")"
        if [ "$(printf '%s' "$actual" | tr '[:upper:]' '[:lower:]')" != "$(printf '%s' "$want" | tr '[:upper:]' '[:lower:]')" ]; then
            bad="$bad $key=${actual:-unset}"
        fi
    done <<< "$(control_data "$id" directives)"

    if [ -n "$bad" ]; then
        verdict_bad "sshd_config:${bad}"
    else
        verdict_ok 'sshd_config matches'
    fi
}

tmx_sshd_apply() {
    local id="$1" path content line key want
    path="$(tmx_sshd_config_path)"
    sys_file_exists "$path" || return 0

    content="$(sys_read_file "$path")"
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        key="${line%% *}"
        want="${line#* }"
        content="$(set_config_directive "$content" "$key" "$want")"
    done <<< "$(control_data "$id" directives)"

    printf '%s\n' "$content" | guarded_write_file "$id" "$path"
}

register_control \
    --id TMX-001 \
    --name 'Termux sshd: public-key authentication only' \
    --category Termux \
    --tier baseline \
    --capability none \
    --test tmx_sshd_test \
    --apply tmx_sshd_apply \
    --reboot \
    --counters 'hydra, medusa, ncrack, patator, Metasploit ssh_login' \
    --rationale 'Termux sshd accepts passwords by default, and the password is often short because it is typed on a phone keyboard. Key-only authentication removes the entire online guessing class of attack.' \
    --tags 'termux ssh bruteforce' \
    --data 'directives=PasswordAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
MaxAuthTries 3'

register_control \
    --id TMX-002 \
    --name 'Termux sshd: listen on loopback only' \
    --category Termux \
    --tier standard \
    --capability none \
    --test tmx_sshd_test \
    --apply tmx_sshd_apply \
    --reboot \
    --counters 'nmap -p8022 sweeps, lateral movement from a compromised LAN host' \
    --rationale 'Keeps sshd usable for local scripting and adb port-forwarding while making it unreachable from the network. Standard tier because it breaks genuine remote logins from your laptop.' \
    --tags 'termux ssh exposure' \
    --data 'directives=ListenAddress 127.0.0.1'

# ---------------------------------------------------------------------------
# TMX-003  Key and config permissions
# ---------------------------------------------------------------------------

tmx_perm_test() {
    local bad='' target mode
    for target in "$KCM_HOME_DIR/.ssh" "$KCM_HOME_DIR/.ssh/authorized_keys"; do
        sys_file_exists "$target" || continue
        mode="$(stat -c '%a' "$target" 2>/dev/null || true)"
        [ -n "$mode" ] || continue
        case "$mode" in
            700|600) ;;
            *) bad="$bad $target=$mode" ;;
        esac
    done

    if [ -n "$bad" ]; then
        verdict_bad "group or world readable:${bad}"
    else
        verdict_ok 'ssh key material is not readable by other apps'
    fi
}

tmx_perm_apply() {
    local id="$1"
    if sys_file_exists "$KCM_HOME_DIR/.ssh"; then
        journal_append note "$id" 'text=chmod was applied to ~/.ssh and authorized_keys; the previous modes were non-standard'
        chmod 700 "$KCM_HOME_DIR/.ssh" 2>/dev/null || true
    fi
    if sys_file_exists "$KCM_HOME_DIR/.ssh/authorized_keys"; then
        chmod 600 "$KCM_HOME_DIR/.ssh/authorized_keys" 2>/dev/null || true
    fi
}

register_control \
    --id TMX-003 \
    --name 'Termux ssh key material permissions' \
    --category Termux \
    --tier baseline \
    --capability none \
    --test tmx_perm_test \
    --apply tmx_perm_apply \
    --counters 'LaZagne-style credential harvesting, malicious app reading shared storage' \
    --rationale 'Android isolates apps by uid, but files left group or world readable inside Termux can be reached by anything sharing that uid, including Termux plugins you installed and forgot about.' \
    --tags 'termux ssh permissions'

# ---------------------------------------------------------------------------
# TMX-004  Shell startup file integrity
# ---------------------------------------------------------------------------

tmx_rc_test() {
    local file line hits='' n=0
    for file in "$KCM_HOME_DIR/.bashrc" "$KCM_HOME_DIR/.bash_profile" "$KCM_HOME_DIR/.profile" "$KCM_HOME_DIR/.zshrc" "$KCM_PREFIX/etc/bash.bashrc" "$KCM_PREFIX/etc/profile"; do
        sys_file_exists "$file" || continue
        while IFS= read -r line; do
            if rc_line_is_suspicious "$line"; then
                n=$((n + 1))
                hits="$hits
  $file: $(printf '%s' "$line" | cut -c1-110)"
            fi
        done <<< "$(sys_read_file "$file")"
    done

    if [ "$n" -gt 0 ]; then
        verdict_bad "$n shell-startup line(s) fetch or execute remote code:$hits"
    else
        verdict_ok 'no startup file executes remote or encoded code'
    fi
}

register_control \
    --id TMX-004 \
    --name 'Shell startup files free of remote code execution' \
    --category Termux \
    --tier baseline \
    --capability none \
    --test tmx_rc_test \
    --audit-only \
    --counters 'persistence dropped by a Metasploit session, curl-pipe-sh implants, reverse shells in .bashrc' \
    --rationale 'The first thing a shell payload does to survive a reboot is append a line to .bashrc. Audit only, because the toolkit will not edit your shell configuration on a guess: it shows you the line and you decide.' \
    --tags 'termux persistence audit'

# ---------------------------------------------------------------------------
# TMX-005  PATH hygiene
# ---------------------------------------------------------------------------

tmx_path_test() {
    local unsafe
    unsafe="$(find_unsafe_path_entries "${PATH}")"
    if [ -n "$unsafe" ]; then
        verdict_bad "PATH contains relative or empty entries: $(printf '%s' "$unsafe" | tr '\n' ' ')"
    else
        verdict_ok 'every PATH entry is absolute'
    fi
}

register_control \
    --id TMX-005 \
    --name 'PATH contains no relative entries' \
    --category Termux \
    --tier standard \
    --capability none \
    --test tmx_path_test \
    --audit-only \
    --counters 'binary planting, command hijacking from a writable working directory' \
    --rationale 'A relative or empty PATH entry means commands get searched for in whatever directory you happen to be in. Dropping a file named ls into a shared folder is then enough to run code.' \
    --tags 'termux path audit'

# ---------------------------------------------------------------------------
# TMX-006  World-writable executables
# ---------------------------------------------------------------------------

tmx_writable_test() {
    local hits count
    hits="$(find "$KCM_PREFIX/bin" -maxdepth 1 -perm -o+w -type f 2>/dev/null | head -20 || true)"
    count="$(printf '%s' "$hits" | grep -c . || true)"

    if [ "${count:-0}" -gt 0 ]; then
        verdict_bad "$count world-writable executable(s) in the Termux bin directory: $(printf '%s' "$hits" | tr '\n' ' ')"
    else
        verdict_ok "no world-writable executables in $KCM_PREFIX/bin"
    fi
}

tmx_writable_apply() {
    local id="$1" file
    while IFS= read -r file; do
        [ -n "$file" ] || continue
        journal_append note "$id" "text=removed the world-writable bit from $file"
        chmod o-w "$file" 2>/dev/null || true
    done <<< "$(find "$KCM_PREFIX/bin" -maxdepth 1 -perm -o+w -type f 2>/dev/null || true)"
}

register_control \
    --id TMX-006 \
    --name 'No world-writable executables in the Termux bin directory' \
    --category Termux \
    --tier standard \
    --capability none \
    --test tmx_writable_test \
    --apply tmx_writable_apply \
    --counters 'persistence by overwriting a trusted binary, supply-chain tampering' \
    --rationale 'Anything that can write to a binary on your PATH owns every shell you open afterwards.' \
    --tags 'termux permissions persistence'
