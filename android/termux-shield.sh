#!/usr/bin/env bash
# =============================================================================
#  termux-shield.sh  v1.0  -  defensive hardening & detection kit for Termux
# =============================================================================
#  Counters the attack techniques that AI-assisted pentest copilots
#  (Kali GPT-style Nmap / Metasploit / Burp / Aircrack-ng / Hydra / Hashcat
#  workflows) automate - on YOUR phone, from inside Termux:
#
#    Recon / scanning   -> exposed-listener audit, sshd kill-switch, optional
#                          root iptables firewall (stealth: drops scans/ICMP)
#    Brute force        -> sshd key-only + modern crypto, failed-login detector,
#                          auto-ban (root) or sshd shutdown (no root)
#    Rogue Wi-Fi / MITM -> trusted-BSSID baseline (evil twin), gateway-MAC and
#                          ARP duplicate checks, DNS-hijack / TLS-interception /
#                          captive-portal tripwires
#    Exploitation       -> OS patch level, root/ADB/accessibility-service audit,
#                          package-repo audit, upgrade, secrets-exposure scan
#    Post-exploitation  -> reverse-shell + offensive-tool process detector,
#                          shell-startup / boot / cron persistence audit,
#                          file-integrity baseline of $PREFIX/bin, etc, ~/.ssh
#
#  Usage:   bash termux-shield.sh <command> [options]
#
#    audit                 read-only security audit (default)           [safe]
#    harden [--yes]        apply hardening (backups kept in ~/.termux-shield)
#    monitor [--once|--daemon|--stop|--status] [--autoblock]
#    baseline              (re)create file-integrity baseline
#    verify                compare files against the baseline
#    wifi-learn [--all]    trust the current Wi-Fi AP (--all: every AP that
#                          advertises the same SSID, e.g. mesh)
#    net-check             DNS / TLS / captive-portal tripwires (run on new Wi-Fi)
#    ssh-start | ssh-stop  start sshd WITH logging / stop it
#    fw-on  [--allow-port 8022,...] [--allow-ip A.B.C.D,...]   (root only)
#    fw-off                remove the iptables rules                    (root only)
#    install-boot          start the monitor at boot (needs Termux:Boot)
#    remove-boot | status | quick | help
#
#  Options: --yes  --quiet  --deep  --threshold N  --window MIN  --interval SEC
#           --ban-hours H  --fim-every N  --allow-ip IPS  --allow-port PORTS
#
#  Install:  pkg install -y curl procps iproute2 termux-api openssh
#            chmod +x termux-shield.sh && ./termux-shield.sh audit
# =============================================================================
VERSION="1.0"
set -u
umask 077

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
HOME="${HOME:-/data/data/com.termux/files/home}"
SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"
SHIELD_DIR="$HOME/.termux-shield"
LOG_DIR="$SHIELD_DIR/logs"
STATE_DIR="$SHIELD_DIR/state"
BACKUP_DIR="$SHIELD_DIR/backup"
LOG_FILE="$LOG_DIR/shield.log"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$BACKUP_DIR" 2>/dev/null
chmod 700 "$SHIELD_DIR" "$LOG_DIR" "$STATE_DIR" "$BACKUP_DIR" 2>/dev/null

# ---- defaults ---------------------------------------------------------------
WINDOW_MIN=15; THRESHOLD=5; INTERVAL=60; AUTOBLOCK=0; QUIET=0; ASSUME_YES=0
DEEP=0; FIM_EVERY=30; BAN_HOURS=24; DAEMON=0; ONCE=0; STOPFLAG=0; STATUSFLAG=0
ALLOW_PORTS=""; ALLOW_IPS=""; LEARN_ALL=0

# ---- tiny helpers -----------------------------------------------------------
have()   { command -v "$1" >/dev/null 2>&1; }
die()    { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
is_num() { case "${1:-}" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

if [ -t 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; CYN=$'\033[36m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  RED=""; GRN=""; YEL=""; CYN=""; DIM=""; RST=""
fi

PASS=0; FAILS=0

notify() {
  have termux-notification || return 0
  termux-notification --id "termux-shield" --title "Termux Shield ALERT" \
    --content "$1" --priority high >/dev/null 2>&1 &
  return 0
}

log() {  # log LEVEL message...
  local lvl="$1"; shift
  local msg="$*" ts c
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  printf '[%s][%s] %s\n' "$ts" "$lvl" "$msg" >> "$LOG_FILE" 2>/dev/null
  if [ "$QUIET" = 1 ] && [ "$lvl" != ALERT ] && [ "$lvl" != WARN ]; then return 0; fi
  case "$lvl" in
    OK) c="$GRN" ;; WARN) c="$YEL" ;; ALERT|FAIL) c="$RED" ;; STEP) c="$CYN" ;; *) c="$DIM" ;;
  esac
  printf '%s[%s]%s %s\n' "$c" "$lvl" "$RST" "$msg"
  [ "$lvl" = ALERT ] && notify "$msg"
  return 0
}
pass() { PASS=$((PASS+1));   log OK   "$*"; }
fail() { FAILS=$((FAILS+1)); log WARN "$*"; }

# keep the log small
if [ -f "$LOG_FILE" ] && [ "$(stat -c %s "$LOG_FILE" 2>/dev/null || echo 0)" -gt 2097152 ]; then
  tail -n 3000 "$LOG_FILE" > "$LOG_FILE.tmp" 2>/dev/null && mv "$LOG_FILE.tmp" "$LOG_FILE"
fi

# alert at most once per hour per key (so a 60 s monitor does not spam you)
alert_once() {  # key message...
  local key="$1"; shift
  local f="$STATE_DIR/alerted" now last
  now=$(date +%s)
  last=$(awk -v k="$key" '$1==k {t=$2} END{print t+0}' "$f" 2>/dev/null)
  if [ $(( now - ${last:-0} )) -ge 3600 ]; then
    log ALERT "$*"
    printf '%s %s\n' "$key" "$now" >> "$f"
    tail -n 500 "$f" > "$f.tmp" 2>/dev/null && mv "$f.tmp" "$f"
  fi
  return 0
}
hkey() { printf '%s' "$*" | cksum | cut -d' ' -f1; }

gp()   { have getprop && getprop "$1" 2>/dev/null; return 0; }
sget() { have settings || return 0; timeout 5 settings get "$1" "$2" 2>/dev/null | head -1; return 0; }

list_procs() {
  ps -eo pid=,args= 2>/dev/null && return 0
  ps -A -o PID,ARGS 2>/dev/null | sed 1d && return 0
  ps 2>/dev/null | sed 1d
}
proc_running() { pgrep -x "$1" >/dev/null 2>&1 || list_procs | grep -Eq "(^|[ /])$1( |\$)"; }

in_csv() { case ",$2," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
is_allowed_ip() { [ -n "$ALLOW_IPS" ] && in_csv "$1" "$ALLOW_IPS"; }

# ---- root helper (optional) -------------------------------------------------
ROOT_OK=""; RSU=""
detect_root() {
  [ -n "$ROOT_OK" ] && { [ "$ROOT_OK" = 1 ]; return; }
  ROOT_OK=0
  if [ "$(id -u)" = 0 ]; then ROOT_OK=1; RSU=""; return 0; fi
  if have su && su -c 'id -u' 2>/dev/null | grep -qx 0; then ROOT_OK=1; RSU="su -c"; return 0; fi
  return 1
}
rcmd() { if [ -z "$RSU" ]; then sh -c "$*"; else $RSU "$*"; fi; }

# =============================================================================
#  AUDIT: device / OS
# =============================================================================
audit_device() {
  log STEP "Device & Android posture"
  local rel patch crypto vbs tags dbg locked adb wadb acc nl age pe now
  rel=$(gp ro.build.version.release)
  if [ -z "$rel" ]; then log INFO "getprop unavailable (not on Android?) - device checks skipped"; return 0; fi
  patch=$(gp ro.build.version.security_patch)
  log INFO "Android $rel, security patch: ${patch:-unknown}"
  if [ -n "$patch" ]; then
    pe=$(date -d "$patch" +%s 2>/dev/null); now=$(date +%s)
    if [ -n "$pe" ]; then
      age=$(( (now - pe) / 86400 ))
      if [ "$age" -le 90 ]; then pass "Security patch is $age days old"
      else fail "Security patch is $age days old (>90): unpatched OS/kernel bugs are what exploit frameworks target - run system update"; fi
    fi
  fi
  crypto=$(gp ro.crypto.state)
  [ "$crypto" = "encrypted" ] && pass "Storage is encrypted" || fail "Storage encryption not reported as 'encrypted' (value: ${crypto:-none})"
  vbs=$(gp ro.boot.verifiedbootstate)
  case "$vbs" in
    green)  pass "Verified boot state: green" ;;
    "")     log INFO "Verified boot state not reported" ;;
    *)      fail "Verified boot state is '$vbs' (not green): bootloader unlocked or custom ROM weakens the chain of trust" ;;
  esac
  locked=$(gp ro.boot.flash.locked); [ -z "$locked" ] && locked=$(gp ro.boot.vbmeta.device_state)
  case "$locked" in
    1|locked)   pass "Bootloader locked" ;;
    0|unlocked) fail "Bootloader UNLOCKED: anyone with physical access can bypass device security" ;;
    *)          log INFO "Bootloader lock state not reported" ;;
  esac
  tags=$(gp ro.build.tags); dbg=$(gp ro.debuggable)
  [ "$tags" = "release-keys" ] && pass "Build signed with release-keys" || fail "Build tags: '${tags:-?}' (test-keys = custom/insecure build)"
  [ "$dbg" = "1" ] && fail "ro.debuggable=1 (debug build)" || pass "Not a debuggable build"
  local r=0 p
  for p in /system/bin/su /system/xbin/su /sbin/su /su/bin/su /data/adb/magisk /system/app/Superuser.apk; do
    [ -e "$p" ] && r=1
  done
  have su && r=1
  if [ "$r" = 1 ]; then log WARN "Root/su detected. Root gives Termux real firewall power (fw-on) but also means any app that gets root can own the phone - keep the root manager on 'ask every time'."
  else pass "No su binary found"; fi
  adb=$(sget global adb_enabled); wadb=$(sget global adb_wifi_enabled)
  [ "$adb" = "1" ] && fail "USB debugging is ON - disable it when not developing (Settings > Developer options)"
  [ "$wadb" = "1" ] && log ALERT "Wireless debugging is ON: remote ADB over Wi-Fi is a direct remote-control surface. Turn it off now."
  acc=$(sget secure enabled_accessibility_services)
  if [ -n "$acc" ] && [ "$acc" != "null" ]; then
    fail "Accessibility services enabled: $acc  (banking trojans abuse this - keep only services you recognise)"
  else pass "No accessibility services enabled (or not readable)"; fi
  nl=$(sget secure enabled_notification_listeners)
  if [ -n "$nl" ] && [ "$nl" != "null" ]; then
    log WARN "Notification listeners enabled (can read your 2FA codes): $nl"
  fi
  return 0
}

# =============================================================================
#  AUDIT: Termux environment integrity
# =============================================================================
audit_env() {
  log STEP "Termux environment integrity"
  log INFO "Termux ${TERMUX_VERSION:-?} installed from: ${TERMUX_APK_RELEASE:-unknown}  (keep ONE source - F-Droid or GitHub - and update regularly)"
  # LD_PRELOAD hooking
  local e bad=0
  for e in $(printf '%s' "${LD_PRELOAD:-}" | tr ':' ' '); do
    case "$e" in *libtermux-exec*) ;; *) bad=1; log WARN "Unexpected LD_PRELOAD entry: $e" ;; esac
  done
  [ "$bad" = 0 ] && pass "LD_PRELOAD clean" || FAILS=$((FAILS+1))
  # PATH hygiene
  local d pbad=0 IFS_SAVE="$IFS"
  IFS=':'
  for d in $PATH; do
    case "$d" in ""|"."|[!/]*) pbad=1; log WARN "Relative/empty entry in PATH ('$d'): command hijacking risk" ;; esac
  done
  IFS="$IFS_SAVE"
  [ "$pbad" = 0 ] && pass "PATH has only absolute entries" || FAILS=$((FAILS+1))
  return 0
}

# =============================================================================
#  AUDIT: persistence (shell startup, boot scripts, cron, services, SSH keys)
# =============================================================================
RS_RX='(nc|ncat|netcat|busybox nc) +(-[a-zA-Z]*e|-c|--exec|--sh-exec)|bash +-i *>&|/dev/(tcp|udp)/|socat .*(exec|EXEC|system|SYSTEM)|mkfifo .*(nc|ncat|telnet)|python[0-9.]* +-c .*(socket|pty\.spawn)|perl +-e .*(socket|fsockopen)|ruby +-rsocket|php +-r .*fsockopen|pwncat|meterpreter|msfvenom|chisel +(client|server)|ligolo|sliver-(client|server)|cobaltstrike'
TOOL_RX='(^| |/)(hydra|hashcat|john|aircrack-ng|airodump-ng|aireplay-ng|sqlmap|masscan|nmap|ettercap|bettercap|responder|nikto|gobuster|ffuf|wpscan|mitmproxy|mitmdump|hping3|medusa|crackmapexec|netexec|netdiscover|arpspoof|dsniff|reaver|wifite|msfconsole)( |$)'
RC_RX='curl[^|;]*\|[ ]*(ba)?sh|wget[^|;]*\|[ ]*(ba)?sh|base64 +-d[^|;]*\|[ ]*(ba)?sh|/dev/(tcp|udp)/|(^|[ ;])nc +(-[a-zA-Z]*e|-e)|ncat .*(--exec|-e )|socat .*exec|mkfifo|eval +"?\$\(curl|python[0-9.]* +-c .*(socket|urllib|requests)|LD_PRELOAD *=|PROMPT_COMMAND *=.*(curl|nc |bash -i)|alias +(sudo|su|ssh|sshd|pkg|apt|passwd|scp|termux-[a-z-]+)='

audit_persistence() {
  log STEP "Persistence (shell startup, boot scripts, cron, services, SSH keys)"
  local f hits=0 line
  local rcs=("$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshrc" "$HOME/.zshenv" "$HOME/.zprofile"
             "$PREFIX/etc/bash.bashrc" "$PREFIX/etc/profile")
  [ -d "$PREFIX/etc/profile.d" ] && for f in "$PREFIX"/etc/profile.d/*; do [ -f "$f" ] && rcs+=("$f"); done
  [ -d "$HOME/.termux/boot" ]   && for f in "$HOME"/.termux/boot/*;   do [ -f "$f" ] && rcs+=("$f"); done
  for f in "${rcs[@]}"; do
    [ -f "$f" ] || continue
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      hits=$((hits+1)); log ALERT "Suspicious line in $f -> ${line:0:110}"
    done < <(grep -nE "$RC_RX" "$f" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#')
  done
  if [ "$hits" = 0 ]; then pass "No suspicious commands in shell startup / boot files"; else FAILS=$((FAILS+1)); fi

  if [ -d "$HOME/.termux/boot" ] && [ -n "$(ls -A "$HOME/.termux/boot" 2>/dev/null)" ]; then
    log WARN "Termux:Boot scripts present (run at every reboot) - verify you wrote each one: $(ls -1 "$HOME/.termux/boot" | tr '\n' ' ')"
  else pass "No Termux:Boot scripts"; fi

  if have crontab && [ -n "$(crontab -l 2>/dev/null | grep -v '^[[:space:]]*#' | grep .)" ]; then
    log WARN "Crontab entries exist - review with: crontab -l"
  else pass "No cron jobs"; fi

  if [ -d "$PREFIX/var/service" ] && [ -n "$(ls -A "$PREFIX/var/service" 2>/dev/null)" ]; then
    log INFO "termux-services entries: $(ls -1 "$PREFIX/var/service" | tr '\n' ' ')"
  fi

  if [ -s "$HOME/.ssh/authorized_keys" ]; then
    log WARN "authorized_keys contains keys - every one of these can log in to your sshd. Verify you recognise each:"
    if have ssh-keygen; then ssh-keygen -lf "$HOME/.ssh/authorized_keys" 2>/dev/null | sed 's/^/        /'; fi
  else pass "No authorized_keys (nobody can key-login)"; fi
  return 0
}

# =============================================================================
#  AUDIT: SSH server
# =============================================================================
audit_ssh() {
  log STEP "SSH server (remote-shell attack surface)"
  local cfg="$PREFIX/etc/ssh/sshd_config"
  if ! have sshd; then pass "openssh not installed (no remote shell surface)"; return 0; fi
  if proc_running sshd; then
    log WARN "sshd is RUNNING (default port 8022) - reachable by everyone on your Wi-Fi/hotspot. Stop when idle: $SELF ssh-stop"
  else pass "sshd is not running"; fi
  [ -f "$cfg" ] || return 0
  local want k v cur def
  for want in "PasswordAuthentication no" "KbdInteractiveAuthentication no" "PermitEmptyPasswords no" \
              "PubkeyAuthentication yes" "X11Forwarding no" "AllowTcpForwarding no" "MaxAuthTries 3"; do
    k=${want%% *}; v=${want#* }
    cur=$(awk -v k="$k" 'tolower($1)==tolower(k) {print $2; exit}' "$cfg" 2>/dev/null)
    case "$k" in
      PasswordAuthentication|KbdInteractiveAuthentication|AllowTcpForwarding) def="yes" ;;
      PubkeyAuthentication) def="yes" ;;
      MaxAuthTries) def="6" ;;
      *) def="no" ;;
    esac
    [ -z "$cur" ] && cur="$def"
    if [ "$(printf '%s' "$cur" | tr 'A-Z' 'a-z')" = "$v" ]; then pass "sshd: $k = $cur"
    else fail "sshd: $k = $cur (want $v)"; fi
  done
  return 0
}

# =============================================================================
#  AUDIT: package supply chain
# =============================================================================
audit_packages() {
  log STEP "Package supply chain"
  local srcs line n
  srcs=$(cat "$PREFIX"/etc/apt/sources.list "$PREFIX"/etc/apt/sources.list.d/* 2>/dev/null | grep -E '^[[:space:]]*deb')
  if [ -z "$srcs" ]; then log INFO "No apt sources found (non-Termux environment?)"; return 0; fi
  local bad=0
  while IFS= read -r line; do
    case "$line" in
      *"trusted=yes"*|*"allow-insecure"*) bad=1; log ALERT "Repo with signature checking DISABLED: $line" ;;
      *"http://"*) bad=1; log WARN "Repo over plain HTTP (tamperable on hostile Wi-Fi): $line" ;;
    esac
  done <<< "$srcs"
  [ "$bad" = 0 ] && pass "All apt repos use HTTPS with signature checking" || FAILS=$((FAILS+1))
  if have apt; then
    n=$(apt list --upgradable 2>/dev/null | grep -c 'upgradable')
    if [ "${n:-0}" -gt 0 ]; then fail "$n package(s) upgradable (as of last 'pkg update') - run: $SELF harden"
    else pass "No pending package upgrades (as of last 'pkg update')"; fi
  fi
  return 0
}

# =============================================================================
#  AUDIT: filesystem permissions & exposure
# =============================================================================
audit_filesystem() {
  log STEP "File permissions & exposure"
  local d m k n
  for d in "$HOME" "$HOME/.ssh" "$HOME/.termux" "$SHIELD_DIR"; do
    [ -d "$d" ] || continue
    m=$(stat -c %a "$d" 2>/dev/null)
    if [ "${m: -1}" = "0" ]; then pass "$d mode $m"; else fail "$d mode $m: 'others' have access (want 700)"; fi
  done
  for k in "$HOME"/.ssh/id_*; do
    [ -f "$k" ] || continue
    case "$k" in *.pub) continue ;; esac
    m=$(stat -c %a "$k" 2>/dev/null)
    if [ "$m" = "600" ] || [ "$m" = "400" ]; then pass "Private key $k mode $m"; else fail "Private key $k mode $m (want 600)"; fi
  done
  if [ -e "$HOME/storage" ]; then
    log WARN "~/storage links exist (termux-setup-storage): any app with storage access can read files you keep there. Never put keys, tokens or dumps in shared storage."
  else pass "No shared-storage bridge"; fi
  n=$(find "$HOME" -maxdepth 4 -xdev -type f -perm -o+w 2>/dev/null | grep -v "^$HOME/storage" | wc -l)
  if [ "${n:-0}" -gt 0 ]; then fail "$n world-writable file(s) under \$HOME (find ~ -type f -perm -o+w)"; else pass "No world-writable files under \$HOME"; fi
  return 0
}

# =============================================================================
#  AUDIT: dual-use / offensive tooling installed (inventory)
# =============================================================================
audit_tools() {
  log STEP "Dual-use / offensive tools installed (inventory)"
  local t found=""
  for t in nmap hydra hashcat john msfconsole sqlmap aircrack-ng nikto masscan ettercap bettercap hping3 ncat nc socat tcpdump responder mitmproxy wifite; do
    have "$t" && found="$found $t"
  done
  if [ -n "$found" ]; then
    log INFO "Installed:$found"
    log INFO "If you do not use them, remove them ('pkg uninstall <name>'): if the phone is ever compromised they become the attacker's toolkit."
  else pass "No common offensive tools installed"; fi
  return 0
}

# =============================================================================
#  Listening sockets (what a scanner would see)
# =============================================================================
list_listeners() {  # prints "port address"
  if have ss && ss -ltnH >/dev/null 2>&1; then
    ss -ltnH 2>/dev/null | awk '{n=split($4,a,":"); print a[n], $4}'
    return 0
  fi
  local f h ip port
  for f in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$f" ] || continue
    awk 'NR>1 && $4=="0A" {print $2}' "$f" 2>/dev/null
  done | while read -r h; do
    ip=${h%:*}; port=$(( 16#${h#*:} ))
    case "$ip" in 0100007F|00000000000000000000000001000000) continue ;; esac
    case "$ip" in 00000000|00000000000000000000000000000000) ip="0.0.0.0" ;; esac
    echo "$port $ip:$port"
  done
}

audit_listeners() {
  log STEP "Listening network services visible to the LAN"
  local out port addr bad=0
  out=$(list_listeners 2>/dev/null)
  if [ -z "$out" ]; then
    log INFO "No non-loopback listeners found (or Android blocks /proc/net and 'ss' for this app - then check: ps -ef | grep -E 'sshd|http|nc|socat')"
    return 0
  fi
  while read -r port addr; do
    case "$addr" in 127.*|"[::1]:"*|"::1:"*) continue ;; esac
    if in_csv "$port" "$ALLOW_PORTS"; then log INFO "Listener on $addr (allow-listed)"
    else bad=1; log WARN "Service listening on $addr - reachable by scanners (nmap) on this network"; fi
  done <<< "$out"
  [ "$bad" = 0 ] && pass "Only allow-listed listeners" || FAILS=$((FAILS+1))
  return 0
}

# =============================================================================
#  Process detector: reverse shells and offensive tools
# =============================================================================
proc_scan() {
  log STEP "Process scan (reverse shells / offensive tools)"
  local line pid hits=0
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    [ -z "$line" ] && continue
    pid=${line%% *}
    [ "$pid" = "$$" ] && continue
    [ "$pid" = "$PPID" ] && continue
    if [[ "$line" =~ $RS_RX ]]; then
      hits=$((hits+1)); alert_once "rs-$(hkey "$line")" "Reverse-shell / C2 pattern in process: ${line:0:120}"
      if [ "$AUTOBLOCK" = 1 ] && is_num "$pid"; then kill -9 "$pid" 2>/dev/null && log ALERT "Killed process $pid"; fi
    elif [[ "$line" =~ $TOOL_RX ]]; then
      hits=$((hits+1)); log WARN "Offensive/dual-use tool running: ${line:0:120}"
    fi
  done < <(list_procs)
  [ "$hits" = 0 ] && pass "No reverse-shell or offensive-tool processes" || FAILS=$((FAILS+1))
  return 0
}

# =============================================================================
#  Secrets exposure scan (file NAMES only - contents are never printed)
# =============================================================================
scan_secrets() {
  log STEP "Secrets exposure scan (names only)"
  local rx='AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|sk-[A-Za-z0-9_-]{32,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----'
  local files f m n=0
  files=$(timeout 90 grep -rIlE \
      --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.cache --exclude-dir=storage \
      --exclude-dir=.termux-shield --exclude-dir=.npm --exclude-dir=.cargo --exclude-dir=.rustup \
      --exclude-dir=.gradle --exclude-dir=.local -e "$rx" "$HOME" 2>/dev/null | head -50)
  if [ -z "$files" ]; then pass "No credential-looking strings found under \$HOME"; return 0; fi
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    m=$(stat -c %a "$f" 2>/dev/null)
    case "$f" in
      "$HOME"/.ssh/*) if [ "$m" = "600" ] || [ "$m" = "400" ]; then log INFO "Key material in $f (mode $m) - expected"; continue; fi ;;
    esac
    n=$((n+1)); log WARN "Secret-looking data in $f (mode $m) - move to a password manager / revoke if it was ever pushed or shared"
  done <<< "$files"
  [ "$n" = 0 ] && pass "Only expected key material found" || FAILS=$((FAILS+1))
  return 0
}

# =============================================================================
#  Wi-Fi: trusted-BSSID baseline (evil twin), gateway MAC, ARP duplicates
# =============================================================================
jfield() {  # jfield "<json>" key   (termux-api prints pretty JSON, one key per line)
  sed -n "s/^[[:space:]]*\"$2\":[[:space:]]*\"\{0,1\}\(.*[^\",]\)\"\{0,1\},\{0,1\}[[:space:]]*\$/\1/p" <<< "$1" | head -1
}

wifi_scan_list() {  # prints: ssid<TAB>bssid<TAB>rssi
  have termux-wifi-scaninfo || return 0
  timeout 20 termux-wifi-scaninfo 2>/dev/null |
    sed -n 's/^[[:space:]]*"\(bssid\|ssid\|rssi\)":[[:space:]]*"\{0,1\}\(.*[^",]\)"\{0,1\},\{0,1\}[[:space:]]*$/\1=\2/p;
            s/^[[:space:]]*},\{0,1\}[[:space:]]*$/--/p' |
    awk '/^bssid=/{b=substr($0,7)} /^ssid=/{s=substr($0,6)} /^rssi=/{r=substr($0,6)}
         /^--$/{ if (b!="") print s "\t" b "\t" r; b=""; s=""; r="" }'
}

gateway_ip()  { ip route 2>/dev/null | awk '/^default/ {print $3; exit}'; }
gateway_mac() {
  local g="$1" m=""
  [ -z "$g" ] && return 0
  m=$(ip neigh show "$g" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="lladdr") print $(i+1)}' | head -1)
  [ -z "$m" ] && [ -r /proc/net/arp ] && m=$(awk -v g="$g" '$1==g {print $4; exit}' /proc/net/arp 2>/dev/null)
  case "$m" in ""|"00:00:00:00:00:00") m="" ;; esac
  printf '%s' "$m" | tr 'A-Z' 'a-z'
}

wifi_check() {
  log STEP "Wi-Fi / local-network integrity"
  if ! have termux-wifi-connectioninfo; then
    log INFO "Install Termux:API (app + 'pkg install termux-api') for Wi-Fi checks"; return 0
  fi
  local info ssid bssid ip known="$STATE_DIR/wifi_known" safe key
  info=$(timeout 10 termux-wifi-connectioninfo 2>/dev/null)
  ssid=$(jfield "$info" ssid); bssid=$(jfield "$info" bssid | tr 'A-Z' 'a-z'); ip=$(jfield "$info" ip)
  if [ -z "$ssid" ] || [ "$ssid" = "<unknown ssid>" ] || [ -z "$ip" ] || [ "$ip" = "0.0.0.0" ]; then
    log INFO "Not connected to Wi-Fi (or location permission missing for SSID)"; return 0
  fi
  log INFO "Connected: '$ssid' via $bssid"
  touch "$known"; chmod 600 "$known"
  if grep -qxF "$ssid	$bssid" "$known" 2>/dev/null; then pass "Access point is a trusted BSSID for '$ssid'"
  elif grep -q "^$ssid	" "$known" 2>/dev/null; then
    alert_once "newap-$(hkey "$ssid$bssid")" "Known network '$ssid' but UNKNOWN access point $bssid - evil twin / rogue AP (or a new mesh node: trust it with '$SELF wifi-learn')"
    FAILS=$((FAILS+1))
  else
    printf '%s\t%s\n' "$ssid" "$bssid" >> "$known"
    log INFO "First time on '$ssid' - learned its BSSID. (If this is an untrusted/public network, run: $SELF net-check)"
  fi
  # unknown APs advertising a trusted SSID nearby
  local s b r twins=0
  while IFS=$'\t' read -r s b r; do
    [ -z "$s" ] && continue
    b=$(printf '%s' "$b" | tr 'A-Z' 'a-z')
    if grep -q "^$s	" "$known" 2>/dev/null && ! grep -qxF "$s	$b" "$known" 2>/dev/null; then
      twins=$((twins+1)); log WARN "Unknown AP $b (signal $r dBm) is advertising your trusted SSID '$s' - possible evil twin"
    fi
  done < <(wifi_scan_list)
  [ "$twins" = 0 ] && pass "No unknown AP clones a trusted SSID in range (or scan unavailable)"
  # gateway MAC pinning + ARP duplicates
  local gw gm base
  gw=$(gateway_ip); gm=$(gateway_mac "$gw")
  if [ -n "$gw" ] && [ -n "$gm" ]; then
    safe=$(printf '%s' "$ssid" | tr -c 'A-Za-z0-9._-' '_')
    base="$STATE_DIR/gw_$safe"
    if [ -f "$base" ]; then
      if [ "$(cat "$base")" = "$gm" ]; then pass "Gateway $gw MAC unchanged ($gm)"
      else alert_once "gw-$(hkey "$ssid$gm")" "Gateway MAC for '$ssid' changed: $(cat "$base") -> $gm  - ARP spoofing / MITM (Ettercap/Bettercap) on this network?"; FAILS=$((FAILS+1)); fi
    else printf '%s\n' "$gm" > "$base"; log INFO "Pinned gateway $gw = $gm for '$ssid'"; fi
    key=$(ip neigh show 2>/dev/null | awk '$1 ~ /^[0-9]+\./ && /lladdr/ {c[$5]++; ips[$5]=ips[$5] " " $1} END{for(m in c) if(c[m]>1) print m ":" ips[m]}')
    if [ -n "$key" ]; then log WARN "Several IPv4 hosts share one MAC (classic ARP-spoof signature): $key"; fi
  else
    log INFO "Gateway/ARP data not readable here (Android restricts it for apps) - skipped"
  fi
  return 0
}

cmd_wifi_learn() {
  have termux-wifi-connectioninfo || die "termux-api not installed"
  local info ssid bssid known="$STATE_DIR/wifi_known" s b r
  info=$(timeout 10 termux-wifi-connectioninfo 2>/dev/null)
  ssid=$(jfield "$info" ssid); bssid=$(jfield "$info" bssid | tr 'A-Z' 'a-z')
  [ -n "$ssid" ] && [ -n "$bssid" ] || die "not connected to Wi-Fi"
  touch "$known"; chmod 600 "$known"
  grep -qxF "$ssid	$bssid" "$known" || printf '%s\t%s\n' "$ssid" "$bssid" >> "$known"
  log OK "Trusted: '$ssid' $bssid"
  if [ "$LEARN_ALL" = 1 ]; then
    while IFS=$'\t' read -r s b r; do
      [ "$s" = "$ssid" ] || continue
      b=$(printf '%s' "$b" | tr 'A-Z' 'a-z')
      grep -qxF "$s	$b" "$known" || { printf '%s\t%s\n' "$s" "$b" >> "$known"; log OK "Trusted mesh node: $b"; }
    done < <(wifi_scan_list)
  fi
}

# =============================================================================
#  Tripwires for hostile networks: DNS hijack, TLS interception, captive portal
# =============================================================================
cmd_net_check() {
  log STEP "Hostile-network tripwires"
  have curl || die "install curl: pkg install curl"
  local code rc ip site bad=0
  # 1. captive portal / HTTP injection
  code=$(curl -s -m 8 -o /dev/null -w '%{http_code}' http://connectivitycheck.gstatic.com/generate_204 2>/dev/null)
  if [ "$code" = "204" ]; then pass "HTTP probe clean (204): no captive portal / injection"
  else fail "HTTP probe returned '${code:-none}' instead of 204: captive portal, proxy or HTTP injection - do NOT log in to anything on this network"; fi
  # 2. NXDOMAIN hijacking
  ip=$(curl -s -m 8 -o /dev/null -w '%{remote_ip}' "http://akg$RANDOM$RANDOM.invalid/" 2>/dev/null); rc=$?
  if [ -z "$ip" ]; then pass "Resolver correctly refuses non-existent names (no DNS hijack)"
  else alert_once "dnshijack" "Resolver answered a non-existent name with $ip: DNS hijack / rogue DNS (Responder/Bettercap-style)"; FAILS=$((FAILS+1)); fi
  # 3. TLS interception (certificate validation against Termux's own CA bundle)
  for site in https://www.google.com https://www.cloudflare.com https://github.com; do
    curl -sS -m 10 -o /dev/null "$site" 2>/dev/null; rc=$?
    case "$rc" in
      0) ;;
      35|51|58|59|60|77|83|90|91) bad=1; log ALERT "TLS validation FAILED for $site (curl exit $rc): man-in-the-middle / TLS interception on this network" ;;
      *) log INFO "$site unreachable (curl exit $rc)" ;;
    esac
  done
  [ "$bad" = 0 ] && pass "TLS certificates validate for 3 major sites" || FAILS=$((FAILS+1))
  log INFO "Tip: Android Settings > Network > Private DNS > hostname 'dns.quad9.net' or 'one.one.one.one'; use a VPN on public Wi-Fi."
  return 0
}

# =============================================================================
#  sshd: logging, brute-force detection, banning
# =============================================================================
ssh_scan() {
  local log="$LOG_DIR/sshd.log" off_file="$STATE_DIR/sshd.offset" ev="$STATE_DIR/ssh_events" size off now
  [ -f "$log" ] || return 0
  now=$(date +%s)
  size=$(stat -c %s "$log" 2>/dev/null || echo 0); off=$(cat "$off_file" 2>/dev/null || echo 0)
  is_num "$off" || off=0
  [ "$off" -gt "$size" ] && off=0
  tail -c +"$((off+1))" "$log" 2>/dev/null |
    grep -E 'Failed |Invalid user|authenticating user|Unable to negotiate|Bad protocol|Did not receive identification|banner exchange|kex_exchange_identification|Too many authentication' |
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3} port [0-9]+' |
    awk -v t="$now" '{print t, $1}' >> "$ev"
  echo "$size" > "$off_file"
  # successful logins
  tail -c +"$((off+1))" "$log" 2>/dev/null | grep -E 'Accepted (publickey|password)' | while IFS= read -r l; do
    log WARN "SSH login: ${l:0:140}"
  done
  [ -f "$ev" ] || return 0
  awk -v now="$now" 'now-$1 < 86400' "$ev" > "$ev.tmp" 2>/dev/null && mv "$ev.tmp" "$ev"
  local c ipaddr w=$(( WINDOW_MIN * 60 ))
  while read -r c ipaddr; do
    [ -z "$ipaddr" ] && continue
    if [ "$c" -ge "$THRESHOLD" ] && ! is_allowed_ip "$ipaddr"; then
      alert_once "sshbf-$ipaddr" "SSH brute-force / scan from $ipaddr: $c attempts in ${WINDOW_MIN} min (Hydra/Medusa pattern)"
      [ "$AUTOBLOCK" = 1 ] && ban_ip "$ipaddr" "ssh brute force"
    fi
  done < <(awk -v now="$now" -v w="$w" 'now-$1 <= w {n[$2]++} END{for (i in n) print n[i], i}' "$ev")
  return 0
}

ban_ip() {  # ban_ip IP reason
  local ip="$1"; shift
  case "$ip" in ""|127.*|0.0.0.0) return 0 ;; esac
  if is_allowed_ip "$ip"; then log INFO "Not banning allow-listed $ip"; return 0; fi
  if detect_root; then
    rcmd "iptables -C INPUT -s $ip -j DROP 2>/dev/null || iptables -I INPUT 1 -s $ip -j DROP" >/dev/null 2>&1 &&
      { printf '%s %s\n' "$ip" "$(date +%s)" >> "$STATE_DIR/bans"; log ALERT "Banned $ip with iptables for ${BAN_HOURS}h ($*)"; }
  elif proc_running sshd; then
    pkill -x sshd 2>/dev/null
    log ALERT "No root firewall available: sshd STOPPED to cut off $ip ($*). Restart later with: $SELF ssh-start"
  fi
  return 0
}

expire_bans() {
  local f="$STATE_DIR/bans" now ip t
  [ -s "$f" ] || return 0
  detect_root || return 0
  now=$(date +%s)
  : > "$f.new"
  while read -r ip t; do
    if [ $(( now - t )) -ge $(( BAN_HOURS * 3600 )) ]; then
      rcmd "iptables -D INPUT -s $ip -j DROP" >/dev/null 2>&1 && log INFO "Ban on $ip expired"
    else printf '%s %s\n' "$ip" "$t" >> "$f.new"; fi
  done < "$f"
  mv "$f.new" "$f"
}

cmd_ssh_start() {
  have sshd || die "openssh not installed: pkg install openssh"
  pkill -x sshd 2>/dev/null
  ssh-keygen -A >/dev/null 2>&1
  : >> "$LOG_DIR/sshd.log"; chmod 600 "$LOG_DIR/sshd.log"
  sshd -E "$LOG_DIR/sshd.log" && log OK "sshd started on port 8022 with logging to $LOG_DIR/sshd.log (stop it when idle: $SELF ssh-stop)"
}
cmd_ssh_stop() { pkill -x sshd 2>/dev/null && log OK "sshd stopped" || log INFO "sshd was not running"; }

# =============================================================================
#  File-integrity monitoring (FIM)
# =============================================================================
fim_targets() {
  find "$PREFIX/bin" "$PREFIX/etc" -type f -print0 2>/dev/null
  find "$HOME/.ssh" "$HOME/.termux" -type f ! -name 'known_hosts*' -print0 2>/dev/null
  local f
  for f in .bashrc .bash_profile .profile .zshrc .zshenv .zprofile; do
    [ -f "$HOME/$f" ] && printf '%s\0' "$HOME/$f"
  done
  [ "$DEEP" = 1 ] && find "$PREFIX/lib" -maxdepth 1 -type f -print0 2>/dev/null
  return 0
}
fim_snapshot() { fim_targets | xargs -0 sha256sum 2>/dev/null | sort -k2; }

cmd_baseline() {
  fim_snapshot > "$STATE_DIR/fim.baseline"; chmod 600 "$STATE_DIR/fim.baseline"
  log OK "Integrity baseline saved: $(wc -l < "$STATE_DIR/fim.baseline") files. (Re-run after every pkg upgrade you made yourself. Only baseline a device you believe is clean.)"
}

cmd_verify() {
  local base="$STATE_DIR/fim.baseline" cur="$STATE_DIR/fim.current" out kind path n=0
  if [ ! -f "$base" ]; then log WARN "No integrity baseline yet - run: $SELF baseline"; return 1; fi
  fim_snapshot > "$cur"
  out=$(awk 'NR==FNR { h=$1; $1=""; sub(/^ +/,""); b[$0]=h; next }
             { h=$1; $1=""; sub(/^ +/,""); c[$0]=h }
             END { for (f in c) { if (!(f in b)) print "NEW\t" f; else if (b[f]!=c[f]) print "MODIFIED\t" f }
                   for (f in b) if (!(f in c)) print "DELETED\t" f }' "$base" "$cur" | sort)
  if [ -z "$out" ]; then pass "Integrity: no change since baseline"; return 0; fi
  while IFS=$'\t' read -r kind path; do
    n=$((n+1))
    [ "$n" -le 25 ] && alert_once "fim-$(hkey "$kind$path")" "Integrity $kind: $path"
  done <<< "$out"
  [ "$n" -gt 25 ] && log WARN "...and $((n-25)) more changed files (bulk change usually = you ran pkg upgrade: re-baseline if so)"
  FAILS=$((FAILS+1))
  return 0
}

# =============================================================================
#  Local reverse-shell / suspicious outbound connections
# =============================================================================
conn_check() {
  local f h rem port bad=0 BADP=" 4444 4445 1337 31337 5555 6666 9999 12345 54321 "
  for f in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$f" ] || continue
    while read -r h; do
      rem=${h%:*}; port=$(( 16#${h#*:} ))
      case "$BADP" in *" $port "*) bad=1; alert_once "conn-$port-$rem" "Established connection to classic backdoor/Metasploit port $port (remote hex $rem) - reverse shell?" ;; esac
    done < <(awk 'NR>1 && $4=="01" {print $3}' "$f" 2>/dev/null)
  done
  return 0
}

# =============================================================================
#  MONITOR
# =============================================================================
monitor_once() {
  ssh_scan
  expire_bans
  proc_scan >/dev/null
  conn_check
  wifi_check >/dev/null
}

cmd_monitor() {
  local pidf="$STATE_DIR/monitor.pid" pid
  if [ "$STOPFLAG" = 1 ]; then
    pid=$(cat "$pidf" 2>/dev/null)
    if [ -n "$pid" ] && kill "$pid" 2>/dev/null; then log OK "Monitor stopped"; rm -f "$pidf"; have termux-wake-unlock && termux-wake-unlock
    else log INFO "Monitor not running"; fi
    return 0
  fi
  if [ "$STATUSFLAG" = 1 ]; then
    pid=$(cat "$pidf" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then log OK "Monitor running (pid $pid)"; else log INFO "Monitor not running"; fi
    return 0
  fi
  if [ "$ONCE" = 1 ]; then monitor_once; cmd_verify; return 0; fi
  if [ "$DAEMON" = 1 ] && [ "${SHIELD_CHILD:-0}" != 1 ]; then
    pid=$(cat "$pidf" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then log INFO "Monitor already running (pid $pid)"; return 0; fi
    SHIELD_CHILD=1 nohup "$SELF" monitor --daemon --quiet \
      --threshold "$THRESHOLD" --window "$WINDOW_MIN" --interval "$INTERVAL" --ban-hours "$BAN_HOURS" --fim-every "$FIM_EVERY" \
      ${ALLOW_IPS:+--allow-ip "$ALLOW_IPS"} ${ALLOW_PORTS:+--allow-port "$ALLOW_PORTS"} \
      $([ "$AUTOBLOCK" = 1 ] && echo --autoblock) >/dev/null 2>&1 &
    echo $! > "$pidf"
    log OK "Monitor started in background (pid $!). Alerts -> Termux notifications + $LOG_FILE"
    return 0
  fi
  # foreground / daemon loop
  [ "$DAEMON" = 1 ] && echo $$ > "$pidf"
  have termux-wake-lock && [ "$DAEMON" = 1 ] && termux-wake-lock
  log INFO "Monitoring every ${INTERVAL}s (Ctrl+C to stop). autoblock=$AUTOBLOCK"
  local cycle=0
  trap 'rm -f "$pidf"; exit 0' INT TERM
  while true; do
    monitor_once
    if [ $(( cycle % FIM_EVERY )) -eq 0 ] && [ -f "$STATE_DIR/fim.baseline" ]; then cmd_verify >/dev/null; fi
    cycle=$((cycle+1))
    sleep "$INTERVAL"
  done
}

# =============================================================================
#  ROOT FIREWALL (optional, root only)
# =============================================================================
fw_apply_family() {  # fw_apply_family iptables|ip6tables
  local ipt="$1" W="" p i
  rcmd "$ipt -w -L -n >/dev/null 2>&1" && W="-w"
  rcmd "command -v $ipt >/dev/null 2>&1" || return 0
  add() { rcmd "$ipt $W -A AKG_IN $*" >/dev/null 2>&1 || log INFO "skipped (kernel lacks support): $ipt $*"; }
  rcmd "$ipt $W -N AKG_IN >/dev/null 2>&1; $ipt $W -F AKG_IN"
  add "-i lo -j RETURN"
  add "-m conntrack --ctstate ESTABLISHED,RELATED -j RETURN" || add "-m state --state ESTABLISHED,RELATED -j RETURN"
  add "-m conntrack --ctstate INVALID -j DROP"
  if [ "$ipt" = "iptables" ]; then
    add "-p tcp --tcp-flags ALL NONE -j DROP"          # NULL scan
    add "-p tcp --tcp-flags ALL ALL -j DROP"           # XMAS scan
    add "-p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP"
    add "-p tcp --tcp-flags SYN,RST SYN,RST -j DROP"
    add "-p tcp --tcp-flags FIN,RST FIN,RST -j DROP"
    add "-p tcp --tcp-flags ACK,FIN FIN -j DROP"       # FIN scan
    add "-p tcp --tcp-flags ACK,URG URG -j DROP"
    add "-p icmp --icmp-type echo-request -j DROP"     # no ping replies
  else
    add "-p icmpv6 --icmpv6-type echo-request -j DROP"
    for t in 133 134 135 136; do add "-p icmpv6 --icmpv6-type $t -j RETURN"; done   # IPv6 needs ND/RA
    add "-p udp --dport 546 -j RETURN"
  fi
  # hotspot / tethering interfaces are left alone so tethering keeps working
  for p in $(printf '%s' "$ALLOW_PORTS" | tr ',' ' '); do
    is_num "$p" || continue
    if ! { add "-p tcp --dport $p -m conntrack --ctstate NEW -m recent --name AKG_BF --update --seconds 60 --hitcount 6 -j DROP" &&
           add "-p tcp --dport $p -m conntrack --ctstate NEW -m recent --name AKG_BF --set -j RETURN"; }; then
      add "-p tcp --dport $p -m limit --limit 10/min --limit-burst 10 -j RETURN"
    fi
    add "-p tcp --dport $p -j DROP"
  done
  for i in wlan0 rmnet+ ccmni+ eth0 v4-rmnet+ clat+; do add "-i $i -j DROP"; done
  rcmd "$ipt $W -C INPUT -j AKG_IN >/dev/null 2>&1 || $ipt $W -I INPUT 1 -j AKG_IN"
}

cmd_fw_on() {
  detect_root || die "root not available - an iptables firewall needs root. (No-root alternative: keep sshd off, use Private DNS + VPN, run 'monitor'.)"
  log STEP "Applying root firewall (stealth: drops scans, ping, unsolicited inbound)"
  fw_apply_family iptables
  fw_apply_family ip6tables
  log WARN "Rules active. If connectivity broke, wait - they auto-revert unless you confirm."
  printf 'Press ENTER within 45 s to KEEP the rules (otherwise they are removed): '
  if read -r -t 45 _; then log OK "Firewall rules kept. Remove with: $SELF fw-off"
  else echo; cmd_fw_off; log WARN "No confirmation - firewall rules reverted (safety)."; fi
}
cmd_fw_off() {
  detect_root || die "root not available"
  local ipt
  for ipt in iptables ip6tables; do
    rcmd "$ipt -D INPUT -j AKG_IN; $ipt -F AKG_IN; $ipt -X AKG_IN" >/dev/null 2>&1
  done
  log OK "AKG firewall rules removed"
}

# =============================================================================
#  HARDEN
# =============================================================================
harden_packages() {
  log STEP "Updating packages and installing detection dependencies"
  if ! have pkg; then log WARN "'pkg' not found - skipping"; return 0; fi
  export DEBIAN_FRONTEND=noninteractive
  pkg update -y >/dev/null 2>&1 || log WARN "pkg update failed (network?)"
  apt-get -y -o Dpkg::Options::=--force-confold upgrade >/dev/null 2>&1 && log OK "Packages upgraded" || log WARN "Upgrade reported problems - run 'pkg upgrade' manually"
  pkg install -y procps iproute2 net-tools curl openssl coreutils findutils diffutils grep sed gawk termux-api >/dev/null 2>&1 \
    && log OK "Dependencies installed" || log WARN "Some dependencies failed to install"
}

harden_permissions() {
  log STEP "Tightening permissions"
  chmod 700 "$HOME" "$HOME/.ssh" "$HOME/.termux" 2>/dev/null
  local f
  for f in "$HOME"/.ssh/*; do
    [ -f "$f" ] || continue
    case "$f" in *.pub) chmod 644 "$f" ;; *) chmod 600 "$f" ;; esac
  done
  [ -f "$HOME/.bash_history" ] && chmod 600 "$HOME/.bash_history"
  log OK "Permissions set (HOME/.ssh/.termux = 700, keys = 600)"
}

harden_shell() {
  log STEP "Shell hygiene (umask, history, integrity nudge)"
  local rc="$HOME/.bashrc"
  [ -f "$rc" ] && cp -p "$rc" "$BACKUP_DIR/bashrc.$(date +%s)"
  touch "$rc"
  sed -i '/# >>> termux-shield >>>/,/# <<< termux-shield <<</d' "$rc"
  cat >> "$rc" <<EOF
# >>> termux-shield >>>
umask 077
export HISTCONTROL=ignoreboth:erasedups
export HISTIGNORE='*password*:*passwd*:*token*:*secret*:*api_key*:*apikey*'
export HISTSIZE=2000 HISTFILESIZE=2000
[ -x "$SHIELD_DIR/termux-shield.sh" ] && "$SHIELD_DIR/termux-shield.sh" quick
# <<< termux-shield <<<
EOF
  cp "$SELF" "$SHIELD_DIR/termux-shield.sh" 2>/dev/null && chmod 700 "$SHIELD_DIR/termux-shield.sh"
  log OK "~/.bashrc updated (backup in $BACKUP_DIR); script installed at $SHIELD_DIR/termux-shield.sh"
}

ssh_block() {  # ssh_block with_crypto(0/1) password_auth(no/keep)
  echo "# >>> termux-shield >>>"
  echo "PubkeyAuthentication yes"
  [ "$2" = no ] && { echo "PasswordAuthentication no"; echo "KbdInteractiveAuthentication no"; }
  cat <<'EOF'
PermitEmptyPasswords no
MaxAuthTries 3
MaxStartups 3:50:10
LoginGraceTime 20
ClientAliveInterval 120
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
LogLevel VERBOSE
EOF
  if [ "$1" = 1 ]; then
    cat <<'EOF'
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF
  fi
  echo "# <<< termux-shield <<<"
}

harden_ssh() {
  log STEP "SSH server hardening"
  local cfg="$PREFIX/etc/ssh/sshd_config" keys="$HOME/.ssh/authorized_keys" pw="no" tmp ok=0 crypto
  if ! have sshd || [ ! -f "$cfg" ]; then log INFO "openssh not installed - nothing to harden"; return 0; fi
  ssh-keygen -A >/dev/null 2>&1
  if [ ! -s "$keys" ]; then
    log WARN "No authorized_keys yet: keeping password login so you are not locked out. Put your PC's public key (ssh-keygen -t ed25519) into $keys, then re-run harden to go key-only."
    pw="keep"
  fi
  cp -p "$cfg" "$BACKUP_DIR/sshd_config.$(date +%s)"
  tmp=$(mktemp "$SHIELD_DIR/sshd.XXXXXX")
  for crypto in 1 0; do
    { ssh_block "$crypto" "$pw"; sed '/# >>> termux-shield >>>/,/# <<< termux-shield <<</d' "$cfg"; } > "$tmp"
    if sshd -t -f "$tmp" >/dev/null 2>&1; then ok=1; break; fi
  done
  if [ "$ok" = 1 ]; then
    cat "$tmp" > "$cfg"; log OK "sshd_config hardened (block placed first because sshd uses the FIRST value of a keyword). Crypto restricted: $([ "$crypto" = 1 ] && echo yes || echo 'no (build lacks some algorithms)')"
    proc_running sshd && log WARN "sshd is running with the OLD config - restart it: $SELF ssh-start"
  else
    log FAIL "New sshd config failed validation - original left untouched"
  fi
  rm -f "$tmp"
}

harden_boot_cleanup() { :; }

android_manual_steps() {
  cat <<EOF

${CYN}Android-level steps Termux cannot enforce (do these by hand):${RST}
  1. Settings > Network > Private DNS > hostname: dns.quad9.net (or one.one.one.one)   -> stops DNS spoofing
  2. Wi-Fi: forget open/old networks, turn OFF "connect to open networks", keep randomized MAC ON;
     router: WPA3 (or WPA2-AES), WPS OFF, firmware current, guest network for IoT
  3. Developer options: turn OFF USB debugging and Wireless debugging; revoke USB-debugging authorisations
  4. Termux:API app: revoke permissions you do not use (SMS, contacts, location, microphone, camera)
  5. Do not run termux-setup-storage unless needed; keep Play Protect on; install apps from trusted stores only
  6. Use a reputable VPN on public Wi-Fi; keep Android and Termux updated; use a strong screen lock + encryption
  7. Re-run '$SELF audit' monthly and '$SELF net-check' on every new Wi-Fi
EOF
}

cmd_harden() {
  if [ "$ASSUME_YES" != 1 ]; then
    printf 'This will upgrade packages, tighten permissions, edit ~/.bashrc and sshd_config (backups kept). Continue? [y/N] '
    read -r a; case "$a" in y|Y|yes|YES) ;; *) log WARN "Aborted"; return 0 ;; esac
  fi
  harden_packages
  harden_permissions
  harden_shell
  harden_ssh
  cmd_baseline
  android_manual_steps
  log OK "Hardening complete. Next: '$SELF audit', then '$SELF monitor --daemon --autoblock' (and 'install-boot' to survive reboots)."
}

cmd_install_boot() {
  local d="$HOME/.termux/boot" f="$HOME/.termux/boot/termux-shield"
  mkdir -p "$d"; chmod 700 "$d"
  cp "$SELF" "$SHIELD_DIR/termux-shield.sh" 2>/dev/null && chmod 700 "$SHIELD_DIR/termux-shield.sh"
  cat > "$f" <<EOF
#!/data/data/com.termux/files/usr/bin/sh
# installed by termux-shield: start the monitor at boot
termux-wake-lock
exec "$SHIELD_DIR/termux-shield.sh" monitor --daemon --autoblock
EOF
  chmod 700 "$f"
  log OK "Boot hook installed ($f). Requires the Termux:Boot app (open it once). Re-run 'baseline' so this file is part of the trusted state."
}
cmd_remove_boot() { rm -f "$HOME/.termux/boot/termux-shield" && log OK "Boot hook removed"; }

cmd_quick() {  # printed at every shell start: keep it instant
  local since n
  since=$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null) || return 0
  n=$(grep -h '\[ALERT\]' "$LOG_FILE" 2>/dev/null | awk -v s="$since" 'substr($0,2,19) >= s' | wc -l)
  if [ "${n:-0}" -gt 0 ]; then
    printf '%s[termux-shield] %s security alert(s) in the last 24h:%s\n' "$RED" "$n" "$RST"
    grep -h '\[ALERT\]' "$LOG_FILE" | awk -v s="$since" 'substr($0,2,19) >= s' | tail -n 3 | cut -c1-160
  fi
}

cmd_status() {
  local pid
  pid=$(cat "$STATE_DIR/monitor.pid" 2>/dev/null)
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then log OK "Monitor: running (pid $pid)"; else log WARN "Monitor: not running ($SELF monitor --daemon)"; fi
  proc_running sshd && log WARN "sshd: running" || log OK "sshd: stopped"
  [ -f "$STATE_DIR/fim.baseline" ] && log OK "Integrity baseline: $(date -r "$STATE_DIR/fim.baseline" '+%F %T')" || log WARN "Integrity baseline: none"
  cmd_quick
}

summary() {
  local total=$((PASS+FAILS)) score=0
  [ "$total" -gt 0 ] && score=$(( PASS * 100 / total ))
  echo
  log STEP "Result: $PASS/$total checks passed ($score%), $FAILS to fix. Log: $LOG_FILE"
  [ "$FAILS" -gt 0 ] && log INFO "Fix list: run '$SELF harden' for what can be automated; the rest are Android settings (printed by harden)."
}

cmd_audit() {
  audit_device
  audit_env
  audit_persistence
  audit_ssh
  audit_packages
  audit_filesystem
  audit_tools
  audit_listeners
  wifi_check
  proc_scan
  scan_secrets
  if [ -f "$STATE_DIR/fim.baseline" ]; then log STEP "File integrity"; cmd_verify
  else log INFO "No integrity baseline yet - after a clean 'harden', one is created automatically."; fi
  summary
}

cmd_help() { sed -n '2,50p' "$SELF" | sed 's/^# \{0,1\}//'; }

# =============================================================================
#  ARGUMENT PARSING + DISPATCH
# =============================================================================
CMD="${1:-audit}"; [ $# -gt 0 ] && shift
need_val() { [ $# -ge 2 ] || die "option $1 needs a value"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --autoblock)  AUTOBLOCK=1 ;;
    --quiet|-q)   QUIET=1 ;;
    --yes|-y)     ASSUME_YES=1 ;;
    --deep)       DEEP=1 ;;
    --daemon)     DAEMON=1 ;;
    --once)       ONCE=1 ;;
    --stop)       STOPFLAG=1 ;;
    --status)     STATUSFLAG=1 ;;
    --all)        LEARN_ALL=1 ;;
    --threshold)  need_val "$@"; THRESHOLD="$2"; shift ;;
    --window)     need_val "$@"; WINDOW_MIN="$2"; shift ;;
    --interval)   need_val "$@"; INTERVAL="$2"; shift ;;
    --ban-hours)  need_val "$@"; BAN_HOURS="$2"; shift ;;
    --fim-every)  need_val "$@"; FIM_EVERY="$2"; shift ;;
    --allow-ip)   need_val "$@"; ALLOW_IPS="$2"; shift ;;
    --allow-port) need_val "$@"; ALLOW_PORTS="$2"; shift ;;
    -h|--help)    CMD=help ;;
    *)            die "unknown option: $1 (try: $0 help)" ;;
  esac
  shift
done
for v in THRESHOLD WINDOW_MIN INTERVAL BAN_HOURS FIM_EVERY; do
  is_num "${!v}" && [ "${!v}" -gt 0 ] || die "$v must be a positive integer"
done

if [ ! -d /data/data/com.termux ] && [ "$QUIET" != 1 ]; then
  log INFO "Not running inside Termux - Android/Termux-specific checks will be skipped or partial."
fi

case "$CMD" in
  audit)        cmd_audit ;;
  harden)       cmd_harden ;;
  monitor)      cmd_monitor ;;
  baseline)     cmd_baseline ;;
  verify)       cmd_verify ;;
  wifi-learn)   cmd_wifi_learn ;;
  net-check)    cmd_net_check; summary ;;
  ssh-start)    cmd_ssh_start ;;
  ssh-stop)     cmd_ssh_stop ;;
  fw-on)        cmd_fw_on ;;
  fw-off)       cmd_fw_off ;;
  install-boot) cmd_install_boot ;;
  remove-boot)  cmd_remove_boot ;;
  quick)        cmd_quick ;;
  status)       cmd_status ;;
  help)         cmd_help ;;
  *)            die "unknown command: $CMD (try: $0 help)" ;;
esac
