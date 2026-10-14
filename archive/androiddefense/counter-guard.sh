#!/data/data/com.termux/files/usr/bin/bash
grep -q $'\r' "$0" && tr -d $'\r' <"$0" >"$0.lf" && mv -f "$0.lf" "$0" && exec bash "$0" "$@" #
# counter-guard.sh - detect and neutralise tethering/SIM-spoof/remote-control
# tooling on a rooted Android device. Run from Termux with root (tsu / su).
#
# Targets:
#   otilrac/sim-spoof          Magisk service.d spoof scripts, resetprop gsm.* overrides,
#                              iptables TTL/HL rewrites and port-53 DNAT
#   DevL0rd/Android-Daemon     re-armed wireless ADB, scrcpy server, trusted ADB hosts,
#                              USB tether failover
#   RSR-Projects/CastDrive     accessibility + MediaProjection mirroring app
#   pratikbin/hotspot-ttl      tether clients sending TTL/HL 65 (looks phone-native after
#                              the phone's decrement)
#   riteshgharti333/auto-usb-tether  accessibility service that flips USB tethering on
#
# Usage: counter-guard.sh [audit|fix|watch|install|uninstall|status] [options]
#   audit            read-only scan (default). Exit 0 = clean, 1 = findings
#   fix              scan and neutralise everything found
#   watch [SECS]     fix in a loop (default 60s), notify on new findings
#   install          fix + persist: Magisk/KSU service.d autostart of watch mode
#   uninstall        remove autostart, firewall guard chain; restore quarantined files
#   status           show guard state
# Options:
#   --strict         also disable USB debugging, drop all trusted ADB hosts
#   --block-tether   also reset the USB function (drops RNDIS/NCM tethering)
#   --remove-apps    uninstall flagged apps instead of disabling them
#   --monitor-only   firewall guard only counts TTL-65 clients, no normalising
#   --dry-run        with fix: print what would change, change nothing
#   --termux-boot    with install: also write ~/.termux/boot entry (Termux:Boot)
#   -h, --help

VERSION="1.2.0"
export PATH="$PATH:/system/bin:/system/xbin:/vendor/bin:/data/adb/magisk:/data/adb/ksu/bin:/data/adb/ap/bin"

SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "$0")"
TERMUX_HOME="${TERMUX_HOME:-/data/data/com.termux/files/home}"
TERMUX_BASH="${TERMUX_BASH:-/data/data/com.termux/files/usr/bin/bash}"
[ -x "$TERMUX_BASH" ] || TERMUX_BASH="$(command -v bash)"
STATE_DIR="${COUNTER_GUARD_DIR:-$TERMUX_HOME/.counter-guard}"
[ -d "$TERMUX_HOME" ] || STATE_DIR="${COUNTER_GUARD_DIR:-/data/local/tmp/counter-guard}"
QDIR="$STATE_DIR/quarantine"
LOGFILE="$STATE_DIR/guard.log"
PIDFILE="$STATE_DIR/watch.pid"
INSTALL_DIR="/data/adb/counter-guard"
BOOT_HOOK="/data/adb/service.d/zz-counter-guard.sh"

KNOWN_PKGS="com.aistudio.automirror.cxkmv com.aistudio.usbtether.vxkqz ${EXTRA_PKGS:-}"
KNOWN_A11Y_RE='UsbTetherAccessibilityService|AutoMirrorAccessibilityService'
KNOWN_SVC_RE='ScreenMirrorService|AutoMirrorCarAppService|AutoMirrorMediaBrowserService'
SPOOF_SIG='resetprop[^#]*gsm\.(sim\.)?operator|--ttl-set|--hl-set|--dport 53[^#]*DNAT|ReBullet'
TETHER_IF_RE='^(ap[0-9]+|swlan[0-9]+|wlan[1-9][0-9]*|softap[0-9]*|rndis[0-9]+|usb[0-9]+|ncm[0-9]+|ecm[0-9]+|bt-pan)$'
GUARD_CHAIN="COUNTER_GUARD"

MODE="audit"
APPLY=0
DRY=0
STRICT=0
BLOCK_TETHER=0
REMOVE_APPS=0
MONITOR_ONLY=0
TERMUX_BOOT=0
QUIET=0
WATCH_SECS=60
FOUND=0
FIXED=0
GUARD_SIG=""

if [ -t 1 ]; then
  C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_B=$'\033[36m'; C_0=$'\033[0m'; C_D=$'\033[2m'
else
  C_R=""; C_G=""; C_Y=""; C_B=""; C_0=""; C_D=""
fi

have() { command -v "$1" >/dev/null 2>&1; }
# Toolbox, toybox and su drop CR on many lines. A leftover \r fails string
# compares and grep -x, breaks [ -gt ], and rewinds the cursor mid-line.
nocr() { tr -d '\r'; }
one() { nocr | tr -d '[:space:]'; }
lines() { nocr | wc -l | tr -cd '0-9'; }
say() { [ "$QUIET" = 1 ] || printf '%s\n' "${*//$'\r'/}"; }
head_() { say ""; say "${C_B}== $* ==${C_0}"; }
ok() { say "  ${C_G}[ok]${C_0} $*"; }
info() { say "  ${C_D}[..]${C_0} $*"; }
find_() { FOUND=$((FOUND + 1)); say "  ${C_R}[!!]${C_0} $*"; log "FOUND: $*"; }
warn() { say "  ${C_Y}[??]${C_0} $*"; }
fixed() { FIXED=$((FIXED + 1)); say "  ${C_G}[fix]${C_0} $*"; log "FIXED: $*"; }
log() { [ -d "$STATE_DIR" ] && printf '%s %s\n' "$(date '+%F %T')" "${*//$'\r'/}" >>"$LOGFILE" 2>/dev/null; }

# Run a remediation. Prints the intent in dry-run, does nothing in audit mode.
act() {
  local desc="$1"; shift
  if [ "$APPLY" != 1 ]; then
    say "       ${C_D}-> would fix: $desc (run with 'fix')${C_0}"
    return 1
  fi
  if [ "$DRY" = 1 ]; then
    say "       ${C_D}-> dry-run: $desc${C_0}"
    return 1
  fi
  if "$@" >/dev/null 2>&1; then
    fixed "$desc"
    return 0
  fi
  warn "failed: $desc"
  return 1
}

need_root() {
  if [ "$(id -u 2>/dev/null | one)" = 0 ]; then return 0; fi
  if have tsu; then exec tsu -c "$(printf '%q ' "$TERMUX_BASH" "$SELF" "$@")"; fi
  if have su; then exec su -c "$(printf '%q ' "$TERMUX_BASH" "$SELF" "$@")"; fi
  echo "root required: install tsu (pkg install tsu) and grant root to Termux" >&2
  exit 2
}

mkdir_state() { mkdir -p "$QDIR" 2>/dev/null; }

# ---------------------------------------------------------------- helpers

setting() { settings get "$1" "$2" 2>/dev/null | one; }
prop() { getprop "$1" 2>/dev/null | one; }

setprop_any() {
  if have resetprop; then resetprop -n "$1" "$2"; else setprop "$1" "$2"; fi
}

quarantine() {
  local f="$1" dest
  mkdir_state
  dest="$QDIR/$(date +%s)-$(printf '%s' "$f" | tr '/' '_')"
  cp -p "$f" "$dest" 2>/dev/null && rm -f "$f"
}

# Listening TCP ports (decimal), from /proc, so no netstat/ss dependency.
listen_ports() {
  local f line hex
  for f in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$f" ] || continue
    while read -r _ loc _ st _; do
      [ "$st" = "0A" ] || continue
      hex="${loc##*:}"
      hex="${hex//$'\r'/}"
      printf '%d\n' "0x$hex"
    done < <(nocr <"$f")
  done | sort -un
}

# Delete iptables rules whose -S line matches a regex. Prints how many were removed.
purge_rules() {
  local bin="$1" table="$2" re="$3" rule n=0
  set -f
  while IFS= read -r rule; do
    [ -n "$rule" ] || continue
    # shellcheck disable=SC2086
    if $bin -t "$table" ${rule/-A /-D } 2>/dev/null; then
      n=$((n + 1))
    fi
  done < <(list_rules "$bin" "$table" "$re")
  set +f
  echo "$n"
}

list_rules() {
  local bin="$1" table="$2" re="$3"
  $bin -t "$table" -S 2>/dev/null | nocr | grep -E '^-A ' | grep -vE "^-A $GUARD_CHAIN " | grep -E -e "$re" || true
}

tether_ifaces() {
  local out
  if [ -n "${TETHER_IFACES:-}" ]; then printf '%s\n' $TETHER_IFACES | nocr; return; fi
  if have ip; then
    out="$(ip -o link show 2>/dev/null | nocr)"
    [ -n "$out" ] || out="$(ip link show 2>/dev/null | nocr)"
    printf '%s\n' "$out" | awk -F': ' 'NF>1 {print $2}' | sed 's/@.*//' | nocr | grep -E "$TETHER_IF_RE" || true
  else
    ls /sys/class/net 2>/dev/null | nocr | grep -E "$TETHER_IF_RE" || true
  fi
}

# Scripts that apply sim-spoof style changes at boot.
spoof_scripts() {
  local f
  for f in /data/adb/service.d/* /data/adb/post-fs-data.d/* \
           /data/adb/modules/*/service.sh /data/adb/modules/*/post-fs-data.sh \
           /data/adb/modules/*/system.prop /data/local/tmp/script.sh; do
    [ -f "$f" ] || continue
    case "$f" in *counter-guard*) continue ;; esac
    if grep -qE "$SPOOF_SIG" "$f" 2>/dev/null; then echo "$f"; fi
  done
}

# ---------------------------------------------------------------- checks

check_sim_spoof() {
  head_ "sim-spoof (SIM/DNS/TTL spoofing)"
  local f n any=0 rule

  while IFS= read -r f; do
    [ -n "$f" ] || continue
    any=1
    find_ "boot-time spoof script: $f"
    case "$f" in
      /data/adb/modules/*)
        local mod; mod="$(dirname "$f")"
        act "disable Magisk module $(basename "$mod")" touch "$mod/disable"
        ;;
      *) act "quarantine $f" quarantine "$f" ;;
    esac
  done < <(spoof_scripts)
  [ "$any" = 1 ] || ok "no spoof boot scripts in service.d / modules"

  any=0
  for b in iptables ip6tables; do
    have "$b" || continue
    while IFS= read -r rule; do
      [ -n "$rule" ] || continue
      any=1
      find_ "$b rewrites TTL/HL: $rule"
    done < <(list_rules "$b" mangle '-j (TTL|HL) --(ttl|hl)-set')
    if [ "$(list_rules "$b" mangle '-j (TTL|HL) --(ttl|hl)-set' | lines)" -gt 0 ]; then
      act "remove $b TTL/HL mangle rules" purge_rules "$b" mangle '-j (TTL|HL) --(ttl|hl)-set'
    fi
    while IFS= read -r rule; do
      [ -n "$rule" ] || continue
      any=1
      find_ "$b intercepts DNS: $rule"
    done < <(list_rules "$b" nat '--dport 53 .*-j DNAT')
    if [ "$(list_rules "$b" nat '--dport 53 .*-j DNAT' | lines)" -gt 0 ]; then
      act "remove $b port-53 DNAT rules" purge_rules "$b" nat '--dport 53 .*-j DNAT'
    fi
  done
  [ "$any" = 1 ] || ok "no TTL/HL rewrite or DNS DNAT rules"

  # Operator props vs what the radio actually registered on.
  local prop_num real tok match=0 have_real=0
  prop_num="$(prop gsm.operator.numeric)"
  real="$(dumpsys telephony.registry 2>/dev/null | nocr | grep -oE '(m)?[Oo]perator[Nn]umeric=[0-9]{5,6}' | sed 's/.*=//' | sort -u)"
  if [ -n "$prop_num" ] && [ -n "$real" ]; then
    have_real=1
    for tok in $(printf '%s' "$prop_num" | tr ',' ' '); do
      printf '%s\n' "$real" | grep -qx "$tok" && match=1
    done
    if [ "$match" = 0 ]; then
      find_ "gsm.operator.numeric=$prop_num but radio registered on: $(printf '%s' "$real" | tr '\n' ' ')"
      if [ "$(printf '%s\n' "$real" | lines)" = 1 ]; then
        act "restore gsm.operator.numeric=$real" setprop_any gsm.operator.numeric "$real"
      else
        info "multiple registered operators, not restoring automatically (reboot after removal)"
      fi
    else
      ok "operator props agree with the registered network"
    fi
  fi
  [ "$have_real" = 1 ] || info "could not compare operator props (no registration data / airplane mode)"

  local pdns
  pdns="$(setting global private_dns_mode)"
  if [ "$pdns" = "off" ]; then
    warn "private_dns_mode=off (sim-spoof sets this so its DNS DNAT works)"
    act "set private_dns_mode=opportunistic" settings put global private_dns_mode opportunistic
  fi
  [ "$FOUND" -gt 0 ] && info "SIM/timezone props revert fully after a reboot once the scripts above are gone"
}

check_android_daemon() {
  head_ "Android-Daemon (wireless ADB / scrcpy / USB tether failover)"
  local before=$FOUND p wifi tcp port

  wifi="$(setting global adb_wifi_enabled)"
  if [ "$wifi" = "1" ]; then
    find_ "wireless debugging is enabled"
    act "disable wireless debugging" settings put global adb_wifi_enabled 0
  fi

  tcp=""
  for p in service.adb.tcp.port persist.adb.tcp.port; do
    port="$(prop "$p")"
    case "$port" in ''|-1|0) ;; *) tcp="$tcp $p=$port" ;; esac
  done
  if [ -n "$tcp" ]; then
    find_ "adbd TCP port armed:$tcp"
    act "reset adbd TCP port props" bash -c '
      setprop service.adb.tcp.port -1; setprop persist.adb.tcp.port -1' 
  fi

  local ports
  ports="$(listen_ports | tr '\n' ' ')"
  for p in 5555 $(printf '%s' "${tcp:-}" | grep -oE '=[0-9]+' | tr -d '='); do
    case " $ports " in
      *" $p "*)
        find_ "something is listening on TCP $p (adb tcpip)"
        act "restart adbd without TCP" bash -c 'setprop service.adb.tcp.port -1; stop adbd; sleep 1; start adbd'
        break
        ;;
    esac
  done

  local procs
  procs="$(ps -A 2>/dev/null | nocr | grep -E 'scrcpy|com\.genymobile' | grep -vE 'grep|counter-guard' || true)"
  if [ -n "$procs" ]; then
    find_ "scrcpy server running: $(printf '%s' "$procs" | head -n1 | cut -c1-100)"
    act "kill scrcpy processes" kill_pids "$procs"
  fi
  local f
  for f in /data/local/tmp/scrcpy-server*; do
    [ -e "$f" ] || continue
    find_ "scrcpy server binary left on device: $f"
    act "quarantine $f" quarantine "$f"
  done

  local keys=/data/misc/adb/adb_keys
  if [ -s "$keys" ]; then
    local n hosts
    n="$(lines <"$keys")"
    hosts="$(nocr <"$keys" | awk '{print $NF}' | sort -u | tr '\n' ' ')"
    if [ "$STRICT" = 1 ]; then
      find_ "$n trusted ADB key(s): $hosts"
      act "revoke all trusted ADB hosts" bash -c "rm -f $keys /data/misc/adb/adb_temp_keys.xml; stop adbd; start adbd"
    else
      info "$n trusted ADB key(s): $hosts (--strict revokes them; Android-Daemon needs one)"
    fi
  fi

  if [ "$(setting global adb_enabled)" = "1" ]; then
    if [ "$STRICT" = 1 ]; then
      find_ "USB debugging is on"
      act "disable USB debugging" settings put global adb_enabled 0
    else
      info "USB debugging is on (--strict turns it off)"
    fi
  fi

  local usb cfg
  usb="$(prop sys.usb.state)"
  cfg="$(prop sys.usb.config)"
  [ -n "$cfg" ] && [ "$cfg" != "$usb" ] && usb="$usb,$cfg"
  if printf '%s' "$usb" | grep -qE 'rndis|ncm|ecm'; then
    if [ "$BLOCK_TETHER" = 1 ]; then
      find_ "USB tethering function active ($usb)"
      act "reset USB function to mtp" svc usb setFunctions mtp
    else
      warn "USB tethering function active ($usb) - --block-tether drops it"
    fi
  fi

  [ "$FOUND" = "$before" ] && ok "no wireless ADB, scrcpy or failover tether found"
}

kill_pids() {
  printf '%s\n' "$1" | nocr | awk '{
    for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+$/) { print $i; break }
  }' | xargs kill -9
}

pkg_installed() { pm list packages 2>/dev/null | nocr | grep -qx "package:$1"; }

disable_pkg() {
  local pkg="$1"
  am force-stop "$pkg" 2>/dev/null
  pm revoke "$pkg" android.permission.RECORD_AUDIO 2>/dev/null
  cmd appops set "$pkg" PROJECT_MEDIA deny 2>/dev/null
  if [ "$REMOVE_APPS" = 1 ]; then
    pm uninstall --user 0 "$pkg"
  else
    pm disable-user --user 0 "$pkg"
  fi
}

strip_a11y() { # pkg-or-class-regex
  local re="$1" cur line new=""
  cur="$(setting secure enabled_accessibility_services)"
  [ -n "$cur" ] && [ "$cur" != "null" ] || return 0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    new="${new:+$new:}$line"
  done < <(printf '%s\n' "$cur" | tr ':' '\n' | grep -vE "$re" || true)
  if [ -n "$new" ]; then
    settings put secure enabled_accessibility_services "$new"
  else
    settings delete secure enabled_accessibility_services
    settings put secure accessibility_enabled 0
  fi
}

check_apps() {
  head_ "CastDrive / auto-usb-tether (mirroring + auto-tether apps)"
  local before=$FOUND pkg a11y svc_pkgs

  for pkg in $KNOWN_PKGS; do
    if pkg_installed "$pkg"; then
      find_ "installed: $pkg"
      act "$([ "$REMOVE_APPS" = 1 ] && echo uninstall || echo disable) $pkg" disable_pkg "$pkg"
    fi
  done

  a11y="$(setting secure enabled_accessibility_services | tr ':' '\n' | grep -E "$KNOWN_A11Y_RE")"
  if [ -n "$a11y" ]; then
    while IFS= read -r pkg; do
      find_ "accessibility service enabled: $pkg"
    done <<<"$a11y"
    act "remove those services from enabled_accessibility_services" strip_a11y "$KNOWN_A11Y_RE"
    for pkg in $(printf '%s\n' "$a11y" | cut -d/ -f1 | sort -u); do
      case " $KNOWN_PKGS " in *" $pkg "*) continue ;; esac
      act "disable repackaged build $pkg" disable_pkg "$pkg"
    done
  fi

  svc_pkgs="$(dumpsys activity services 2>/dev/null | nocr | grep -oE "ServiceRecord\{[^}]* u[0-9]+ [^ /]+/[^ }]*($KNOWN_SVC_RE)" | sed -E 's/.* u[0-9]+ ([^ /]+)\/.*/\1/' | sort -u)"
  for pkg in $svc_pkgs; do
    find_ "mirroring service running in $pkg"
    act "stop $pkg" disable_pkg "$pkg"
  done

  local aistudio
  aistudio="$(pm list packages 2>/dev/null | nocr | sed 's/^package://' | grep -E '^com\.aistudio\.' | grep -vxF "$(printf '%s\n' $KNOWN_PKGS)" || true)"
  for pkg in $aistudio; do
    warn "AI Studio generated app (same toolchain as the two tools above): $pkg"
  done

  local mp
  mp="$(dumpsys media_projection 2>/dev/null | nocr | grep -iE 'package|uid' | head -n3 || true)"
  [ -n "$mp" ] && info "media_projection: $(printf '%s' "$mp" | tr -s ' \n' ' ' | cut -c1-140)"

  [ "$FOUND" = "$before" ] && ok "no known mirror/auto-tether apps or services"
}

guard_remove() {
  local bin
  for bin in iptables ip6tables; do
    have "$bin" || continue
    while $bin -t mangle -D PREROUTING -j "$GUARD_CHAIN" 2>/dev/null; do :; done
    $bin -t mangle -F "$GUARD_CHAIN" 2>/dev/null
    $bin -t mangle -X "$GUARD_CHAIN" 2>/dev/null
  done
  return 0
}

guard_setup() {
  local bin ifs i m_eq m_gt tgt
  ifs="$(tether_ifaces | sort -u | tr '\n' ' ')"
  for bin in iptables ip6tables; do
    have "$bin" || continue
    if [ "$bin" = iptables ]; then m_eq="-m ttl --ttl-eq 65"; m_gt="-m ttl --ttl-gt 64"; tgt="TTL --ttl-set 64"
    else m_eq="-m hl --hl-eq 65"; m_gt="-m hl --hl-gt 64"; tgt="HL --hl-set 64"; fi
    $bin -t mangle -N "$GUARD_CHAIN" 2>/dev/null
    $bin -t mangle -F "$GUARD_CHAIN"
    for i in $ifs; do
      # shellcheck disable=SC2086
      $bin -t mangle -A "$GUARD_CHAIN" -i "$i" $m_eq -m comment --comment cg-spoof65 || return 1
      if [ "$MONITOR_ONLY" != 1 ]; then
        # shellcheck disable=SC2086
        $bin -t mangle -A "$GUARD_CHAIN" -i "$i" $m_gt -m comment --comment cg-normalise -j $tgt || return 1
      fi
    done
    $bin -t mangle -C PREROUTING -j "$GUARD_CHAIN" 2>/dev/null || $bin -t mangle -I PREROUTING 1 -j "$GUARD_CHAIN"
  done
  GUARD_SIG="$ifs"
  return 0
}

guard_hits() {
  local bin total=0 n
  for bin in iptables ip6tables; do
    have "$bin" || continue
    n="$($bin -t mangle -nvxL "$GUARD_CHAIN" 2>/dev/null | nocr | awk '/cg-spoof65/ {s+=$1} END {print s+0}' | one)"
    total=$((total + ${n:-0}))
  done
  echo "$total"
}

check_ttl_clients() {
  head_ "hotspot-ttl (tether clients masking as phone traffic)"
  local ifs hits
  ifs="$(tether_ifaces | sort -u | tr '\n' ' ')"
  if [ -z "$ifs" ]; then
    info "no tether interface up right now (hotspot/USB tether off)"
  else
    info "tether interfaces: $ifs"
  fi
  if have iptables && iptables -t mangle -nL "$GUARD_CHAIN" >/dev/null 2>&1; then
    hits="$(guard_hits)"
    if [ "$hits" -gt 0 ]; then
      find_ "$hits packet(s) from tether clients arrived with TTL/HL 65 (hotspot-ttl signature)"
    else
      ok "guard chain active, no TTL/HL 65 clients seen"
    fi
  else
    info "firewall guard not installed yet - counts TTL/HL 65 clients and normalises them to 64"
  fi
  if [ "$APPLY" = 1 ] && [ "$DRY" != 1 ]; then
    if [ "$ifs" != "$GUARD_SIG" ] || ! iptables -t mangle -C PREROUTING -j "$GUARD_CHAIN" 2>/dev/null; then
      if guard_setup; then
        fixed "firewall guard $([ "$MONITOR_ONLY" = 1 ] && echo '(monitor only)' || echo '(counts TTL 65, normalises to 64)') on: ${ifs:-no tether iface yet}"
      else
        warn "kernel lacks xt_ttl/xt_hl or comment match; guard not installed"
        guard_remove
      fi
    fi
  elif [ "$APPLY" != 1 ] && ! iptables -t mangle -C PREROUTING -j "$GUARD_CHAIN" 2>/dev/null; then
    say "       ${C_D}-> would fix: install firewall guard on tether interfaces (run with 'fix')${C_0}"
  fi
}

run_checks() {
  FOUND=0; FIXED=0
  check_sim_spoof
  check_android_daemon
  check_apps
  check_ttl_clients
}

summary() {
  say ""
  if [ "$FOUND" = 0 ]; then
    say "${C_G}clean: nothing detected${C_0}"
  elif [ "$APPLY" = 1 ] && [ "$DRY" != 1 ]; then
    say "${C_Y}$FOUND finding(s), $FIXED action(s) applied. Reboot to fully reset radio props.${C_0}"
  else
    say "${C_R}$FOUND finding(s). Re-run with 'fix' to neutralise.${C_0}"
  fi
}

# ---------------------------------------------------------------- watch / install

notify() {
  have termux-notification || return 0
  timeout 5 termux-notification --id counter-guard --title "counter-guard" --content "$1" >/dev/null 2>&1 &
}

watch_loop() {
  mkdir_state
  if [ -f "$PIDFILE" ] && kill -0 "$(one <"$PIDFILE")" 2>/dev/null; then
    echo "watch already running (pid $(one <"$PIDFILE"))"; exit 0
  fi
  echo $$ >"$PIDFILE"
  trap 'rm -f "$PIDFILE"; exit 0' INT TERM
  APPLY=1; QUIET=1
  log "watch started (interval ${WATCH_SECS}s, strict=$STRICT block_tether=$BLOCK_TETHER)"
  while :; do
    run_checks
    if [ "$FOUND" -gt 0 ]; then
      notify "neutralised $FIXED of $FOUND finding(s), see $LOGFILE"
    fi
    sleep "$WATCH_SECS"
  done
}

install_boot() {
  local flags=""
  [ "$STRICT" = 1 ] && flags="$flags --strict"
  [ "$BLOCK_TETHER" = 1 ] && flags="$flags --block-tether"
  [ "$REMOVE_APPS" = 1 ] && flags="$flags --remove-apps"
  [ "$MONITOR_ONLY" = 1 ] && flags="$flags --monitor-only"

  mkdir -p "$INSTALL_DIR" /data/adb/service.d || { echo "cannot write /data/adb (Magisk/KernelSU needed)"; exit 1; }
  cp "$SELF" "$INSTALL_DIR/counter-guard.sh" && chmod 755 "$INSTALL_DIR/counter-guard.sh"
  cat >"$BOOT_HOOK" <<EOF
#!/system/bin/sh
until [ "\$(getprop sys.boot_completed | tr -d '\\r[:space:]')" = 1 ]; do sleep 5; done
sleep 20
COUNTER_GUARD_DIR="$STATE_DIR" nohup "$TERMUX_BASH" "$INSTALL_DIR/counter-guard.sh" watch $WATCH_SECS$flags >/dev/null 2>&1 &
EOF
  chmod 755 "$BOOT_HOOK"
  say "installed $BOOT_HOOK (watch every ${WATCH_SECS}s${flags:+, flags:$flags})"

  if [ "$TERMUX_BOOT" = 1 ]; then
    mkdir -p "$TERMUX_HOME/.termux/boot"
    cat >"$TERMUX_HOME/.termux/boot/counter-guard.sh" <<EOF
#!$TERMUX_BASH
termux-wake-lock
tsu -c "$TERMUX_BASH $INSTALL_DIR/counter-guard.sh watch $WATCH_SECS$flags" >/dev/null 2>&1 &
EOF
    chmod 755 "$TERMUX_HOME/.termux/boot/counter-guard.sh"
    say "installed Termux:Boot entry (needs the Termux:Boot app opened once)"
  fi
}

uninstall_all() {
  if [ -f "$PIDFILE" ]; then kill "$(one <"$PIDFILE")" 2>/dev/null; rm -f "$PIDFILE"; fi
  rm -f "$BOOT_HOOK" "$TERMUX_HOME/.termux/boot/counter-guard.sh"
  rm -rf "$INSTALL_DIR"
  guard_remove
  say "removed autostart and firewall guard chain"
  if [ -d "$QDIR" ] && [ -n "$(ls -A "$QDIR" 2>/dev/null)" ]; then
    say "quarantined files are kept in $QDIR (copy back by hand if you want them)"
  fi
}

show_status() {
  if [ -f "$PIDFILE" ] && kill -0 "$(one <"$PIDFILE")" 2>/dev/null; then
    echo "watch: running (pid $(one <"$PIDFILE"))"
  else
    echo "watch: not running"
  fi
  [ -f "$BOOT_HOOK" ] && echo "autostart: $BOOT_HOOK" || echo "autostart: not installed"
  if have iptables && iptables -t mangle -nL "$GUARD_CHAIN" >/dev/null 2>&1; then
    echo "firewall guard: active, TTL/HL 65 hits so far: $(guard_hits)"
  else
    echo "firewall guard: not installed"
  fi
  [ -f "$LOGFILE" ] && { echo "last log lines:"; tail -n 8 "$LOGFILE"; }
}

usage() { sed -n '/^# counter-guard/,/^VERSION=/p' "$SELF" | sed '$d' | sed 's/^# \{0,1\}//'; }

# ---------------------------------------------------------------- main

set -- "${@//$'\r'/}"
ARGS=("$@")
while [ $# -gt 0 ]; do
  case "$1" in
    audit|fix|watch|install|uninstall|status) MODE="$1" ;;
    --strict) STRICT=1 ;;
    --block-tether) BLOCK_TETHER=1 ;;
    --remove-apps) REMOVE_APPS=1 ;;
    --monitor-only) MONITOR_ONLY=1 ;;
    --dry-run) DRY=1 ;;
    --termux-boot) TERMUX_BOOT=1 ;;
    -q|--quiet) QUIET=1 ;;
    -h|--help|help) usage; exit 0 ;;
    [0-9]*) WATCH_SECS="$1" ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

need_root "${ARGS[@]}"
mkdir_state

case "$MODE" in
  audit)
    APPLY=0; run_checks; summary
    [ "$FOUND" = 0 ] && exit 0 || exit 1
    ;;
  fix)
    APPLY=1; run_checks; summary
    ;;
  watch) watch_loop ;;
  install)
    APPLY=1; run_checks; summary
    install_boot
    ;;
  uninstall) uninstall_all ;;
  status) show_status ;;
esac
