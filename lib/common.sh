#!/usr/bin/env bash
# Shared helpers for the CEH Toolkit.

# ---------- colors ----------------------------------------------------------
setup_colors() {
  if [[ "${COLOR:-auto}" == "on" || ( "${COLOR:-auto}" == "auto" && -t 1 ) ]]; then
    RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'
    CYN=$'\e[36m'; BLD=$'\e[1m'; RST=$'\e[0m'
  else
    RED=""; GRN=""; YEL=""; BLU=""; CYN=""; BLD=""; RST=""
  fi
}

info()  { printf '%s[*]%s %s\n' "$BLU" "$RST" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$GRN" "$RST" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$YEL" "$RST" "$*"; }
fail()  { printf '%s[-]%s %s\n' "$RED" "$RST" "$*" >&2; }
dbg()   { [[ "${VERBOSE:-0}" == "1" ]] && printf '%s[d]%s %s\n' "$CYN" "$RST" "$*" >&2; return 0; }
header(){ printf '\n%s== %s ==%s\n' "$BLD" "$*" "$RST"; }

# Findings are tallied so the report module can summarize them.
FINDINGS_FILE=""
finding() {   # finding <SEVERITY> <module> <message>
  local sev="$1" mod="$2"; shift 2
  local color="$RST"
  case "$sev" in
    CRITICAL|HIGH) color="$RED" ;;
    MEDIUM)        color="$YEL" ;;
    LOW)           color="$CYN" ;;
    INFO)          color="$BLU" ;;
    PASS)          color="$GRN" ;;
  esac
  printf '  %s[%-8s]%s %s\n' "$color" "$sev" "$RST" "$*"
  [[ -n "$FINDINGS_FILE" ]] && printf '%s|%s|%s|%s\n' "$(date +%FT%T)" "$sev" "$mod" "$*" >> "$FINDINGS_FILE"
  return 0
}

# ---------- environment -----------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

load_config() {
  local conf="$TOOLKIT_ROOT/config/ceh.conf"
  [[ -f "$conf" ]] && source "$conf"
  [[ -f "$TOOLKIT_ROOT/config/user.conf" ]] && source "$TOOLKIT_ROOT/config/user.conf"
  case "$REPORT_DIR" in /*) ;; *) REPORT_DIR="$TOOLKIT_ROOT/$REPORT_DIR" ;; esac
  case "$SCOPE_FILE" in /*) ;; *) SCOPE_FILE="$TOOLKIT_ROOT/$SCOPE_FILE" ;; esac
  mkdir -p "$REPORT_DIR"
  FINDINGS_FILE="$REPORT_DIR/findings-$(date +%Y%m%d).log"
}

# ---------- target validation / authorization -------------------------------
valid_host() {  # letters, digits, dot, dash, colon (ipv6) only
  [[ "$1" =~ ^[A-Za-z0-9._:-]+$ ]] && [[ ${#1} -le 253 ]]
}

valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

in_scope() {
  local target="$1" line
  case "$target" in localhost|127.*|::1) return 0 ;; esac
  [[ "${REQUIRE_SCOPE:-1}" == "0" ]] && return 0
  [[ -f "$SCOPE_FILE" ]] || return 1
  while IFS= read -r line; do
    line="${line%%#*}"; line="${line//[[:space:]]/}"
    [[ -z "$line" ]] && continue
    # shellcheck disable=SC2053
    if [[ "$target" == $line ]]; then return 0; fi
  done < "$SCOPE_FILE"
  return 1
}

require_target() {   # require_target <host>  -> exits module if bad / out of scope
  local t="$1"
  if [[ -z "$t" ]]; then fail "No target given."; return 1; fi
  if ! valid_host "$t"; then fail "Invalid target: $t"; return 1; fi
  if ! in_scope "$t"; then
    fail "Target '$t' is NOT in scope ($SCOPE_FILE)."
    fail "Only test systems you own or have written permission to test."
    fail "Add it to scope.txt to confirm authorization."
    return 1
  fi
  return 0
}

# Expand "22,80,8000-8010" into one port per line.
expand_ports() {
  local spec="$1" part a b
  IFS=',' read -ra parts <<< "$spec"
  for part in "${parts[@]}"; do
    if [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"
      valid_port "$a" && valid_port "$b" && (( a <= b )) || { fail "Bad port range: $part"; return 1; }
      seq "$a" "$b"
    elif valid_port "$part"; then
      echo "$part"
    else
      fail "Bad port: $part"; return 1
    fi
  done
}

service_name() {
  case "$1" in
    21) echo ftp;; 22) echo ssh;; 23) echo telnet;; 25) echo smtp;; 53) echo dns;;
    80) echo http;; 110) echo pop3;; 111) echo rpcbind;; 135) echo msrpc;;
    139) echo netbios;; 143) echo imap;; 443) echo https;; 445) echo smb;;
    465) echo smtps;; 587) echo submission;; 993) echo imaps;; 995) echo pop3s;;
    1433) echo mssql;; 1521) echo oracle;; 2049) echo nfs;; 3306) echo mysql;;
    3389) echo rdp;; 5432) echo postgres;; 5900) echo vnc;; 6379) echo redis;;
    8000|8080) echo http-alt;; 8443) echo https-alt;; 9200) echo elasticsearch;;
    27017) echo mongodb;; *) echo unknown;;
  esac
}

# Ports whose exposure is notable when open.
risky_port_note() {
  case "$1" in
    21)  echo "FTP sends credentials in clear text";;
    23)  echo "Telnet is unencrypted; replace with SSH";;
    111|2049) echo "RPC/NFS exposure; restrict to trusted hosts";;
    135|139|445) echo "Windows file/RPC services; should not be internet-facing";;
    1433|1521|3306|5432|27017|6379|9200) echo "Database/datastore port reachable; restrict by firewall";;
    3389) echo "RDP exposed; enforce NLA/VPN/MFA";;
    5900) echo "VNC exposed; tunnel over SSH/VPN";;
    *) echo "";;
  esac
}

# Open a TCP connection using bash's /dev/tcp with a timeout.
tcp_open() {  # tcp_open host port [timeout]
  timeout "${3:-${SCAN_TIMEOUT:-1}}" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
}

lookup_a() {   # resolve host to IPv4 using whatever is installed
  local h="$1" out=""
  if have getent; then out=$(getent ahostsv4 "$h" 2>/dev/null | awk '{print $1; exit}'); fi
  if [[ -z "$out" ]] && have dig; then out=$(dig +short A "$h" | grep -E '^[0-9.]+$' | head -1); fi
  if [[ -z "$out" ]] && have host; then out=$(host "$h" 2>/dev/null | awk '/has address/{print $4; exit}'); fi
  if [[ -z "$out" ]] && have nslookup; then out=$(nslookup "$h" 2>/dev/null | awk '/^Address: /{print $2}' | tail -1); fi
  [[ "$h" =~ ^[0-9.]+$ ]] && out="$h"
  echo "$out"
}
