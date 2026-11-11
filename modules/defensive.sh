#!/usr/bin/env bash
# Module: local hardening audit, log analysis, file integrity monitoring.

# ---------------------------------------------------------------------------
run_sysaudit() {
  header "Local Linux hardening audit"
  [[ "$(uname -s)" == "Linux" ]] || warn "Non-Linux system; some checks will be skipped."
  info "Host: $(hostname) | Kernel: $(uname -r) | User: $(id -un) (uid $(id -u))"
  (( EUID != 0 )) && info "Not root: shadow/sudoers checks may be limited."

  header "Accounts"
  local uid0; uid0=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd 2>/dev/null)
  [[ -n "$uid0" ]] && finding CRITICAL sysaudit "Non-root accounts with UID 0: $uid0" || finding PASS sysaudit "Only root has UID 0"
  if [[ -r /etc/shadow ]]; then
    local empty; empty=$(awk -F: '($2==""){print $1}' /etc/shadow)
    [[ -n "$empty" ]] && finding CRITICAL sysaudit "Accounts with EMPTY passwords: $empty" || finding PASS sysaudit "No empty-password accounts"
  else
    info "/etc/shadow not readable; skipping empty-password check."
  fi
  local shells; shells=$(awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ && $3>=1000 && $1!="nobody"{print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')
  [[ -n "$shells" ]] && info "Interactive human accounts: $shells"

  header "SSH daemon"
  local cfg=/etc/ssh/sshd_config
  if [[ -r $cfg ]]; then
    _ssh() { grep -iE "^[[:space:]]*$1[[:space:]]" "$cfg" | tail -1 | awk '{print tolower($2)}'; }
    local v
    v=$(_ssh PermitRootLogin);        [[ "$v" == "yes" ]] && finding HIGH sysaudit "SSH PermitRootLogin yes" || finding PASS sysaudit "SSH root login restricted (${v:-default})"
    v=$(_ssh PasswordAuthentication); [[ "$v" == "no" ]] && finding PASS sysaudit "SSH password auth disabled" || finding MEDIUM sysaudit "SSH password authentication enabled (prefer keys)"
    v=$(_ssh PermitEmptyPasswords);   [[ "$v" == "yes" ]] && finding CRITICAL sysaudit "SSH PermitEmptyPasswords yes"
    v=$(_ssh Protocol);               [[ "$v" == "1" ]] && finding HIGH sysaudit "SSH Protocol 1 enabled"
    v=$(_ssh X11Forwarding);          [[ "$v" == "yes" ]] && finding LOW sysaudit "SSH X11Forwarding enabled"
  else
    info "No readable $cfg (sshd not installed or no permission)."
  fi

  header "File permissions"
  local p
  for p in /etc/passwd:644 /etc/shadow:640 /etc/group:644 /etc/sudoers:440; do
    local f="${p%%:*}" want="${p##*:}"
    [[ -e "$f" ]] || continue
    local mode; mode=$(stat -c '%a' "$f" 2>/dev/null)
    [[ -z "$mode" ]] && continue
    if (( 8#$mode > 8#$want )) && [[ "$f" != /etc/shadow || "$mode" != "600" && "$mode" != "000" && "$mode" != "400" && "$mode" != "640" ]]; then
      finding MEDIUM sysaudit "$f mode $mode is looser than recommended $want"
    else
      finding PASS sysaudit "$f permissions OK ($mode)"
    fi
  done
  local ww; ww=$(find /etc -xdev -type f -perm -0002 2>/dev/null | head -5)
  [[ -n "$ww" ]] && finding HIGH sysaudit "World-writable files in /etc: $(tr '\n' ' ' <<< "$ww")" || finding PASS sysaudit "No world-writable files in /etc"
  local suid; suid=$(find /usr /bin /sbin -xdev -type f -perm -4000 2>/dev/null | wc -l)
  info "SUID binaries found: $suid (review against a known-good baseline)"
  local odd; odd=$(find /tmp /var/tmp -xdev -type f -perm -4000 2>/dev/null | head -3)
  [[ -n "$odd" ]] && finding CRITICAL sysaudit "SUID files in temp directories: $odd"

  header "Network exposure"
  if have ss; then
    local listen; listen=$(ss -tulnH 2>/dev/null | awk '{print $1" "$5}')
    local wild; wild=$(awk '$2 ~ /^(0\.0\.0\.0|\*|\[::\]):/{print $2}' <<< "$listen" | sort -u | tr '\n' ' ')
    [[ -n "$wild" ]] && info "Listening on all interfaces: $wild" || info "No wildcard listeners."
    grep -qE ':23( |$)' <<< "$wild" && finding HIGH sysaudit "Telnet is listening on all interfaces"
  else
    info "ss not available; skipping listener check."
  fi
  if have ufw && ufw status 2>/dev/null | grep -q active; then finding PASS sysaudit "UFW firewall active"
  elif have iptables && iptables -S 2>/dev/null | grep -q -- '-P INPUT DROP'; then finding PASS sysaudit "iptables default INPUT policy DROP"
  elif have nft && nft list ruleset 2>/dev/null | grep -q 'hook input'; then finding PASS sysaudit "nftables rules present"
  else finding MEDIUM sysaudit "No active host firewall detected (or insufficient privileges to tell)"; fi

  header "Kernel hardening (sysctl)"
  _sc() { cat "/proc/sys/${1//.//}" 2>/dev/null; }
  [[ "$(_sc net.ipv4.ip_forward)" == "1" ]] && finding LOW sysaudit "IP forwarding enabled" || true
  [[ "$(_sc net.ipv4.conf.all.accept_redirects)" == "1" ]] && finding LOW sysaudit "ICMP redirects accepted"
  [[ "$(_sc net.ipv4.tcp_syncookies)" == "0" ]] && finding MEDIUM sysaudit "SYN cookies disabled"
  local aslr; aslr=$(_sc kernel.randomize_va_space)
  [[ -n "$aslr" ]] && { [[ "$aslr" == "2" ]] && finding PASS sysaudit "ASLR fully enabled" || finding MEDIUM sysaudit "ASLR not fully enabled (value $aslr)"; }

  header "Privilege escalation hints"
  if [[ -r /etc/sudoers ]]; then
    grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^#' | head -3 | while read -r l; do
      finding MEDIUM sysaudit "sudo NOPASSWD rule: $l"; done
  fi
  local pu; pu=$(awk -F: '$5 !~ /^[0-9]+$/ {next} $5>99999{print $1}' /etc/shadow 2>/dev/null | head -3)
  [[ -n "$pu" ]] && finding LOW sysaudit "Accounts with no password expiry: $pu"
  ok "Audit complete."
}

# ---------------------------------------------------------------------------
run_logs() {
  local file="${1:-/var/log/auth.log}" thr="${2:-$FAILED_LOGIN_THRESHOLD}"
  [[ -r "$file" ]] || { fail "Cannot read log file: $file"; return 1; }
  [[ "$thr" =~ ^[0-9]+$ ]] || { fail "Threshold must be a number."; return 1; }
  header "Log analysis: $file (threshold $thr)"

  local fails; fails=$(grep -E 'Failed password|authentication failure|Invalid user|Failed publickey' "$file" || true)
  local total; total=$(grep -c . <<< "$fails")
  [[ -z "$fails" ]] && total=0
  info "Failed authentication events: $total"
  (( total == 0 )) && { finding PASS logs "No failed logins in $file"; return 0; }

  echo; printf '  %-8s %s\n' COUNT SOURCE-IP
  local flagged=0
  while read -r cnt ip; do
    [[ -z "$ip" ]] && continue
    printf '  %-8s %s\n' "$cnt" "$ip"
    if (( cnt >= thr )); then
      finding HIGH logs "Possible brute force: $ip made $cnt failed attempts"
      flagged=$((flagged + 1))
    fi
  done < <(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' <<< "$fails" | sort | uniq -c | sort -rn | head -15)

  echo; info "Most targeted usernames:"
  grep -oE '(Invalid user|Failed password for( invalid user)?) [^ ]+' <<< "$fails" \
    | awk '{print $NF}' | sort | uniq -c | sort -rn | head -8 | sed 's/^/    /'

  grep -q 'Accepted password for root' "$file" && finding HIGH logs "Successful root password login recorded"
  local acc; acc=$(grep -c 'Accepted ' "$file" || true)
  info "Successful logins in file: $acc"
  (( flagged == 0 )) && finding INFO logs "No source exceeded the threshold of $thr"

  if (( flagged > 0 )); then
    info "Mitigation: enable fail2ban/sshguard, key-only auth, and restrict SSH by firewall."
  fi
}

# ---------------------------------------------------------------------------
run_fim() {
  local action="${1:-}" dir="${2:-}"
  [[ "$action" == "baseline" || "$action" == "check" ]] || { fail "Usage: fim baseline|check <dir>"; return 1; }
  [[ -d "$dir" ]] || { fail "Not a directory: $dir"; return 1; }
  have sha256sum || { fail "sha256sum required."; return 1; }

  local abs; abs=$(cd "$dir" && pwd)
  local key; key=$(printf '%s' "$abs" | sha256sum | cut -c1-12)
  local base="$REPORT_DIR/fim-$key.baseline"

  if [[ "$action" == "baseline" ]]; then
    header "FIM baseline: $abs"
    ( cd "$abs" && find . -type f -print0 | sort -z | xargs -0 -r sha256sum ) > "$base"
    ok "Baseline stored: $base ($(wc -l < "$base") files)"
    return 0
  fi

  header "FIM check: $abs"
  [[ -f "$base" ]] || { fail "No baseline for $abs. Run: fim baseline $dir"; return 1; }
  local now; now=$(mktemp)
  ( cd "$abs" && find . -type f -print0 | sort -z | xargs -0 -r sha256sum ) > "$now"

  local changed=0 added=0 removed=0
  local f
  while read -r f; do
    finding HIGH fim "MODIFIED: $f"; changed=$((changed + 1))
  done < <(join -j2 -o 1.2 -o 1.1 -o 2.1 <(sort -k2 "$base") <(sort -k2 "$now") 2>/dev/null | awk '$2!=$3{print $1}')
  while read -r f; do
    finding MEDIUM fim "ADDED:    $f"; added=$((added + 1))
  done < <(comm -13 <(awk '{print $2}' "$base" | sort) <(awk '{print $2}' "$now" | sort))
  while read -r f; do
    finding MEDIUM fim "REMOVED:  $f"; removed=$((removed + 1))
  done < <(comm -23 <(awk '{print $2}' "$base" | sort) <(awk '{print $2}' "$now" | sort))
  rm -f "$now"
  if (( changed + added + removed == 0 )); then finding PASS fim "No changes since baseline"
  else info "Summary: $changed modified, $added added, $removed removed"; fi
}
