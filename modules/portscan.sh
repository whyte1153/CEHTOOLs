#!/usr/bin/env bash
# Module: TCP connect port scanner + banner grabber (pure bash, /dev/tcp).

run_portscan() {
  local host="${1:-}" spec="${2:-top}"
  require_target "$host" || return 1

  local ports
  case "$spec" in
    top) ports="$TOP_PORTS" ;;
    all) ports="1-65535" ;;
    *)   ports="$spec" ;;
  esac
  local list
  list=$(expand_ports "$ports") || return 1
  local total; total=$(wc -l <<< "$list")

  local ip; ip=$(lookup_a "$host")
  [[ -z "$ip" ]] && { fail "Could not resolve $host"; return 1; }

  header "Port scan: $host ($ip) - $total ports"
  info "Timeout ${SCAN_TIMEOUT}s, ${SCAN_THREADS} parallel probes"
  local start=$SECONDS tmp; tmp=$(mktemp)

  local p running=0
  while read -r p; do
    ( tcp_open "$ip" "$p" && echo "$p" >> "$tmp" ) &
    running=$((running + 1))
    if (( running >= SCAN_THREADS )); then wait -n 2>/dev/null || wait; running=$((running - 1)); fi
  done <<< "$list"
  wait

  local open_count=0
  if [[ -s "$tmp" ]]; then
    printf '\n  %-8s %-8s %-14s %s\n' PORT STATE SERVICE NOTE
    while read -r p; do
      open_count=$((open_count + 1))
      local svc note; svc=$(service_name "$p"); note=$(risky_port_note "$p")
      printf '  %-8s %-8s %-14s %s\n' "$p/tcp" open "$svc" "$note"
      if [[ -n "$note" ]]; then
        finding MEDIUM portscan "$host:$p ($svc) open - $note"
      else
        finding INFO portscan "$host:$p ($svc) open"
      fi
    done < <(sort -n "$tmp")
  fi
  rm -f "$tmp"
  echo
  ok "Scan finished in $((SECONDS - start))s: $open_count open of $total ports."
}

run_banner() {
  local host="${1:-}" port="${2:-}"
  require_target "$host" || return 1
  valid_port "$port" || { fail "Usage: banner <host> <port>"; return 1; }
  header "Banner grab: $host:$port"
  local out
  case "$port" in
    80|8000|8080)
      out=$(timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port; printf 'HEAD / HTTP/1.0\r\nHost: $host\r\nUser-Agent: $USER_AGENT\r\n\r\n' >&3; head -n 12 <&3" 2>/dev/null | tr -d '\r') ;;
    443|8443)
      if have openssl; then
        out=$(printf 'HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n' "$host" | timeout 8 openssl s_client -quiet -connect "$host:$port" -servername "$host" 2>/dev/null | head -n 12 | tr -d '\r')
      fi ;;
    *)
      out=$(timeout 4 bash -c "exec 3<>/dev/tcp/$host/$port; timeout 2 head -n 3 <&3" 2>/dev/null | tr -d '\r') ;;
  esac
  if [[ -z "$out" ]]; then
    warn "No banner received (service may be silent or filtered)."
  else
    printf '%s\n' "$out" | sed 's/^/    /'
    if grep -qiE 'server:|ssh-|ftp|smtp|mysql|postgres' <<< "$out"; then
      finding LOW banner "$host:$port discloses software/version information"
    fi
  fi
}
