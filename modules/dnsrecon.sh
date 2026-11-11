#!/usr/bin/env bash
# Module: DNS reconnaissance for domains you are authorized to assess.

_dns_query() {  # _dns_query <type> <name>
  local type="$1" name="$2"
  if have dig; then
    dig +short +time=3 +tries=1 "$type" "$name" 2>/dev/null
  elif have host; then
    host -W 3 -t "$type" "$name" 2>/dev/null | sed -E 's/^.*(has address|mail is handled by|descriptive text|name server|has IPv6 address|domain name pointer) //'
  elif have nslookup; then
    nslookup -type="$type" "$name" 2>/dev/null | sed -n '/^[^;]*answer/,$p' | tail -n +2
  elif [[ "$type" == "A" ]]; then
    getent ahostsv4 "$name" 2>/dev/null | awk '{print $1}' | sort -u
  fi
}

run_dns() {
  local domain="${1:-}"; shift || true
  local brute=0
  [[ "${1:-}" == "--brute" ]] && brute=1
  require_target "$domain" || return 1

  if ! have dig && ! have host && ! have nslookup; then
    warn "No dig/host/nslookup found; only A-record lookups via getent are possible."
  fi

  header "DNS recon: $domain"
  local t rec
  for t in A AAAA MX NS TXT SOA CNAME; do
    rec=$(_dns_query "$t" "$domain")
    if [[ -n "$rec" ]]; then
      printf '  %s%-6s%s\n' "$BLD" "$t" "$RST"
      sed 's/^/      /' <<< "$rec"
    fi
  done

  # ---- Email authentication -------------------------------------------------
  header "Email authentication (SPF / DMARC)"
  local spf dmarc
  spf=$(_dns_query TXT "$domain" | grep -i 'v=spf1' | head -1)
  dmarc=$(_dns_query TXT "_dmarc.$domain" | grep -i 'v=DMARC1' | head -1)
  if [[ -z "$spf" ]]; then finding MEDIUM dns "$domain has no SPF record (spoofing risk)"
  elif grep -q '+all' <<< "$spf"; then finding HIGH dns "$domain SPF ends in +all (allows anyone to send)"
  elif grep -q '?all' <<< "$spf"; then finding LOW dns "$domain SPF uses neutral ?all"
  else finding PASS dns "$domain SPF present"; fi
  if [[ -z "$dmarc" ]]; then finding MEDIUM dns "$domain has no DMARC record"
  elif grep -qi 'p=none' <<< "$dmarc"; then finding LOW dns "$domain DMARC policy is p=none (monitoring only)"
  else finding PASS dns "$domain DMARC enforced"; fi

  # ---- Zone transfer misconfiguration ---------------------------------------
  header "Zone transfer (AXFR) misconfiguration check"
  if have dig; then
    local ns axfr
    for ns in $(_dns_query NS "$domain"); do
      axfr=$(dig +time=4 +tries=1 AXFR "$domain" "@${ns%.}" 2>/dev/null | grep -vE '^;|^$' | head -5)
      if [[ -n "$axfr" ]] && ! grep -qi 'transfer failed' <<< "$axfr"; then
        finding HIGH dns "Nameserver ${ns%.} allows zone transfer for $domain"
      else
        finding PASS dns "Nameserver ${ns%.} refuses zone transfer"
      fi
    done
  else
    info "dig not installed; skipping AXFR check."
  fi

  # ---- Subdomain enumeration ------------------------------------------------
  if (( brute )); then
    local wl="$TOOLKIT_ROOT/$SUBDOMAIN_WORDLIST"
    [[ -f "$wl" ]] || { fail "Wordlist missing: $wl"; return 1; }
    header "Subdomain enumeration ($(wc -l < "$wl") candidates)"
    local sub ip found=0 running=0 tmp; tmp=$(mktemp)
    while read -r sub; do
      [[ -z "$sub" || "$sub" == \#* ]] && continue
      ( ip=$(lookup_a "$sub.$domain"); [[ -n "$ip" ]] && echo "$sub.$domain -> $ip" >> "$tmp" ) &
      running=$((running + 1))
      if (( running >= 20 )); then wait -n 2>/dev/null || wait; running=$((running - 1)); fi
    done < "$wl"
    wait
    if [[ -s "$tmp" ]]; then
      sort "$tmp" | while read -r line; do ok "$line"; done
      found=$(wc -l < "$tmp")
      finding INFO dns "$found subdomains discovered for $domain"
    else
      info "No subdomains resolved from the wordlist."
    fi
    rm -f "$tmp"
  else
    info "Add --brute to run wordlist subdomain enumeration."
  fi
}
