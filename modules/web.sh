#!/usr/bin/env bash
# Module: web application security posture audit + TLS audit.

run_web() {
  local input="${1:-}"
  [[ -z "$input" ]] && { fail "Usage: web <url|host>"; return 1; }
  local url="$input"
  [[ "$url" =~ ^https?:// ]] || url="https://$url"
  local host="${url#*://}"; host="${host%%/*}"; host="${host%%:*}"
  require_target "$host" || return 1
  have curl || { fail "curl is required."; return 1; }

  header "Web audit: $url"
  local hdrs
  hdrs=$(curl -sIL --max-time "$HTTP_TIMEOUT" -A "$USER_AGENT" "$url" 2>/dev/null | tr -d '\r')
  if [[ -z "$hdrs" ]]; then fail "No response from $url"; return 1; fi
  local status; status=$(grep -m1 '^HTTP' <<< "$hdrs")
  info "Response: $status"

  _hdr() { grep -i -m1 "^$1:" <<< "$hdrs" | sed -E 's/^[^:]+:[[:space:]]*//'; }

  header "Security headers"
  local h v
  declare -A need=(
    [strict-transport-security]="HSTS missing (downgrade / MITM risk)"
    [content-security-policy]="CSP missing (XSS mitigation absent)"
    [x-frame-options]="X-Frame-Options missing (clickjacking risk)"
    [x-content-type-options]="X-Content-Type-Options missing (MIME sniffing)"
    [referrer-policy]="Referrer-Policy missing"
    [permissions-policy]="Permissions-Policy missing"
  )
  for h in strict-transport-security content-security-policy x-frame-options x-content-type-options referrer-policy permissions-policy; do
    v=$(_hdr "$h")
    if [[ -z "$v" ]]; then
      local sev=LOW
      [[ "$h" == "strict-transport-security" || "$h" == "content-security-policy" ]] && sev=MEDIUM
      finding "$sev" web "$host: ${need[$h]}"
    else
      finding PASS web "$host: $h present"
    fi
  done

  header "Information disclosure"
  local srv pwr
  srv=$(_hdr server); pwr=$(_hdr x-powered-by)
  if [[ "$srv" =~ [0-9]+\.[0-9]+ ]]; then finding LOW web "Server header leaks version: $srv"
  elif [[ -n "$srv" ]]; then finding INFO web "Server header: $srv"; fi
  [[ -n "$pwr" ]] && finding LOW web "X-Powered-By discloses technology: $pwr"

  header "Cookie flags"
  local cookies; cookies=$(grep -i '^set-cookie:' <<< "$hdrs")
  if [[ -z "$cookies" ]]; then info "No cookies set on this response."
  else
    while IFS= read -r c; do
      local name="${c#*: }"; name="${name%%=*}"
      grep -qi 'secure'   <<< "$c" || finding MEDIUM web "Cookie '$name' missing Secure flag"
      grep -qi 'httponly' <<< "$c" || finding MEDIUM web "Cookie '$name' missing HttpOnly flag"
      grep -qi 'samesite' <<< "$c" || finding LOW web "Cookie '$name' missing SameSite attribute"
    done <<< "$cookies"
  fi

  header "HTTP methods"
  local allow
  allow=$(curl -s -X OPTIONS -D - -o /dev/null --max-time "$HTTP_TIMEOUT" -A "$USER_AGENT" "$url" 2>/dev/null | tr -d '\r' | grep -i '^allow:' | sed -E 's/^[^:]+:[[:space:]]*//')
  if [[ -n "$allow" ]]; then
    info "Allowed: $allow"
    grep -qiE 'TRACE|TRACK' <<< "$allow" && finding MEDIUM web "TRACE/TRACK method enabled"
    grep -qiE 'PUT|DELETE' <<< "$allow" && finding LOW web "PUT/DELETE enabled; verify authorization controls"
  else
    info "No Allow header returned."
  fi

  header "Common exposed files (GET status only)"
  local base="${url%/}" path code
  base="${base%%\?*}"
  [[ "$base" =~ ^(https?://[^/]+) ]] && base="${BASH_REMATCH[1]}"
  for path in robots.txt .git/HEAD .env .DS_Store backup.zip phpinfo.php server-status admin/ .well-known/security.txt; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time "$HTTP_TIMEOUT" -A "$USER_AGENT" "$base/$path" 2>/dev/null)
    case "$path:$code" in
      .git/HEAD:200|.env:200|backup.zip:200|phpinfo.php:200|server-status:200)
        finding HIGH web "/$path is publicly accessible (HTTP $code)" ;;
      admin/:200|admin/:401|admin/:403)
        finding INFO web "/$path responds with HTTP $code (admin surface exists)" ;;
      robots.txt:200|.well-known/security.txt:200)
        finding INFO web "/$path present" ;;
      *) dbg "/$path -> $code" ;;
    esac
  done
}

run_tls() {
  local host="${1:-}" port="${2:-443}"
  require_target "$host" || return 1
  valid_port "$port" || { fail "Bad port"; return 1; }
  have openssl || { fail "openssl is required."; return 1; }

  header "TLS audit: $host:$port"
  local cert
  cert=$(printf '' | timeout 10 openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null)
  if ! grep -q 'BEGIN CERTIFICATE' <<< "$cert"; then
    fail "No certificate retrieved (TLS not offered or host unreachable)."; return 1
  fi
  local pem; pem=$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' <<< "$cert")
  local subj iss nb na
  subj=$(openssl x509 -noout -subject -nameopt multiline <<< "$pem" 2>/dev/null | awk -F= '/commonName/{gsub(/^ +/,"",$2);print $2}')
  iss=$(openssl x509 -noout -issuer <<< "$pem" 2>/dev/null | sed 's/^issuer=//')
  nb=$(openssl x509 -noout -startdate <<< "$pem" | cut -d= -f2)
  na=$(openssl x509 -noout -enddate <<< "$pem" | cut -d= -f2)
  info "Subject CN : ${subj:-n/a}"
  info "Issuer     : $iss"
  info "Valid from : $nb"
  info "Valid to   : $na"

  if openssl x509 -noout -checkend 0 <<< "$pem" >/dev/null; then
    if ! openssl x509 -noout -checkend $((30*86400)) <<< "$pem" >/dev/null; then
      finding MEDIUM tls "$host certificate expires within 30 days ($na)"
    else
      finding PASS tls "$host certificate valid until $na"
    fi
  else
    finding HIGH tls "$host certificate has EXPIRED ($na)"
  fi

  local sig; sig=$(openssl x509 -noout -text <<< "$pem" | awk -F': ' '/Signature Algorithm/{print $2; exit}')
  info "Signature  : $sig"
  grep -qiE 'md5|sha1' <<< "$sig" && finding MEDIUM tls "Weak certificate signature algorithm: $sig"

  [[ "$(openssl x509 -noout -issuer <<< "$pem")" == "issuer=$(openssl x509 -noout -subject <<< "$pem" | sed 's/^subject=//')" ]] 2>/dev/null \
    && warn "Certificate appears self-signed."

  header "Protocol support"
  local proto flag out
  for proto in tls1 tls1_1 tls1_2 tls1_3; do
    flag="-$proto"
    out=$(printf '' | timeout 6 openssl s_client -connect "$host:$port" -servername "$host" "$flag" 2>&1)
    if grep -qE 'Cipher is [A-Za-z0-9_-]+|Cipher    : [A-Za-z0-9_-]+' <<< "$out" && ! grep -q 'Cipher is (NONE)' <<< "$out" \
       && ! grep -qiE 'handshake failure|no protocols available|wrong version|unsupported|alert' <<< "$out"; then
      case "$proto" in
        tls1|tls1_1) finding MEDIUM tls "$host supports deprecated ${proto/_/.}" ;;
        *)           finding PASS tls "$host supports ${proto/_/.}" ;;
      esac
    else
      dbg "$proto not supported"
    fi
  done
}
