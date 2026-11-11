#!/usr/bin/env bash
# Module: reporting and scope management.

_html_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

run_report() {
  local fmt="${1:-txt}"
  [[ "$fmt" == "txt" || "$fmt" == "html" ]] || { fail "Format must be txt or html."; return 1; }
  [[ -s "$FINDINGS_FILE" ]] || { warn "No findings recorded today ($FINDINGS_FILE). Run some modules first."; return 1; }

  local out="$REPORT_DIR/report-$(date +%Y%m%d-%H%M%S).$fmt"
  local sev n
  declare -A count
  for sev in CRITICAL HIGH MEDIUM LOW INFO PASS; do
    count[$sev]=$(awk -F'|' -v s="$sev" '$2==s' "$FINDINGS_FILE" | wc -l)
  done

  if [[ "$fmt" == "txt" ]]; then
    {
      echo "$TOOLKIT_NAME - Assessment Report"
      echo "Generated: $(date)  Host: $(hostname)  Operator: $(id -un)"
      echo "============================================================"
      echo "SUMMARY"
      for sev in CRITICAL HIGH MEDIUM LOW INFO PASS; do printf '  %-9s %s\n' "$sev" "${count[$sev]}"; done
      echo
      echo "FINDINGS (highest severity first)"
      for sev in CRITICAL HIGH MEDIUM LOW INFO PASS; do
        awk -F'|' -v s="$sev" '$2==s{printf "  [%s] (%s) %s\n",$2,$3,$4}' "$FINDINGS_FILE"
      done
    } > "$out"
  else
    {
      cat <<EOF
<!doctype html><html><head><meta charset="utf-8"><title>$TOOLKIT_NAME Report</title>
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1b1f23}
h1{margin-bottom:0}.meta{color:#57606a;margin-bottom:1.5rem}
.cards{display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:1.5rem}
.card{padding:.6rem 1rem;border-radius:8px;color:#fff;min-width:90px;text-align:center}
.card b{display:block;font-size:1.6rem}
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #d0d7de;padding:.45rem .6rem;text-align:left;font-size:.92rem}
th{background:#f6f8fa}
.CRITICAL{background:#82071e}.HIGH{background:#cf222e}.MEDIUM{background:#bf8700}.LOW{background:#0969da}.INFO{background:#57606a}.PASS{background:#1a7f37}
.tag{color:#fff;padding:.1rem .5rem;border-radius:4px;font-size:.78rem;font-weight:600}
</style></head><body>
<h1>$TOOLKIT_NAME &mdash; Assessment Report</h1>
<div class="meta">Generated $(date) &middot; Host $(hostname | _html_escape) &middot; Operator $(id -un | _html_escape)</div>
<div class="cards">
EOF
      for sev in CRITICAL HIGH MEDIUM LOW INFO PASS; do
        echo "<div class=\"card $sev\"><b>${count[$sev]}</b>$sev</div>"
      done
      echo '</div><table><tr><th>Severity</th><th>Module</th><th>Finding</th><th>Time</th></tr>'
      for sev in CRITICAL HIGH MEDIUM LOW INFO PASS; do
        awk -F'|' -v s="$sev" '$2==s{print $1"|"$2"|"$3"|"$4}' "$FINDINGS_FILE" | while IFS='|' read -r ts sv mod msg; do
          printf '<tr><td><span class="tag %s">%s</span></td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
            "$sv" "$sv" "$(_html_escape <<< "$mod")" "$(_html_escape <<< "$msg")" "$ts"
        done
      done
      echo '</table><p class="meta">Only test systems you own or are authorized in writing to assess.</p></body></html>'
    } > "$out"
  fi
  ok "Report written: $out"
  for sev in CRITICAL HIGH MEDIUM; do n=${count[$sev]}; (( n > 0 )) && warn "$n $sev finding(s)"; done
  return 0
}

run_scope() {
  header "Authorized scope ($SCOPE_FILE)"
  grep -vE '^[[:space:]]*(#|$)' "$SCOPE_FILE" 2>/dev/null | sed 's/^/  /' || warn "No scope file."
  if [[ -t 0 && -z "${1:-}" ]]; then
    printf '\nAdd a target (blank to skip): '
    local t; read -r t
    if [[ -n "$t" ]]; then
      if valid_host "$t" || [[ "$t" == \*.* ]]; then
        printf '%sConfirm you own this system or have WRITTEN authorization [yes/no]: %s' "$YEL" "$RST"
        local a; read -r a
        if [[ "$a" == "yes" ]]; then echo "$t" >> "$SCOPE_FILE"; ok "Added $t to scope."
        else warn "Not added."; fi
      else fail "Invalid host."; fi
    fi
  elif [[ "${1:-}" == "add" && -n "${2:-}" ]]; then
    valid_host "$2" && { echo "$2" >> "$SCOPE_FILE"; ok "Added $2"; }
  fi
}
