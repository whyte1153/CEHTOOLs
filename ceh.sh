#!/usr/bin/env bash
# CEH Toolkit - modular, bash-only security assessment toolkit.
# For authorized testing and defensive auditing ONLY.
set -u

TOOLKIT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TOOLKIT_ROOT
VERSION="1.0.0"

# shellcheck source=lib/common.sh
source "$TOOLKIT_ROOT/lib/common.sh"
load_config
setup_colors

for m in "$TOOLKIT_ROOT"/modules/*.sh; do
  # shellcheck disable=SC1090
  source "$m"
done

banner() {
  cat <<EOF
${BLD}${GRN}
   ____ _____ _   _   _____           _ _    _ _
  / ___| ____| | | | |_   _|__   ___ | | | _(_) |_
 | |   |  _| | |_| |   | |/ _ \\ / _ \\| | |/ / | __|
 | |___| |___|  _  |   | | (_) | (_) | |   <| | |_
  \\____|_____|_| |_|   |_|\\___/ \\___/|_|_|\\_\\_|\\__|  v$VERSION
${RST}${YEL} Authorized testing & defensive auditing only. Know your scope.${RST}
EOF
}

usage() {
  cat <<EOF
${BLD}Usage:${RST} ceh.sh [command] [args]     (no command = interactive menu)

${BLD}Recon${RST}
  portscan  <host> [ports|top|all]     TCP connect scan (default: top ports)
  banner    <host> <port>              Grab a service banner
  dns       <domain> [--brute]         DNS records, mail auth, AXFR check, subdomains
${BLD}Web / TLS${RST}
  web       <url|host>                 Security headers, cookies, methods, exposed files
  tls       <host> [port]              Certificate & protocol audit
${BLD}Credentials${RST}
  hashid    <hash>                     Identify likely hash type
  passcheck [--pwned]                  Password strength (reads from prompt, hidden)
${BLD}Defensive${RST}
  sysaudit                             Local Linux hardening audit
  logs      <auth.log> [threshold]     Failed-login / brute-force analysis
  fim       baseline|check <dir>       File integrity monitoring
${BLD}Reporting${RST}
  report    [txt|html]                 Build a report from today's findings
  scope                                Show / edit authorized scope
  help                                 This help

Examples:
  ./ceh.sh portscan 127.0.0.1 22,80,443
  ./ceh.sh dns example.org --brute
  ./ceh.sh web https://example.org
  ./ceh.sh report html
EOF
}

menu() {
  while true; do
    clear 2>/dev/null || true
    banner
    cat <<EOF

  ${BLD}RECON${RST}                       ${BLD}DEFENSIVE${RST}
  1) Port scan                 8) System hardening audit
  2) Banner grab               9) Log / brute-force analysis
  3) DNS recon                10) File integrity monitor
  ${BLD}WEB / TLS${RST}                    ${BLD}REPORTING${RST}
  4) Web security audit       11) Generate report
  5) TLS certificate audit    12) View / edit scope
  ${BLD}CREDENTIALS${RST}                  13) Help
  6) Identify hash             0) Exit
  7) Password strength
EOF
    printf '\n%sceh>%s ' "$GRN" "$RST"
    read -r choice || exit 0
    case "$choice" in
      1) read -rp "Target host: " h; read -rp "Ports [top|all|22,80,..]: " p; run_portscan "$h" "${p:-top}" ;;
      2) read -rp "Target host: " h; read -rp "Port: " p; run_banner "$h" "$p" ;;
      3) read -rp "Domain: " d; read -rp "Brute-force subdomains? [y/N]: " b
         if [[ "$b" =~ ^[Yy] ]]; then run_dns "$d" --brute; else run_dns "$d"; fi ;;
      4) read -rp "URL or host: " u; run_web "$u" ;;
      5) read -rp "Host: " h; read -rp "Port [443]: " p; run_tls "$h" "${p:-443}" ;;
      6) read -rp "Hash: " h; run_hashid "$h" ;;
      7) run_passcheck ;;
      8) run_sysaudit ;;
      9) read -rp "Log file [/var/log/auth.log]: " f; run_logs "${f:-/var/log/auth.log}" ;;
     10) read -rp "baseline or check: " a; read -rp "Directory: " d; run_fim "$a" "$d" ;;
     11) read -rp "Format [txt|html]: " f; run_report "${f:-txt}" ;;
     12) run_scope ;;
     13) usage ;;
      0|q|quit|exit) exit 0 ;;
      *) warn "Unknown option." ;;
    esac
    printf '\n%sPress Enter to continue...%s' "$CYN" "$RST"; read -r _ || exit 0
  done
}

main() {
  local cmd="${1:-}"
  [[ $# -gt 0 ]] && shift
  case "$cmd" in
    "")        menu ;;
    portscan)  run_portscan "$@" ;;
    banner)    run_banner "$@" ;;
    dns)       run_dns "$@" ;;
    web)       run_web "$@" ;;
    tls)       run_tls "$@" ;;
    hashid)    run_hashid "$@" ;;
    passcheck) run_passcheck "$@" ;;
    sysaudit)  run_sysaudit "$@" ;;
    logs)      run_logs "$@" ;;
    fim)       run_fim "$@" ;;
    report)    run_report "$@" ;;
    scope)     run_scope "$@" ;;
    -V|--version|version) echo "ceh-toolkit $VERSION" ;;
    -h|--help|help) banner; usage ;;
    *) fail "Unknown command: $cmd"; usage; exit 2 ;;
  esac
}

main "$@"
