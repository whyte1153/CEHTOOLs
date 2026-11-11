#!/usr/bin/env bash
# Self-test: syntax checks + functional checks against localhost and sample data.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CEH="$ROOT/ceh.sh"
export COLOR=off
pass=0; failn=0
check() {  # check <name> <command...>
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "PASS  $name"; pass=$((pass+1)); else echo "FAIL  $name"; failn=$((failn+1)); fi
}

for f in "$ROOT"/ceh.sh "$ROOT"/lib/*.sh "$ROOT"/modules/*.sh "$ROOT"/install.sh; do
  check "syntax $(basename "$f")" bash -n "$f"
done

# Local listener for the port scanner
python3 -m http.server 18080 --bind 127.0.0.1 >/dev/null 2>&1 &
SRV=$!; sleep 1

check "help"                     "$CEH" help
check "portscan finds open port" bash -c "'$CEH' portscan 127.0.0.1 18080 | grep -q '18080/tcp'"
check "portscan closed port"     bash -c "! '$CEH' portscan 127.0.0.1 18081 | grep -q '18081/tcp'"
check "scope blocks unknown"     bash -c "'$CEH' portscan 203.0.113.9 80 2>&1 | grep -q 'NOT in scope'"
check "rejects injection"        bash -c "'$CEH' portscan 'x;id' 80 2>&1 | grep -q 'Invalid target'"
check "banner grab"              bash -c "'$CEH' banner 127.0.0.1 18080 2>&1 | grep -qi 'HTTP\|banner'"
check "web audit"                bash -c "'$CEH' web http://127.0.0.1:18080 | grep -q 'Security headers'"
check "hashid md5"               bash -c "'$CEH' hashid 5f4dcc3b5aa765d61d8327deb882cf99 | grep -q MD5"
check "hashid bcrypt"            bash -c "'$CEH' hashid '\$2b\$12\$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234' | grep -q bcrypt"
check "passcheck weak"           bash -c "echo 'password123' | '$CEH' passcheck | grep -q WEAK"
check "passcheck strong"         bash -c "echo 'Tr0ub4dor&Horse-Staple#92' | '$CEH' passcheck | grep -q STRONG"

# Log analysis with synthetic data
LOG=$(mktemp)
for i in 1 2 3 4 5 6 7; do echo "Nov 11 10:0$i:00 host sshd[1]: Failed password for invalid user admin from 198.51.100.7 port 4000$i ssh2" >> "$LOG"; done
echo "Nov 11 10:10:00 host sshd[1]: Accepted publickey for alice from 192.0.2.5 port 5000 ssh2" >> "$LOG"
check "logs flags brute force"   bash -c "'$CEH' logs '$LOG' 5 | grep -q 'Possible brute force: 198.51.100.7'"
rm -f "$LOG"

# File integrity monitoring
D=$(mktemp -d); echo a > "$D/a.txt"; echo b > "$D/b.txt"
"$CEH" fim baseline "$D" >/dev/null 2>&1
echo changed > "$D/a.txt"; echo new > "$D/c.txt"; rm "$D/b.txt"
OUT=$("$CEH" fim check "$D" 2>&1)
check "fim detects modified"     grep -q 'MODIFIED: ./a.txt' <<< "$OUT"
check "fim detects added"        grep -q 'ADDED:    ./c.txt' <<< "$OUT"
check "fim detects removed"      grep -q 'REMOVED:  ./b.txt' <<< "$OUT"
rm -rf "$D"

check "sysaudit runs"            "$CEH" sysaudit
check "report txt"               "$CEH" report txt
check "report html"              "$CEH" report html

kill "$SRV" 2>/dev/null
echo "----"; echo "Passed: $pass  Failed: $failn"
(( failn == 0 ))
