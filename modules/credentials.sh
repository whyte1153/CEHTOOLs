#!/usr/bin/env bash
# Module: hash identification and password-strength auditing.

run_hashid() {
  local h="${1:-}"
  [[ -z "$h" ]] && { fail "Usage: hashid <hash>"; return 1; }
  header "Hash identification"
  info "Input length: ${#h}"
  local -a guesses=()

  if   [[ "$h" =~ ^\$2[abxy]?\$[0-9]{2}\$.{53}$ ]]; then guesses+=("bcrypt")
  elif [[ "$h" =~ ^\$argon2(id|i|d)\$ ]];           then guesses+=("Argon2")
  elif [[ "$h" =~ ^\$6\$ ]];  then guesses+=("SHA-512 crypt (Linux shadow)")
  elif [[ "$h" =~ ^\$5\$ ]];  then guesses+=("SHA-256 crypt (Linux shadow)")
  elif [[ "$h" =~ ^\$1\$ ]];  then guesses+=("MD5 crypt (obsolete)")
  elif [[ "$h" =~ ^\$y\$ ]];  then guesses+=("yescrypt")
  elif [[ "$h" =~ ^\$P\$ || "$h" =~ ^\$H\$ ]]; then guesses+=("phpass (WordPress/phpBB)")
  elif [[ "$h" =~ ^[0-9a-fA-F]+$ ]]; then
    case ${#h} in
      32)  guesses+=("MD5" "NTLM" "MD4") ;;
      40)  guesses+=("SHA-1" "RIPEMD-160") ;;
      56)  guesses+=("SHA-224" "SHA3-224") ;;
      64)  guesses+=("SHA-256" "SHA3-256" "BLAKE2s") ;;
      96)  guesses+=("SHA-384" "SHA3-384") ;;
      128) guesses+=("SHA-512" "SHA3-512" "Whirlpool" "BLAKE2b") ;;
      16)  guesses+=("MySQL323" "Half MD5") ;;
      8)   guesses+=("CRC32 / Adler32") ;;
    esac
  elif [[ "$h" =~ ^\*[0-9A-F]{40}$ ]]; then guesses+=("MySQL 4.1+ (SHA-1 of SHA-1)")
  fi

  if (( ${#guesses[@]} == 0 )); then
    warn "No known format matched."; return 0
  fi
  local g
  for g in "${guesses[@]}"; do ok "Possible: $g"; done
  case "${guesses[0]}" in
    MD5|MD5\ crypt*|SHA-1|MySQL323*|CRC32*)
      finding MEDIUM hashid "Hash looks like ${guesses[0]}: fast/unsalted algorithms are weak for password storage" ;;
    bcrypt|Argon2|yescrypt|SHA-512\ crypt*|SHA-256\ crypt*)
      finding PASS hashid "Hash looks like ${guesses[0]}: a slow salted password-hashing scheme" ;;
  esac
}

_pw_entropy() {   # estimate bits of entropy from character pools
  local pw="$1" pool=0
  [[ "$pw" =~ [a-z] ]] && pool=$((pool + 26))
  [[ "$pw" =~ [A-Z] ]] && pool=$((pool + 26))
  [[ "$pw" =~ [0-9] ]] && pool=$((pool + 10))
  [[ "$pw" =~ [^a-zA-Z0-9] ]] && pool=$((pool + 33))
  (( pool == 0 )) && { echo 0; return; }
  awk -v n="${#pw}" -v p="$pool" 'BEGIN{printf "%.0f", n*log(p)/log(2)}'
}

run_passcheck() {
  local pwned=0
  [[ "${1:-}" == "--pwned" ]] && pwned=1
  header "Password strength check"
  local pw
  printf 'Enter password (hidden, never stored or logged): '
  IFS= read -rs pw; echo
  [[ -z "$pw" ]] && { fail "Empty password."; return 1; }

  local score=0 len=${#pw} bits issues=()
  (( len >= MIN_PASSWORD_LENGTH )) && score=$((score + 2)) || issues+=("shorter than $MIN_PASSWORD_LENGTH characters")
  (( len >= 16 )) && score=$((score + 1))
  [[ "$pw" =~ [a-z] ]] && score=$((score + 1)) || issues+=("no lowercase letters")
  [[ "$pw" =~ [A-Z] ]] && score=$((score + 1)) || issues+=("no uppercase letters")
  [[ "$pw" =~ [0-9] ]] && score=$((score + 1)) || issues+=("no digits")
  [[ "$pw" =~ [^a-zA-Z0-9] ]] && score=$((score + 1)) || issues+=("no symbols")

  [[ "$pw" =~ (.)\1\1 ]] && { score=$((score - 1)); issues+=("repeated characters (aaa)"); }
  [[ "$pw" =~ (012|123|234|345|456|567|678|789|abc|bcd|cde|qwe|asd|zxc) ]] && { score=$((score - 1)); issues+=("sequential/keyboard pattern"); }
  [[ "$pw" =~ ^[A-Za-z]+[0-9]{1,4}[^a-zA-Z0-9]?$ ]] && issues+=("word + digits pattern is easy to guess")

  local wl="$TOOLKIT_ROOT/$COMMON_PASSWORDS" lower="${pw,,}"
  if [[ -f "$wl" ]] && grep -qxiF -- "$pw" "$wl"; then
    score=0; issues+=("appears in the common-password list")
  elif [[ -f "$wl" ]]; then
    local w
    while read -r w; do
      [[ ${#w} -ge 5 && "$lower" == *"$w"* ]] && { score=$((score - 1)); issues+=("contains common password '$w'"); break; }
    done < <(grep -v '^#' "$wl")
  fi
  (( score < 0 )) && score=0

  bits=$(_pw_entropy "$pw")
  info "Length: $len   Estimated entropy: ~${bits} bits"

  if (( pwned )) && have curl && have sha1sum; then
    local sha prefix suffix count
    sha=$(printf '%s' "$pw" | sha1sum | awk '{print toupper($1)}')
    prefix=${sha:0:5}; suffix=${sha:5}
    count=$(curl -s --max-time 8 "https://api.pwnedpasswords.com/range/$prefix" | tr -d '\r' | awk -F: -v s="$suffix" '$1==s{print $2}')
    if [[ -n "$count" ]]; then
      score=0; issues+=("found in $count known data breaches")
    else
      ok "Not found in Have I Been Pwned (only a 5-char hash prefix was sent)."
    fi
  fi

  local rating
  if   (( score >= 7 )); then rating="STRONG";    finding PASS passcheck "Password rated STRONG (~${bits} bits)"
  elif (( score >= 5 )); then rating="MODERATE";  finding LOW  passcheck "Password rated MODERATE (~${bits} bits)"
  else                        rating="WEAK";      finding HIGH passcheck "Password rated WEAK (~${bits} bits)"; fi
  info "Rating: $rating  (score $score/8)"
  local i; for i in "${issues[@]:-}"; do [[ -n "$i" ]] && warn "$i"; done
  [[ "$rating" != "STRONG" ]] && info "Tip: use a passphrase of 4+ random words or a password manager."
  unset pw
}
