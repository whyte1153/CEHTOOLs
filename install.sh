#!/usr/bin/env bash
# Installer: marks scripts executable, checks dependencies, optionally symlinks `ceh`.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$ROOT"/ceh.sh "$ROOT"/install.sh "$ROOT"/tests/run-tests.sh
echo "Checking dependencies..."
for t in bash curl openssl timeout awk sed grep sha256sum; do
  command -v "$t" >/dev/null && echo "  [ok]       $t" || echo "  [MISSING]  $t (required)"
done
for t in dig host nslookup ss nmap; do
  command -v "$t" >/dev/null && echo "  [ok]       $t" || echo "  [optional] $t not found (reduced functionality)"
done
if [[ "${1:-}" == "--link" ]]; then
  dest="${HOME}/.local/bin"; mkdir -p "$dest"
  ln -sf "$ROOT/ceh.sh" "$dest/ceh" && echo "Linked: $dest/ceh (ensure it is on your PATH)"
fi
echo "Done. Run: $ROOT/ceh.sh"
