#!/usr/bin/env bash
# demo.sh — openconnect-slop end-to-end demo
#
# Usage: ./demo.sh <vpn-host> <protected-url>
#
# Demonstrates TOTP-prompt and push auth modes. Tunnel credentials stay
# inside subshells and never leak into the calling shell's environment.
# All tunnel output (stdout + stderr) is appended to a timestamped log file.
#
# Prerequisites:
#   openconnect-slop config file with username + auth_group
#   brew install openconnect  (macOS)  or  apt install openconnect  (Linux)

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <vpn-host> <protected-url>" >&2
  echo "  Example: $0 vpn01.company.com https://docs.company.com" >&2
  exit 1
fi

TOOL="$(dirname "$0")/openconnect-slop"
VPN_HOST="$1"
TARGET="$2"
LOGFILE="demo-$(date +%Y%m%d-%H%M%S).log"

echo "Tunnel output → $LOGFILE"
echo ""
ls -lahF --color "$TOOL"
echo "  openconnect: $(openconnect --version 2>&1 | head -1)"

# ── helpers ──────────────────────────────────────────────────────────────────

banner() {
  printf '\n\033[1;36m══  %s  ══\033[0m\n' "$*"
}

check_access() {
  local status
  status=$(curl -sL --max-time 5 -o /dev/null -w "%{http_code}" "$TARGET" 2>/dev/null) \
    || status="FAILED"
  if [[ "$status" == "FAILED" || "$status" == "000" ]]; then
    printf '  \033[1;31m✗\033[0m  %s  →  unreachable\n' "$TARGET"
  else
    printf '  \033[1;32m✓\033[0m  %s  →  HTTP %s\n' "$TARGET" "$status"
  fi
}

connect_and_test() {
  local mode="$1"
  local prompt="$2"

  # Subshell: COOKIE / HOST / FINGERPRINT / VPID never escape to the caller.
  (
    banner "Auth — mode: $mode"
    echo "  \$ $TOOL --auth-mode $mode $VPN_HOST"
    printf '  \033[2m↳ %s\033[0m\n\n' "$prompt"
    eval "$($TOOL --auth-mode "$mode" "$VPN_HOST")"

    banner "Connecting tunnel"
    echo "  \$ sudo openconnect --quiet --cookie-on-stdin ... (output → $LOGFILE)"
    # stdout + stderr both go to the log file; tunnel runs in background.
    sudo openconnect --quiet \
      --cookie-on-stdin \
      --servercert "$FINGERPRINT" \
      "$HOST" <<< "$COOKIE" >>"$LOGFILE" 2>&1 &
    VPID=$!

    sleep 4  # allow tunnel and routes to establish

    banner "Tunnel up"
    check_access

    banner "Disconnecting"
    # SIGTERM: openconnect catches it, tears down the tunnel, restores routes.
    echo "  \$ sudo kill -TERM $VPID"
    sudo kill -TERM "$VPID" 2>/dev/null || true
    sleep 2

    check_access
  )
}

# ── main ─────────────────────────────────────────────────────────────────────

banner "Caching sudo credentials (openconnect needs root to create the TUN interface)"
sudo -v

banner "Baseline — no VPN"
check_access

connect_and_test totp-prompt "Enter the 6-digit code from your authenticator app when prompted"
connect_and_test push        "Approve the push notification in your authenticator app"

banner "Done  ·  log: $LOGFILE"
