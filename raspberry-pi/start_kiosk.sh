#!/usr/bin/env bash
set -euo pipefail

FRONTEND_URL="${NETOPENWATCHPI_FRONTEND_URL:-${1:-}}"

if [ -z "$FRONTEND_URL" ]; then
  echo "Usage: ./start_kiosk.sh http://<host-pc-ip>:8080/index.html"
  echo "Or set NETOPENWATCHPI_FRONTEND_URL."
  exit 1
fi

if command -v xset >/dev/null 2>&1; then
  xset s off || true
  xset s noblank || true
  xset -dpms || true
fi

if command -v chromium-browser >/dev/null 2>&1; then
  CHROMIUM="chromium-browser"
elif command -v chromium >/dev/null 2>&1; then
  CHROMIUM="chromium"
else
  echo "Chromium was not found. Install it with: sudo apt install chromium-browser"
  exit 1
fi

exec "$CHROMIUM" \
  --kiosk \
  --noerrdialogs \
  --disable-infobars \
  --disable-session-crashed-bubble \
  --check-for-update-interval=31536000 \
  "$FRONTEND_URL"
