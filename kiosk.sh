#!/usr/bin/env bash
set -euo pipefail

# Simple kiosk launcher for Raspberry Pi (X11)
# Run from autostart after desktop login.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

source venv/bin/activate
python monitor.py
