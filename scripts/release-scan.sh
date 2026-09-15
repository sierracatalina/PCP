#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' >/dev/null 2>&1; then
  exec python3 "$SCRIPT_DIR/release_scan.py" "${1:-.}"
fi

if command -v python >/dev/null 2>&1 && python -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' >/dev/null 2>&1; then
  exec python "$SCRIPT_DIR/release_scan.py" "${1:-.}"
fi

if command -v py >/dev/null 2>&1 && py -3 -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' >/dev/null 2>&1; then
  exec py -3 "$SCRIPT_DIR/release_scan.py" "${1:-.}"
fi

echo "PUBLIC RELEASE SCAN ERROR: Python 3.11 or later is required" >&2
exit 2
