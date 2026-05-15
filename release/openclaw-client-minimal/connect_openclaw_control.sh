#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/tools/openclaw_control_connect.py"

echo "[INFO] Working directory: $SCRIPT_DIR"
echo "[INFO] OpenClaw control connect script: $PYTHON_SCRIPT"
echo "[INFO] This launcher activates Runtime credentials and starts the OpenClaw security bridge."

if [[ ! -f "$PYTHON_SCRIPT" ]]; then
  echo "[ERROR] Missing file: $PYTHON_SCRIPT"
  exit 1
fi

if [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
  PYTHON_BIN="$VIRTUAL_ENV/bin/python"
elif [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "[ERROR] Python executable was not found."
  exit 1
fi

echo "[INFO] Using Python: $PYTHON_BIN"
if [[ $# -eq 0 ]]; then
  echo "[INFO] Launching interactive OpenClaw protected connection flow..."
  "$PYTHON_BIN" "$PYTHON_SCRIPT"
else
  echo "[INFO] Forwarding custom arguments to OpenClaw protected connection flow..."
  "$PYTHON_BIN" "$PYTHON_SCRIPT" "$@"
fi
