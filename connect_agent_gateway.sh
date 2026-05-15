#!/usr/bin/env sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON_SCRIPT="$SCRIPT_DIR/tools/agent_gateway/connect_entry.py"

echo "[INFO] Working directory: $SCRIPT_DIR"
echo "[INFO] Gateway entry script: $PYTHON_SCRIPT"

if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo "[ERROR] Missing file: $PYTHON_SCRIPT"
    exit 1
fi

PYTHON_BIN=$(command -v python3)
if [ -n "$PYTHON_BIN" ]; then
    :
else
    PYTHON_BIN=$(command -v python)
fi

if [ -z "$PYTHON_BIN" ]; then
    echo "[ERROR] Python 3 was not found."
    exit 1
fi

export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

echo "[INFO] Using Python: $PYTHON_BIN"
if [ "$#" -eq 0 ]; then
    echo "[INFO] Launching interactive gateway connection flow..."
else
    echo "[INFO] Forwarding custom arguments to gateway connection flow..."
fi

"$PYTHON_BIN" "$PYTHON_SCRIPT" "$@"
EXIT_CODE=$?
echo "[INFO] Script finished with exit code $EXIT_CODE."
exit "$EXIT_CODE"
