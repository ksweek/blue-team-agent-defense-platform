#!/usr/bin/env sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON_SCRIPT="$SCRIPT_DIR/tools/agent_gateway/agent_gateway_cli.py"

if [ ! -f "$PYTHON_SCRIPT" ]; then
    exit 1
fi

if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    exit 1
fi

export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

exec "$PYTHON_BIN" "$PYTHON_SCRIPT" "$@"
