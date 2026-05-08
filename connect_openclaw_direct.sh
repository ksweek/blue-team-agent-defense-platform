#!/usr/bin/env sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON_SCRIPT="$SCRIPT_DIR/tools/openclaw_control_autoconnect.py"

if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo "[错误] 未找到脚本: $PYTHON_SCRIPT"
    exit 1
fi

if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "[错误] 未找到 Python，请先安装 Python 3。"
    exit 1
fi

export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

echo "[信息] 正在执行 OpenClaw 一键直连脚本..."
exec "$PYTHON_BIN" "$PYTHON_SCRIPT"
