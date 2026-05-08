#!/usr/bin/env sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TARGET_SCRIPT="$SCRIPT_DIR/connect_openclaw_control.sh"
LOG_DIR="$SCRIPT_DIR/run_logs"
LOG_PATH="$LOG_DIR/openclaw-control-frames.jsonl"
PLATFORM_BASE_URL="${PLATFORM_BASE_URL:-http://127.0.0.1:8000}"
UPSTREAM_HTTP_URL="${UPSTREAM_HTTP_URL:-http://OPENCLAW_HOST:18789}"
GATEWAY_TOKEN="${GATEWAY_TOKEN:-REPLACE_WITH_OPENCLAW_GATEWAY_TOKEN}"
ENROLLMENT_TOKEN="${ENROLLMENT_TOKEN:-REPLACE_WITH_RUNTIME_ENROLLMENT_TOKEN}"
RUNTIME_DISPLAY_NAME="${RUNTIME_DISPLAY_NAME:-openclaw-control-OPENCLAW_HOST-18789}"
TARGET_AGENT_NAME="${TARGET_AGENT_NAME:-OpenClaw-Control-OPENCLAW_HOST}"
REVIEW_ACTION="${REVIEW_ACTION:-block}"
LISTEN_PORT="${LISTEN_PORT:-19090}"
ACCESS_HOST="${ACCESS_HOST:-127.0.0.1}"

if [ ! -f "$TARGET_SCRIPT" ]; then
    echo "[ERROR] Missing file: $TARGET_SCRIPT"
    exit 1
fi

mkdir -p "$LOG_DIR"

if [ "$UPSTREAM_HTTP_URL" = "http://OPENCLAW_HOST:18789" ]; then
    echo "[ERROR] 请先编辑脚本或传入环境变量，填入真实的 OpenClaw 地址。"
    exit 1
fi

if [ "$GATEWAY_TOKEN" = "REPLACE_WITH_OPENCLAW_GATEWAY_TOKEN" ]; then
    echo "[ERROR] 请先编辑脚本或传入环境变量，填入真实的 OpenClaw gateway token。"
    exit 1
fi

if [ "$ENROLLMENT_TOKEN" = "REPLACE_WITH_RUNTIME_ENROLLMENT_TOKEN" ]; then
    echo "[ERROR] 请先编辑脚本或传入环境变量，填入平台生成的一次性 Runtime 注册码。"
    exit 1
fi

echo "[INFO] Starting OpenClaw remote bridge..."
echo "[INFO] Platform: $PLATFORM_BASE_URL"
echo "[INFO] Upstream: $UPSTREAM_HTTP_URL"
echo "[INFO] Local browser entry: http://$ACCESS_HOST:$LISTEN_PORT"

exec sh "$TARGET_SCRIPT" \
  --upstream-http-url "$UPSTREAM_HTTP_URL" \
  --gateway-token "$GATEWAY_TOKEN" \
  --platform-base-url "$PLATFORM_BASE_URL" \
  --enrollment-token "$ENROLLMENT_TOKEN" \
  --runtime-display-name "$RUNTIME_DISPLAY_NAME" \
  --target-agent-name "$TARGET_AGENT_NAME" \
  --review-action "$REVIEW_ACTION" \
  --listen-port "$LISTEN_PORT" \
  --access-host "$ACCESS_HOST" \
  --log-jsonl "$LOG_PATH"
