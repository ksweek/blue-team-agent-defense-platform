@echo off
setlocal EnableExtensions
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "SCRIPT_DIR=%~dp0"
set "TARGET_SCRIPT=%SCRIPT_DIR%connect_openclaw_control.cmd"
set "LOG_DIR=%SCRIPT_DIR%run_logs"
set "LOG_PATH=%LOG_DIR%\openclaw-control-frames.jsonl"
set "PLATFORM_BASE_URL=http://127.0.0.1:8000"
set "UPSTREAM_HTTP_URL=http://OPENCLAW_HOST:18789"
set "GATEWAY_TOKEN=REPLACE_WITH_OPENCLAW_GATEWAY_TOKEN"
set "ENROLLMENT_TOKEN=REPLACE_WITH_RUNTIME_ENROLLMENT_TOKEN"
set "RUNTIME_DISPLAY_NAME=openclaw-control-OPENCLAW_HOST-18789"
set "TARGET_AGENT_NAME=OpenClaw-Control-OPENCLAW_HOST"
set "REVIEW_ACTION=block"
set "LISTEN_PORT=19090"
set "ACCESS_HOST=127.0.0.1"

if not exist "%TARGET_SCRIPT%" (
    echo [ERROR] Missing file: "%TARGET_SCRIPT%"
    exit /b 1
)

if not exist "%LOG_DIR%" mkdir "%LOG_DIR%" >nul 2>nul

if "%UPSTREAM_HTTP_URL%"=="http://OPENCLAW_HOST:18789" (
    echo [ERROR] 请先编辑脚本，填入真实的 OpenClaw 地址。
    exit /b 1
)

if "%GATEWAY_TOKEN%"=="REPLACE_WITH_OPENCLAW_GATEWAY_TOKEN" (
    echo [ERROR] 请先编辑脚本，填入真实的 OpenClaw gateway token。
    exit /b 1
)

if "%ENROLLMENT_TOKEN%"=="REPLACE_WITH_RUNTIME_ENROLLMENT_TOKEN" (
    echo [ERROR] 请先编辑脚本，填入平台生成的一次性 Runtime 注册码。
    exit /b 1
)

echo [INFO] Starting OpenClaw remote bridge...
echo [INFO] Platform: %PLATFORM_BASE_URL%
echo [INFO] Upstream: %UPSTREAM_HTTP_URL%
echo [INFO] Local browser entry: http://%ACCESS_HOST%:%LISTEN_PORT%

call "%TARGET_SCRIPT%" --upstream-http-url "%UPSTREAM_HTTP_URL%" --gateway-token "%GATEWAY_TOKEN%" --platform-base-url "%PLATFORM_BASE_URL%" --enrollment-token "%ENROLLMENT_TOKEN%" --runtime-display-name "%RUNTIME_DISPLAY_NAME%" --target-agent-name "%TARGET_AGENT_NAME%" --review-action "%REVIEW_ACTION%" --listen-port "%LISTEN_PORT%" --access-host "%ACCESS_HOST%" --log-jsonl "%LOG_PATH%"

exit /b %ERRORLEVEL%
