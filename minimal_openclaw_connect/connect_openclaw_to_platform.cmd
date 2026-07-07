@echo off
setlocal EnableExtensions
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

set "SCRIPT_DIR=%~dp0"
set "PYTHON_SCRIPT=%SCRIPT_DIR%tools\openclaw_control_connect.py"
set "LOCAL_CONFIG=%SCRIPT_DIR%openclaw_connect_config.cmd"

echo ============================================================
echo OpenClaw protected connection launcher
echo ============================================================
echo.

if exist "%LOCAL_CONFIG%" (
    echo [INFO] Loading local config: "%LOCAL_CONFIG%"
    call "%LOCAL_CONFIG%"
)

if not exist "%PYTHON_SCRIPT%" (
    echo [ERROR] Missing file: "%PYTHON_SCRIPT%"
    set "EXIT_CODE=1"
    goto :finish
)

set "PYTHON_BIN="
set "PYTHON_FLAG="
where py >nul 2>nul
if not errorlevel 1 (
    py -3 --version >nul 2>nul
    if not errorlevel 1 (
        set "PYTHON_BIN=py"
        set "PYTHON_FLAG=-3"
    )
)
if not defined PYTHON_BIN (
    where python >nul 2>nul
    if not errorlevel 1 (
        python --version >nul 2>nul
        if not errorlevel 1 set "PYTHON_BIN=python"
    )
)
if not defined PYTHON_BIN (
    echo [ERROR] Python launcher or python executable was not found.
    echo [HINT] Install Python 3.10+ first, then run install_dependencies.cmd.
    set "EXIT_CODE=1"
    goto :finish
)

if not "%~1"=="" (
    echo [INFO] Forwarding custom arguments to the Python connector.
    "%PYTHON_BIN%" %PYTHON_FLAG% "%PYTHON_SCRIPT%" %*
    set "EXIT_CODE=%ERRORLEVEL%"
    goto :finish
)

if not defined PLATFORM_BASE_URL set "PLATFORM_BASE_URL=http://127.0.0.1:8000"
if not defined OPENCLAW_LISTEN_HOST set "OPENCLAW_LISTEN_HOST=0.0.0.0"
if not defined OPENCLAW_LISTEN_PORT set "OPENCLAW_LISTEN_PORT=19090"
if not defined OPENCLAW_ACCESS_HOST set "OPENCLAW_ACCESS_HOST=127.0.0.1"

echo [INFO] Press Enter to keep the value shown in brackets.
echo [INFO] Activation code is required only on first connection or when using --new.
echo.

set "PROMPT_VALUE="
set /p "PROMPT_VALUE=Platform base URL [%PLATFORM_BASE_URL%]: "
if defined PROMPT_VALUE set "PLATFORM_BASE_URL=%PROMPT_VALUE%"

set "PROMPT_VALUE="
if defined OPENCLAW_URL (
    set /p "PROMPT_VALUE=OpenClaw URL [%OPENCLAW_URL%]: "
) else (
    set /p "PROMPT_VALUE=OpenClaw URL: "
)
if defined PROMPT_VALUE set "OPENCLAW_URL=%PROMPT_VALUE%"

set "PROMPT_VALUE="
if defined OPENCLAW_GATEWAY_TOKEN (
    set /p "PROMPT_VALUE=OpenClaw gateway token [already set, press Enter to keep]: "
) else (
    set /p "PROMPT_VALUE=OpenClaw gateway token: "
)
if defined PROMPT_VALUE set "OPENCLAW_GATEWAY_TOKEN=%PROMPT_VALUE%"

set "HAS_LAST_CONFIG="
if exist "%SCRIPT_DIR%tools\agent_gateway\generated\openclaw-control-last.json" set "HAS_LAST_CONFIG=1"

set "PROMPT_VALUE="
if defined OPENCLAW_ACTIVATION_CODE (
    set /p "PROMPT_VALUE=Platform activation code [already set, press Enter to keep]: "
) else (
    if defined HAS_LAST_CONFIG (
        set /p "PROMPT_VALUE=Platform activation code [optional, Enter to reuse saved credentials]: "
    ) else (
        set /p "PROMPT_VALUE=Platform activation code: "
    )
)
if defined PROMPT_VALUE set "OPENCLAW_ACTIVATION_CODE=%PROMPT_VALUE%"

set "PROMPT_VALUE="
set /p "PROMPT_VALUE=Bridge listen host [%OPENCLAW_LISTEN_HOST%]: "
if defined PROMPT_VALUE set "OPENCLAW_LISTEN_HOST=%PROMPT_VALUE%"

set "PROMPT_VALUE="
set /p "PROMPT_VALUE=Bridge listen port [%OPENCLAW_LISTEN_PORT%]: "
if defined PROMPT_VALUE set "OPENCLAW_LISTEN_PORT=%PROMPT_VALUE%"

set "PROMPT_VALUE="
set /p "PROMPT_VALUE=Browser access host [%OPENCLAW_ACCESS_HOST%]: "
if defined PROMPT_VALUE set "OPENCLAW_ACCESS_HOST=%PROMPT_VALUE%"

if not defined PLATFORM_BASE_URL (
    echo [ERROR] Platform base URL is required.
    set "EXIT_CODE=1"
    goto :finish
)
if not defined OPENCLAW_URL (
    echo [ERROR] OpenClaw URL is required.
    set "EXIT_CODE=1"
    goto :finish
)
if not defined OPENCLAW_GATEWAY_TOKEN (
    echo [ERROR] OpenClaw gateway token is required.
    set "EXIT_CODE=1"
    goto :finish
)
if not defined OPENCLAW_ACTIVATION_CODE (
    if not defined HAS_LAST_CONFIG (
        echo [ERROR] Platform activation code is required for the first connection.
        set "EXIT_CODE=1"
        goto :finish
    )
)

echo.
echo [INFO] Starting protected OpenClaw bridge...
echo [INFO] Platform : %PLATFORM_BASE_URL%
echo [INFO] OpenClaw : %OPENCLAW_URL%
echo [INFO] Local UI : http://%OPENCLAW_ACCESS_HOST%:%OPENCLAW_LISTEN_PORT%
echo.

if defined OPENCLAW_ACTIVATION_CODE (
    "%PYTHON_BIN%" %PYTHON_FLAG% "%PYTHON_SCRIPT%" ^
      --platform-base-url "%PLATFORM_BASE_URL%" ^
      --upstream-http-url "%OPENCLAW_URL%" ^
      --gateway-token "%OPENCLAW_GATEWAY_TOKEN%" ^
      --activation-code "%OPENCLAW_ACTIVATION_CODE%" ^
      --listen-host "%OPENCLAW_LISTEN_HOST%" ^
      --listen-port "%OPENCLAW_LISTEN_PORT%" ^
      --access-host "%OPENCLAW_ACCESS_HOST%" ^
      --review-action block
) else (
    "%PYTHON_BIN%" %PYTHON_FLAG% "%PYTHON_SCRIPT%" ^
      --platform-base-url "%PLATFORM_BASE_URL%" ^
      --upstream-http-url "%OPENCLAW_URL%" ^
      --gateway-token "%OPENCLAW_GATEWAY_TOKEN%" ^
      --listen-host "%OPENCLAW_LISTEN_HOST%" ^
      --listen-port "%OPENCLAW_LISTEN_PORT%" ^
      --access-host "%OPENCLAW_ACCESS_HOST%" ^
      --review-action block
)
set "EXIT_CODE=%ERRORLEVEL%"

:finish
if not defined EXIT_CODE set "EXIT_CODE=%ERRORLEVEL%"
echo.
echo [INFO] Script finished with exit code %EXIT_CODE%.
if /I not "%CONNECT_SCRIPT_NO_PAUSE: =%"=="1" (
    echo [INFO] Press any key to close this window.
    pause >nul
)
exit /b %EXIT_CODE%
