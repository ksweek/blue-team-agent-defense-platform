@echo off
setlocal EnableExtensions
chcp 65001
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "SCRIPT_DIR=%~dp0"
set "PYTHON_SCRIPT=%SCRIPT_DIR%tools\openclaw_control_connect.py"

echo [INFO] Working directory: "%SCRIPT_DIR%"
echo [INFO] OpenClaw control connect script: "%PYTHON_SCRIPT%"
echo [INFO] This launcher activates Runtime credentials and starts the OpenClaw security bridge.

if not exist "%PYTHON_SCRIPT%" (
    echo [ERROR] Missing file: "%PYTHON_SCRIPT%"
    set "EXIT_CODE=1"
    goto :finish
)

set "PYTHON_BIN="
set "PYTHON_FLAG="
if defined VIRTUAL_ENV (
    if exist "%VIRTUAL_ENV%\Scripts\python.exe" (
        set "PYTHON_BIN=%VIRTUAL_ENV%\Scripts\python.exe"
    )
)
if not defined PYTHON_BIN (
    if exist "%SCRIPT_DIR%\.venv\Scripts\python.exe" (
        set "PYTHON_BIN=%SCRIPT_DIR%\.venv\Scripts\python.exe"
    )
)
if not defined PYTHON_BIN (
    where py
    if not errorlevel 1 (
        set "PYTHON_BIN=py"
        set "PYTHON_FLAG=-3"
    )
)
if not defined PYTHON_BIN (
    where python
    if not errorlevel 1 set "PYTHON_BIN=python"
)
if not defined PYTHON_BIN (
    echo [ERROR] Python launcher or python executable was not found.
    set "EXIT_CODE=1"
    goto :finish
)

echo [INFO] Using Python: %PYTHON_BIN% %PYTHON_FLAG%
if "%~1"=="" (
    echo [INFO] Launching interactive OpenClaw protected connection flow...
    "%PYTHON_BIN%" %PYTHON_FLAG% "%PYTHON_SCRIPT%"
) else (
    echo [INFO] Forwarding custom arguments to OpenClaw protected connection flow...
    "%PYTHON_BIN%" %PYTHON_FLAG% "%PYTHON_SCRIPT%" %*
)
set "EXIT_CODE=%ERRORLEVEL%"

:finish
if not defined EXIT_CODE set "EXIT_CODE=%ERRORLEVEL%"
echo [INFO] Script finished with exit code %EXIT_CODE%.
if not defined CONNECT_SCRIPT_CHILD (
    if /I not "%CONNECT_SCRIPT_NO_PAUSE: =%"=="1" (
        echo [INFO] Press any key to close this window.
        pause
    )
)
exit /b %EXIT_CODE%
