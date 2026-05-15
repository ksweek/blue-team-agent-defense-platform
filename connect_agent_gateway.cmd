@echo off
setlocal EnableExtensions
chcp 65001
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "SCRIPT_DIR=%~dp0"
set "PYTHON_SCRIPT=%SCRIPT_DIR%tools\agent_gateway\connect_entry.py"

echo [INFO] Working directory: "%SCRIPT_DIR%"
echo [INFO] Gateway entry script: "%PYTHON_SCRIPT%"

if not exist "%PYTHON_SCRIPT%" (
    echo [ERROR] Missing file: "%PYTHON_SCRIPT%"
    set "EXIT_CODE=1"
    goto :finish
)

set "PYTHON_BIN="
set "PYTHON_FLAG="
where py
if not errorlevel 1 (
    set "PYTHON_BIN=py"
    set "PYTHON_FLAG=-3"
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
    echo [INFO] Launching interactive gateway connection flow...
    "%PYTHON_BIN%" %PYTHON_FLAG% "%PYTHON_SCRIPT%"
) else (
    echo [INFO] Forwarding custom arguments to gateway connection flow...
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
