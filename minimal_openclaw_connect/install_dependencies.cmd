@echo off
setlocal EnableExtensions
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "SCRIPT_DIR=%~dp0"
set "REQUIREMENTS=%SCRIPT_DIR%requirements.txt"

echo ============================================================
echo Install OpenClaw connector dependencies
echo ============================================================
echo.

if not exist "%REQUIREMENTS%" (
    echo [ERROR] Missing file: "%REQUIREMENTS%"
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
    set "EXIT_CODE=1"
    goto :finish
)

echo [INFO] Using Python: %PYTHON_BIN% %PYTHON_FLAG%
"%PYTHON_BIN%" %PYTHON_FLAG% -m pip install --upgrade pip
if errorlevel 1 (
    set "EXIT_CODE=%ERRORLEVEL%"
    goto :finish
)

"%PYTHON_BIN%" %PYTHON_FLAG% -m pip install -r "%REQUIREMENTS%"
set "EXIT_CODE=%ERRORLEVEL%"

:finish
if not defined EXIT_CODE set "EXIT_CODE=%ERRORLEVEL%"
echo.
echo [INFO] Dependency install finished with exit code %EXIT_CODE%.
if /I not "%CONNECT_SCRIPT_NO_PAUSE: =%"=="1" (
    echo [INFO] Press any key to close this window.
    pause >nul
)
exit /b %EXIT_CODE%
