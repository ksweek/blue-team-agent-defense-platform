@echo off
setlocal EnableExtensions
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "SCRIPT_DIR=%~dp0"
set "PYTHON_SCRIPT=%SCRIPT_DIR%tools\openclaw_control_bridge.py"
if not exist "%PYTHON_SCRIPT%" exit /b 1
set "PYTHON_BIN="
set "PYTHON_FLAG="
where py >nul 2>nul
if not errorlevel 1 (
    set "PYTHON_BIN=py"
    set "PYTHON_FLAG=-3"
)
if not defined PYTHON_BIN (
    where python >nul 2>nul
    if not errorlevel 1 set "PYTHON_BIN=python"
)
if not defined PYTHON_BIN exit /b 1
if "%~1"=="" (
    "%PYTHON_BIN%" %PYTHON_FLAG% "%PYTHON_SCRIPT%" --help
) else (
    "%PYTHON_BIN%" %PYTHON_FLAG% "%PYTHON_SCRIPT%" %*
)
exit /b %ERRORLEVEL%
