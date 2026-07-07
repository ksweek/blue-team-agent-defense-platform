@echo off
setlocal EnableExtensions
set "SCRIPT_DIR=%~dp0"
call "%SCRIPT_DIR%connect_openclaw_to_platform.cmd" %*
exit /b %ERRORLEVEL%
