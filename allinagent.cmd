@echo off
setlocal
set "ALLINAGENT_ROOT=%~dp0"
if "%ALLINAGENT_ROOT:~-1%"=="\" set "ALLINAGENT_ROOT=%ALLINAGENT_ROOT:~0,-1%"

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    python "%ALLINAGENT_ROOT%\scripts\allinagent_cli.py" %*
    exit /b %ERRORLEVEL%
)

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    py -3 "%ALLINAGENT_ROOT%\scripts\allinagent_cli.py" %*
    exit /b %ERRORLEVEL%
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ALLINAGENT_ROOT%\allinagent.ps1" %*
exit /b %ERRORLEVEL%
