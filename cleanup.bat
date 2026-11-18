@echo off
rem Emergency undo: turns block-all mode off, restores Windows Firewall's normal settings and
rem removes every NetWarden rule and speed limit. Works even if NetWarden won't start. No Python needed.
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
echo Stopping NetWarden and removing its firewall changes...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0cleanup.ps1"
echo.
pause
