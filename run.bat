@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title NetWarden

rem ---- NetWarden needs Administrator rights to change Windows Firewall / QoS and to capture packets.
net session >nul 2>&1
if errorlevel 1 (
    echo Asking Windows for Administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

call "%~dp0setup.bat" || goto :fail

".venv\Scripts\python.exe" -m netwarden
if errorlevel 1 goto :fail
exit /b 0

:fail
echo.
echo NetWarden stopped with an error (see above).
pause
exit /b 1
