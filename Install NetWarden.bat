@echo off
rem Installs NetWarden to Program Files and makes it start in the background at sign-in.
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
    echo Asking Windows for Administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
title NetWarden setup
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\install.ps1"
