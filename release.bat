@echo off
rem Publish a new NetWarden version to GitHub (see release.ps1).
cd /d "%~dp0"
set /p NWVER=New version number (e.g. 2.2.0):
set /p NWMSG=What changed (one line, optional):
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0release.ps1" "%NWVER%" "%NWMSG%"
pause
