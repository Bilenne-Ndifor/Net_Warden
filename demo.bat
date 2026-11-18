@echo off
rem Demo mode: simulated apps and traffic, no Administrator rights, nothing on your PC is changed.
setlocal EnableExtensions
cd /d "%~dp0"
title NetWarden (demo)
call "%~dp0setup.bat" || goto :fail
".venv\Scripts\python.exe" -m netwarden --sim
if errorlevel 1 goto :fail
exit /b 0
:fail
echo.
pause
exit /b 1
