@echo off
rem Creates the private Python environment (.venv) and installs NetWarden's dependencies.
rem Called by run.bat / demo.bat; safe to run again at any time.
setlocal EnableExtensions
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" goto :deps

set "PY="
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1 && set "PY=py -3"
if not defined PY (
    python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo.
    echo  Python 3.10 or newer is required and was not found.
    echo  Install it with:   winget install Python.Python.3.12
    echo  or download it from https://www.python.org/downloads/  ^(tick "Add python.exe to PATH"^)
    echo  then run this again.
    echo.
    exit /b 1
)
echo First run: creating NetWarden's Python environment...
%PY% -m venv .venv || exit /b 1

:deps
".venv\Scripts\python.exe" -c "import psutil, pydivert, pystray, PIL" >nul 2>&1
if not errorlevel 1 exit /b 0
echo Installing dependencies (psutil, pydivert, pystray, pillow)...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt || exit /b 1
exit /b 0
