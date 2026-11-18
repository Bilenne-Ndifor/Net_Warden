@echo off
rem Update NetWarden from GitHub.
rem  - In a git clone: pulls the latest code, then offers to (re)install it.
rem  - The installed copy updates itself: NetWarden > Pro > Settings > Updates.
cd /d "%~dp0"
if not exist ".git" (
    echo This folder is not a git clone. Open NetWarden and use Settings ^> Updates,
    echo or download the latest version from https://github.com/Bilenne-Ndifor/Net_Warden
    pause
    exit /b 1
)
where git >nul 2>&1
if errorlevel 1 (
    if exist "C:\Program Files\Git\cmd\git.exe" (set "GIT=C:\Program Files\Git\cmd\git.exe") else (
        echo Git is not installed. Install it with:  winget install Git.Git
        pause
        exit /b 1
    )
) else (set "GIT=git")
"%GIT%" pull --ff-only
if errorlevel 1 (
    echo.
    echo Could not update automatically ^(local changes?^). Nothing was changed.
    pause
    exit /b 1
)
echo.
choice /m "Install this version on this PC now"
if errorlevel 2 exit /b 0
call "%~dp0Install NetWarden.bat"
