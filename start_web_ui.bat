@echo off
echo ========================================
echo Finsecure Toolkit - Web UI Launcher
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Check if identity.txt exists
if not exist identity.txt (
    echo ERROR: identity.txt not found!
    echo Please create identity.txt before starting the web UI
    echo.
    pause
    exit /b 1
)

REM Check if consent.txt exists
if not exist consent.txt (
    echo ERROR: consent.txt not found!
    echo Please create consent.txt before starting the web UI
    echo.
    pause
    exit /b 1
)

echo Starting Finsecure Web UI...
echo.
echo Access the UI at: http://127.0.0.1:5000
echo Press Ctrl+C to stop the server
echo.
echo ========================================
echo.

python src/web_ui.py

pause

