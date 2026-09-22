@echo off
title CryptoFlow-IDS - Environment Installer
echo ======================================================================
echo           CryptoFlow-IDS Desktop App Setup and Dependency Installer
echo ======================================================================
echo.

:: Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH!
    echo Please install Python 3.8+ from https://www.python.org/
    pause
    exit /b 1
)

echo [*] Upgrading pip...
python -m pip install --upgrade pip

echo [*] Installing required Python dependencies...
python -m pip install -r requirements.txt

echo.
echo ======================================================================
echo [*] Checking for Npcap packet capture driver on Windows...
if exist "%SystemRoot%\System32\Npcap" (
    echo [OK] Npcap directory found.
) else (
    echo [NOTICE] Npcap does not appear to be installed.
    echo Please download and install Npcap from: https://npcap.com/#download
    echo IMPORTANT during Npcap installation:
    echo   1. Check "Support loopback traffic (Npcap Loopback Adapter)"
    echo   2. Check "Install Npcap in WinPcap API-compatible Mode"
)
echo ======================================================================
echo.
echo Setup complete! You can now start the application by running:
echo   run_app.bat
echo.
pause
