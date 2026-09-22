@echo off
title CryptoFlow-IDS Desktop Launcher
:: Check for administrative privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ======================================================================
    echo  Requesting Administrator Privileges...
    echo  (Required for Windows Defender Firewall mitigation & packet sniffing)
    echo ======================================================================
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d \"%~dp0\" && python main.py' -Verb RunAs"
    exit /b
)

:: Already running as Administrator
cd /d "%~dp0"
python main.py
if %errorlevel% neq 0 (
    echo.
    echo Application exited with error. Press any key to close.
    pause
)
