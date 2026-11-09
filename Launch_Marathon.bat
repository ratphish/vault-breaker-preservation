@echo off
title Marathon Standalone Launcher (Project Dawn Emulation)
cd /d "%~dp0"

echo =================================================================
echo   MARATHON STANDALONE OFFLINE LAUNCHER
echo   Build: 26136895 (Cryo Archive Vault Breaker)
echo =================================================================
echo.

:: Check Python availability
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not found in PATH! Please ensure Python 3.11+ is installed.
    pause
    exit /b 1
)

:: Check if server is already running on port 8080
netstat -ano | findstr ":8080" >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Marathon Server is already ACTIVE and listening on port 8080.
) else (
    echo [*] Starting local Marathon Server in a dedicated visible console...
    start "Marathon Emulation Server" cmd /k "title Marathon Emulation Server && python -u D:\vault-breaker-preservation\scripts\marathon_server.py"
    :: Give server a moment to bind ports
    ping 127.0.0.1 -n 4 >nul
)

echo [*] Launching Marathon.exe...
start "" "%~dp0Marathon.exe"
echo [+] Marathon launched! You can monitor marathon_proxy.log for telemetry.
echo.
