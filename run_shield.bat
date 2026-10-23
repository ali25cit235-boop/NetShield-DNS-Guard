@echo off
title NetShield - Dynamic DNS-Leak Guard & Proxy Enforcer (Admin Launcher)
cd /d "%~dp0"

:: ============================================================================
:: Verify Administrator privileges; automatically request UAC elevation if not
:: ============================================================================
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [INFO] Requesting Administrator privileges for NetShield...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
    exit /b
)

echo ============================================================================
echo   NETSHIELD - DYNAMIC DNS-LEAK GUARD ^& PROXY ENFORCER (ADMIN)
echo ============================================================================
echo [OK] Administrator privileges confirmed.
echo [INFO] Launching NetShield GUI...

where pythonw >nul 2>&1
if %errorLevel% equ 0 (
    start "" pythonw "%~dp0main.py"
) else (
    python "%~dp0main.py"
)
exit /b 0
