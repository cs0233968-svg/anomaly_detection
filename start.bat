@echo off
title Sentinel - AI Network Anomaly Detection
color 0a

echo.
echo  ============================================
echo   SENTINEL - AI Anomaly Detection System
echo  ============================================
echo.

:: Check if running as admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo  [ERROR] Please run this file as Administrator!
    echo.
    echo  Right click start.bat and select
    echo  "Run as Administrator"
    echo.
    pause
    exit
)

echo  [OK] Running as Administrator
echo.

:: Navigate to project folder
cd /d C:\Users\chand\OneDrive\Desktop\anomaly_detection

:: Clear old data
if exist live_results.csv del live_results.csv
if exist login_logs.csv del login_logs.csv
echo  [OK] Old data cleared

:: Start Login Monitor in background
echo  [OK] Starting Login Monitor...
start "Login Monitor" /min python login_monitor.py

:: Wait 2 seconds
timeout /t 2 /nobreak >nul

:: Start Flask Dashboard
echo  [OK] Starting Dashboard...
start "Sentinel Dashboard" /min python app.py

:: Wait 3 seconds for Flask to start
timeout /t 3 /nobreak >nul

:: Open browser automatically
echo  [OK] Opening Dashboard in browser...
start http://localhost:8080

echo.
echo  ============================================
echo   Sentinel is running!
echo   Dashboard: http://localhost:8080
echo  ============================================
echo.
echo  Press any key to STOP everything...
pause >nul

:: Stop all processes when key is pressed
echo.
echo  Stopping Sentinel...
taskkill /f /fi "WINDOWTITLE eq Login Monitor*" >nul 2>&1
taskkill /f /fi "WINDOWTITLE eq Sentinel Dashboard*" >nul 2>&1
taskkill /f /im python.exe >nul 2>&1

echo  [OK] Sentinel stopped!
echo.
pause
