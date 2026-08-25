@echo off
setlocal EnableDelayedExpansion
title DataSentry — Silent Deploy

REM ============================================================
REM  DataSentry Silent Deployment Script
REM
REM  Edit the three CONFIG lines below, then deploy this .bat
REM  alongside DataSentry.exe via Group Policy, Intune, or Jamf.
REM
REM  The scanner runs silently in the background, submits its
REM  report to your backend, then exits.  No user interaction.
REM ============================================================

REM ---- CONFIG (edit these before deploying) --------------------
set API_URL=https://YOUR-BACKEND-URL/api
set API_KEY=YOUR-API-KEY-HERE
set CUSTOMER_ID=acme-corp
set CUSTOMER_NAME=Acme Corporation
REM --------------------------------------------------------------

REM Resolve the folder this .bat lives in (works from GP/Intune)
set DEPLOY_DIR=%~dp0

REM Look for the exe next to this bat file, then in dist\ subfolder
if exist "%DEPLOY_DIR%DataSentry.exe" (
    set EXE=%DEPLOY_DIR%DataSentry.exe
) else if exist "%DEPLOY_DIR%dist\DataSentry.exe" (
    set EXE=%DEPLOY_DIR%dist\DataSentry.exe
) else (
    echo [ERROR] DataSentry.exe not found next to this script.
    exit /b 1
)

REM Run the scan in CLI mode (no GUI window, exits when done)
"%EXE%" ^
    --cli ^
    --api-url "%API_URL%" ^
    --api-key "%API_KEY%" ^
    --customer-id "%CUSTOMER_ID%" ^
    --customer-name "%CUSTOMER_NAME%"

exit /b %errorlevel%
