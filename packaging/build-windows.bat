@echo off
setlocal EnableDelayedExpansion
title DataSentry — Windows Build

REM ============================================================
REM  DataSentry Windows Builder
REM  Run this on any Windows machine with Python 3.9+ installed.
REM  Produces:  dist\DataSentry.exe  (~50 MB, no Python needed)
REM ============================================================

echo.
echo  ==========================================
echo   DataSentry -- Windows EXE Builder
echo  ==========================================
echo.

REM ---- Check Python is available ---------------------------------
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Download from https://python.org
    echo         Make sure "Add Python to PATH" is ticked during install.
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo [OK] %PYVER% found

REM ---- Move to the scanner folder --------------------------------
set SCRIPT_DIR=%~dp0
set SCANNER=%SCRIPT_DIR%..\scanner\scanner.py

if not exist "%SCANNER%" (
    echo [ERROR] Cannot find scanner.py at %SCANNER%
    echo         Run this batch file from the packaging\ folder.
    pause
    exit /b 1
)

REM ---- Install/upgrade pip dependencies --------------------------
echo.
echo [1/3] Installing Python dependencies...
python -m pip install --upgrade pip --quiet
python -m pip install -r "%SCRIPT_DIR%..\scanner\requirements.txt" --quiet
if errorlevel 1 (
    echo [ERROR] pip install failed. Check your internet connection.
    pause
    exit /b 1
)
echo [OK] Dependencies installed

REM ---- Install PyInstaller ---------------------------------------
echo.
echo [2/3] Installing PyInstaller...
python -m pip install pyinstaller --quiet
if errorlevel 1 (
    echo [ERROR] Could not install PyInstaller.
    pause
    exit /b 1
)
echo [OK] PyInstaller ready

REM ---- Build the EXE ---------------------------------------------
echo.
echo [3/3] Building DataSentry.exe (this takes ~60 seconds)...
cd /d "%SCRIPT_DIR%.."
python -m PyInstaller ^
    --onefile ^
    --windowed ^
    --name DataSentry ^
    --hidden-import=pdfminer ^
    --hidden-import=pdfminer.high_level ^
    --hidden-import=pdfminer.layout ^
    --hidden-import=docx ^
    --hidden-import=openpyxl ^
    scanner\scanner.py

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed. Check the output above for details.
    pause
    exit /b 1
)

echo.
echo  ==========================================
echo   Build complete!
echo   Output: dist\DataSentry.exe
echo  ==========================================
echo.
echo  Next steps:
echo   1. Test it: dist\DataSentry.exe --cli --verbose
echo   2. Deploy via Group Policy, Intune or Jamf
echo      (see packaging\BUILD.md for instructions)
echo.
pause
