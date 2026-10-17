@echo off
echo ========================================
echo The Red Room - Quick Install
echo ========================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found!
    echo Please install Python 3.10+ from https://www.python.org/
    pause
    exit /b 1
)

echo [1/3] Installing Python dependencies...
pip install -e .

if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo [2/3] Checking Docker...
docker --version >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Docker not found!
    echo Docker is required for the fullscan command.
    echo Download from: https://www.docker.com/products/docker-desktop
    echo.
    echo You can still run: python -m redroom.cli version
) else (
    echo Docker found!
)

echo.
echo [3/3] Verifying installation...
python -m redroom.cli version

echo.
echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo Quick Start:
echo   Scan demo app:
echo      python -m redroom.cli fullscan src/demo/fintech_app
echo      (or: run.bat fullscan src/demo/fintech_app)
echo.
echo   Show version:
echo      python -m redroom.cli version
echo      (or: run.bat version)
echo.
pause
