@echo off
REM Quick setup script for fraud detection pipeline (Windows)

echo ======================================
echo Fraud Detection Pipeline - Quick Setup
echo ======================================

REM Check Python version
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python not found. Please install Python 3.8+
    exit /b 1
)

python --version
echo.

REM Create virtual environment
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
) else (
    echo Virtual environment already exists
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
pip install -q -r requirements.txt

REM Verify data directory
if not exist "data\traffic.jsonl" (
    echo Error: data\traffic.jsonl not found
    exit /b 1
)
echo Traffic log found

REM Show usage
echo.
echo ======================================
echo Setup Complete!
echo ======================================
echo.
echo To run the pipeline:
echo   python main.py data\traffic.jsonl data\decisions.jsonl
echo.
