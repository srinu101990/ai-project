@echo off
REM Clean Windows install for Aegis Intel backend
setlocal
cd /d "%~dp0"

echo.
echo === Aegis Intel Windows Install ===
echo.

where python >nul 2>&1
if errorlevel 1 (
  echo ERROR: Python not found. Install from https://www.python.org/downloads/
  echo Enable "Add python.exe to PATH" during install.
  pause
  exit /b 1
)

if exist .venv (
  echo Removing old virtual environment...
  rmdir /s /q .venv
)

echo Creating virtual environment...
python -m venv .venv
if errorlevel 1 (
  echo ERROR: Could not create .venv
  pause
  exit /b 1
)

call .venv\Scripts\activate.bat

echo Upgrading pip...
python -m pip install --upgrade pip

echo Installing dependencies (Windows-safe packages only)...
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo.
  echo ERROR: pip install failed.
  echo Tip: use Python 3.11 or 3.12 from python.org (64-bit).
  pause
  exit /b 1
)

python -c "import fastapi, uvicorn, sklearn, reportlab; print('Install OK')"
if errorlevel 1 (
  echo ERROR: verification failed
  pause
  exit /b 1
)

echo.
echo Success. Starting server...
echo Dashboard: http://127.0.0.1:8000
echo.
python run.py --host 127.0.0.1 --port 8000
pause
