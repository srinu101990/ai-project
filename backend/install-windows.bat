@echo off
REM Clean Windows install + start for Aegis Intel
setlocal EnableExtensions
cd /d "%~dp0"

echo.
echo === Aegis Intel Windows Install ===
echo.

where python >nul 2>&1
if errorlevel 1 goto :no_python

if exist .venv (
  echo Removing old virtual environment...
  rmdir /s /q .venv
)

echo Creating virtual environment...
python -m venv .venv
if errorlevel 1 goto :venv_fail

call .venv\Scripts\activate.bat
if errorlevel 1 goto :venv_fail

echo Upgrading pip...
python -m pip install --upgrade pip

echo Installing dependencies...
python -m pip install -r requirements.txt
if errorlevel 1 goto :pip_fail

echo Verifying install...
python -c "import fastapi, uvicorn, sklearn, reportlab"
if errorlevel 1 goto :verify_fail

echo.
echo Install OK. Starting server...
echo Open Chrome: http://127.0.0.1:8000
echo Keep this window open.
echo.
python run.py --host 127.0.0.1 --port 8000
goto :eof

:no_python
echo ERROR: Python not found.
echo Install Python 3.11 or 3.12 from https://www.python.org/downloads/
echo Enable "Add python.exe to PATH" during install.
pause
exit /b 1

:venv_fail
echo ERROR: Could not create or activate .venv
pause
exit /b 1

:pip_fail
echo ERROR: pip install failed.
echo Recommended: Python 3.10, 3.11, or 3.12 64-bit from python.org
echo Check version with: python --version
pause
exit /b 1

:verify_fail
echo ERROR: package verification failed.
pause
exit /b 1
