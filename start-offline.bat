@echo off
REM Start CYBER_SENTINEL.AI on Windows (live network detection by default)
setlocal EnableExtensions
cd /d "%~dp0"

if "%COLLECTION_MODE%"=="" set COLLECTION_MODE=network
if "%BIND_HOST%"=="" set BIND_HOST=0.0.0.0
if "%BIND_PORT%"=="" set BIND_PORT=8000

where python >nul 2>&1
if errorlevel 1 goto :no_python

if not exist backend\.venv goto :need_install

call backend\.venv\Scripts\activate.bat

python -c "import fastapi, uvicorn, psutil" >nul 2>&1
if errorlevel 1 goto :need_install

if not exist frontend\dist (
  echo ERROR: frontend\dist missing. Build with: cd frontend ^&^& npm install ^&^& npm run build
  pause
  exit /b 1
)

echo.
echo CYBER_SENTINEL.AI — %COLLECTION_MODE% detection mode
echo Dashboard (this PC): http://127.0.0.1:%BIND_PORT%
echo Dashboard (LAN):     http://^<your-lan-ip^>:%BIND_PORT%
echo API docs:            http://127.0.0.1:%BIND_PORT%/docs
echo Keep this window open. Press Ctrl+C to stop.
echo.

cd backend
python run.py --host %BIND_HOST% --port %BIND_PORT%
goto :eof

:no_python
echo ERROR: Python not found. Install from python.org and enable PATH.
pause
exit /b 1

:need_install
echo Dependencies not installed yet.
if exist backend\install-windows.bat (
  echo Running backend\install-windows.bat ...
  cd backend
  call install-windows.bat
) else (
  echo Creating venv and installing requirements...
  python -m venv backend\.venv
  call backend\.venv\Scripts\activate.bat
  python -m pip install --upgrade pip
  python -m pip install -r backend\requirements.txt
  echo Install complete. Run start-offline.bat again.
  pause
)
goto :eof
