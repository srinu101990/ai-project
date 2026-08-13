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

goto :start_server

:need_install
echo.
echo First run: installing Python packages. Keep this window open.
echo This needs internet once. After install the dashboard will start.
echo.
if not exist backend\.venv (
  python -m venv backend\.venv
  if errorlevel 1 goto :venv_fail
)
call backend\.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r backend\requirements.txt
if errorlevel 1 goto :pip_fail
python -c "import fastapi, uvicorn, psutil" >nul 2>&1
if errorlevel 1 goto :pip_fail
echo Install complete. Starting dashboard...
goto :start_server

:start_server
echo.
echo ============================================================
echo  CYBER_SENTINEL.AI is starting
echo  Leave THIS black window open. Closing it stops the app.
echo  Then Chrome should open: http://127.0.0.1:%BIND_PORT%
echo  If it does not, open that address yourself.
echo ============================================================
echo.

REM Open the browser a few seconds after the server begins binding.
start "" cmd /c "timeout /t 4 /nobreak >nul && start http://127.0.0.1:%BIND_PORT%"

cd backend
python run.py --host %BIND_HOST% --port %BIND_PORT%
echo.
echo Server stopped. If Chrome said "refused to connect", this window
echo closed too early or Python failed above. Scroll up for the error.
pause
goto :eof

:no_python
echo.
echo ERROR: Python was not found.
echo 1. Install Python 3.11 or 3.12 from https://www.python.org/downloads/
echo 2. Enable "Add python.exe to PATH" in the installer
echo 3. Close this window, open a NEW one, run start-offline.bat again
echo Do not open http://127.0.0.1:8000 until this window stays running.
echo.
pause
exit /b 1

:venv_fail
echo ERROR: Could not create backend\.venv
pause
exit /b 1

:pip_fail
echo ERROR: pip install failed. Use Python 3.11/3.12 64-bit from python.org
echo and keep internet on for the first install.
pause
exit /b 1
