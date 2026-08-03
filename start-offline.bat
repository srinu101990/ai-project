@echo off
REM Start Aegis Intel offline on Windows
setlocal EnableExtensions
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 goto :no_python

if not exist backend\.venv goto :need_install

call backend\.venv\Scripts\activate.bat

python -c "import fastapi, uvicorn" >nul 2>&1
if errorlevel 1 goto :need_install

if not exist frontend\dist (
  echo ERROR: frontend\dist missing. Re-download the project ZIP.
  pause
  exit /b 1
)

echo.
echo Aegis Intel offline mode
echo Dashboard: http://127.0.0.1:8000
echo API docs:  http://127.0.0.1:8000/docs
echo Keep this window open.
echo.

cd backend
python run.py --host 127.0.0.1 --port 8000
goto :eof

:no_python
echo ERROR: Python not found. Install from python.org and enable PATH.
pause
exit /b 1

:need_install
echo Dependencies not installed yet.
echo Running backend\install-windows.bat ...
cd backend
call install-windows.bat
goto :eof
