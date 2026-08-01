@echo off
REM Start Aegis Intel fully offline (API + built dashboard on one port).
setlocal
cd /d "%~dp0"

if not exist backend\.venv (
  echo Creating Python virtual environment...
  python -m venv backend\.venv
)

call backend\.venv\Scripts\activate.bat

python -c "import fastapi" >nul 2>&1
if errorlevel 1 (
  echo Installing Python dependencies (needs internet the first time only)...
  pip install -r backend\requirements.txt
)

if not exist frontend\dist (
  if not exist frontend\node_modules (
    echo Installing frontend dependencies (needs internet the first time only)...
    pushd frontend
    call npm install
    popd
  )
  echo Building frontend for offline use...
  pushd frontend
  call npm run build
  popd
)

echo.
echo Aegis Intel offline mode
echo   Dashboard : http://127.0.0.1:8000
echo   API docs  : http://127.0.0.1:8000/docs
echo   No internet required while running.
echo.

cd backend
python run.py --host 127.0.0.1 --port 8000
