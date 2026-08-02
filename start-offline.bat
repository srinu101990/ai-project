@echo off
REM Start Aegis Intel fully offline (API + built dashboard on one port).
setlocal EnableExtensions
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
  echo Python was not found. Install Python 3.10+ from https://www.python.org/downloads/
  echo During setup, enable "Add python.exe to PATH".
  pause
  exit /b 1
)

if not exist backend\.venv (
  echo Creating Python virtual environment...
  python -m venv backend\.venv
  if errorlevel 1 (
    echo Failed to create virtual environment.
    pause
    exit /b 1
  )
)

call backend\.venv\Scripts\activate.bat

python -c "import fastapi, uvicorn" >nul 2>&1
if errorlevel 1 (
  echo Installing Python dependencies (needs internet the first time only)...
  python -m pip install --upgrade pip
  python -m pip install -r backend\requirements.txt
  if errorlevel 1 (
    echo.
    echo Dependency install failed.
    echo Tip: delete the backend\.venv folder and run this script again.
    pause
    exit /b 1
  )
)

if not exist frontend\dist (
  where npm >nul 2>&1
  if errorlevel 1 (
    echo frontend\dist is missing and Node.js/npm was not found.
    echo Install Node.js from https://nodejs.org/ or re-download the project ZIP that includes frontend\dist.
    pause
    exit /b 1
  )
  if not exist frontend\node_modules (
    echo Installing frontend dependencies (needs internet the first time only)...
    pushd frontend
    call npm install
    if errorlevel 1 (
      popd
      echo npm install failed.
      pause
      exit /b 1
    )
    popd
  )
  echo Building frontend for offline use...
  pushd frontend
  call npm run build
  if errorlevel 1 (
    popd
    echo Frontend build failed.
    pause
    exit /b 1
  )
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
if errorlevel 1 (
  echo Server exited with an error.
  pause
  exit /b 1
)
