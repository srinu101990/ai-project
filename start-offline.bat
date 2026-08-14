@echo off
REM Double-click this file. Keep the window open. Do not open Chrome first.
setlocal EnableExtensions
cd /d "%~dp0"

echo.
echo ============================================================
echo  CYBER_SENTINEL.AI
echo  Keep this black window OPEN the whole time.
echo  Log file: %CD%\start-offline.log
echo ============================================================
echo.

if not exist "%~dp0bootstrap.py" (
  echo ERROR: Extract the ZIP first.
  echo Then open the folder that contains start-offline.bat
  echo ^(not the zip file itself, and not only the inner empty window^).
  echo.
  pause
  exit /b 1
)

set "LAUNCHER="
py -3 -c "import sys; raise SystemExit(0 if sys.version_info>=(3,10) else 1)" 2>nul
if not errorlevel 1 set "LAUNCHER=py -3"

if not defined LAUNCHER (
  python -c "import sys; raise SystemExit(0 if sys.version_info>=(3,10) and 'WindowsApps' not in sys.executable else 1)" 2>nul
  if not errorlevel 1 set "LAUNCHER=python"
)

if not defined LAUNCHER (
  python3 -c "import sys; raise SystemExit(0 if sys.version_info>=(3,10) else 1)" 2>nul
  if not errorlevel 1 set "LAUNCHER=python3"
)

if not defined LAUNCHER goto :no_python

echo Using: %LAUNCHER%
echo First run may take a few minutes while packages install.
echo Chrome will open by itself AFTER the server is ready.
echo Second laptop: same Wi-Fi, then run agent\start-agent.bat
echo If Windows Firewall pops up, click Allow access.
echo.
%LAUNCHER% "%~dp0bootstrap.py"
echo.
echo If Chrome did not open, read start-offline.log in this folder
echo and open the URL printed above.
echo.
pause
goto :eof

:no_python
echo.
echo PYTHON WAS NOT FOUND ^(or only the Microsoft Store fake python^).
echo.
echo 1. Download Python 3.12: https://www.python.org/downloads/
echo 2. Tick BOTH:
echo      Add python.exe to PATH
echo      py launcher
echo 3. Close this window, extract the zip again if needed,
echo    then double-click start-offline.bat
echo 4. Do NOT type 127.0.0.1 in Chrome until this window stays open
echo    and says READY.
echo.
start https://www.python.org/downloads/
pause
exit /b 1
