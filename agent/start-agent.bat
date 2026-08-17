@echo off
REM Run this on the SECOND laptop. The dashboard must already be open on the main laptop.
setlocal EnableExtensions
cd /d "%~dp0"

echo.
echo ============================================================
echo  CYBER_SENTINEL.AI  —  second laptop agent
echo  Same Wi-Fi as the main laptop. Python 3 is required here.
echo  Do NOT type 127.0.0.1 — that is this laptop, not the dashboard.
echo  If ipconfig shows 192.168.137.1, turn OFF Mobile hotspot on this laptop
echo  and join the phone Wi-Fi instead. Both PCs need the same first 3 numbers.
echo ============================================================
echo.
:ask_url
set "SERVER="
set /p SERVER=Main laptop URL: 
if "%SERVER%"=="" (
  echo You must type the URL. Example: http://10.87.54.124:8000
  goto ask_url
)
echo %SERVER% | findstr /I "127.0.0.1 localhost" >nul
if not errorlevel 1 (
  echo 127.0.0.1 / localhost will not reach the other laptop. Try again.
  goto ask_url
)

echo.
set "PY="
py -3 -c "import sys; raise SystemExit(0 if sys.version_info>=(3,9) else 1)" 2>nul
if not errorlevel 1 set "PY=py -3"
if not defined PY (
  python -c "import sys; raise SystemExit(0 if sys.version_info>=(3,9) else 1)" 2>nul
  if not errorlevel 1 set "PY=python"
)
if not defined PY (
  echo ERROR: Python was not found on this laptop.
  echo Install Python 3.12 from python.org and tick Add python.exe to PATH.
  pause
  exit /b 1
)
echo Using: %PY%
echo Starting live watch against %SERVER%
echo Leave that new window OPEN. You should see "Starting CYBER_SENTINEL agent..."
echo Then use this menu to inject phishing / malware one by one.
echo.

start "CYBER_SENTINEL watch" cmd /k %PY% -u "%~dp0sentinel_agent.py" --server %SERVER%

:menu
echo.
echo  [1] Inject PHISHING mail from this laptop
echo  [2] Inject virus
echo  [3] Inject worm
echo  [4] Inject trojan
echo  [5] Inject ransomware
echo  [6] Inject spyware
echo  [7] Inject adware
echo  [8] Inject rootkit
echo  [9] Inject botnet
echo  [K] Inject keylogger
echo  [R] Inject RAT
echo  [D] Inject downloader
echo  [B] Inject backdoor
echo  [F] Inject fileless
echo  [M] Inject cryptominer
echo  [A] Inject ALL types one by one (8 seconds apart)
echo  [Q] Quit
echo.
set /p CHOICE=Choice: 
if /I "%CHOICE%"=="1" %PY% -u "%~dp0sentinel_agent.py" --server %SERVER% --inject phishing
if /I "%CHOICE%"=="2" %PY% -u "%~dp0sentinel_agent.py" --server %SERVER% --inject virus
if /I "%CHOICE%"=="3" %PY% -u "%~dp0sentinel_agent.py" --server %SERVER% --inject worm
if /I "%CHOICE%"=="4" %PY% -u "%~dp0sentinel_agent.py" --server %SERVER% --inject trojan
if /I "%CHOICE%"=="5" %PY% -u "%~dp0sentinel_agent.py" --server %SERVER% --inject ransomware
if /I "%CHOICE%"=="6" %PY% -u "%~dp0sentinel_agent.py" --server %SERVER% --inject spyware
if /I "%CHOICE%"=="7" %PY% -u "%~dp0sentinel_agent.py" --server %SERVER% --inject adware
if /I "%CHOICE%"=="8" %PY% -u "%~dp0sentinel_agent.py" --server %SERVER% --inject rootkit
if /I "%CHOICE%"=="9" %PY% -u "%~dp0sentinel_agent.py" --server %SERVER% --inject botnet
if /I "%CHOICE%"=="K" %PY% -u "%~dp0sentinel_agent.py" --server %SERVER% --inject keylogger
if /I "%CHOICE%"=="R" %PY% -u "%~dp0sentinel_agent.py" --server %SERVER% --inject rat
if /I "%CHOICE%"=="D" %PY% -u "%~dp0sentinel_agent.py" --server %SERVER% --inject downloader
if /I "%CHOICE%"=="B" %PY% -u "%~dp0sentinel_agent.py" --server %SERVER% --inject backdoor
if /I "%CHOICE%"=="F" %PY% -u "%~dp0sentinel_agent.py" --server %SERVER% --inject fileless
if /I "%CHOICE%"=="M" %PY% -u "%~dp0sentinel_agent.py" --server %SERVER% --inject cryptominer
if /I "%CHOICE%"=="A" %PY% -u "%~dp0sentinel_agent.py" --server %SERVER% --inject-all --delay 8
if /I "%CHOICE%"=="Q" goto :eof
goto menu
