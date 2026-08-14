@echo off
REM Run this on the SECOND laptop. The dashboard must already be open on the main laptop.
setlocal EnableExtensions
cd /d "%~dp0"

echo.
echo ============================================================
echo  CYBER_SENTINEL.AI  —  second laptop agent
echo  Same Wi-Fi as the main laptop. Python 3 is required here.
echo ============================================================
echo.
set /p SERVER=Main laptop URL (example http://192.168.1.24:8000): 
if "%SERVER%"=="" set "SERVER=http://127.0.0.1:8000"

echo.
echo Starting live watch. Leave that new window OPEN.
echo Then use this menu to inject phishing / malware one by one.
echo.

start "CYBER_SENTINEL watch" cmd /k python "%~dp0sentinel_agent.py" --server %SERVER%

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
if /I "%CHOICE%"=="1" python "%~dp0sentinel_agent.py" --server %SERVER% --inject phishing
if /I "%CHOICE%"=="2" python "%~dp0sentinel_agent.py" --server %SERVER% --inject virus
if /I "%CHOICE%"=="3" python "%~dp0sentinel_agent.py" --server %SERVER% --inject worm
if /I "%CHOICE%"=="4" python "%~dp0sentinel_agent.py" --server %SERVER% --inject trojan
if /I "%CHOICE%"=="5" python "%~dp0sentinel_agent.py" --server %SERVER% --inject ransomware
if /I "%CHOICE%"=="6" python "%~dp0sentinel_agent.py" --server %SERVER% --inject spyware
if /I "%CHOICE%"=="7" python "%~dp0sentinel_agent.py" --server %SERVER% --inject adware
if /I "%CHOICE%"=="8" python "%~dp0sentinel_agent.py" --server %SERVER% --inject rootkit
if /I "%CHOICE%"=="9" python "%~dp0sentinel_agent.py" --server %SERVER% --inject botnet
if /I "%CHOICE%"=="K" python "%~dp0sentinel_agent.py" --server %SERVER% --inject keylogger
if /I "%CHOICE%"=="R" python "%~dp0sentinel_agent.py" --server %SERVER% --inject rat
if /I "%CHOICE%"=="D" python "%~dp0sentinel_agent.py" --server %SERVER% --inject downloader
if /I "%CHOICE%"=="B" python "%~dp0sentinel_agent.py" --server %SERVER% --inject backdoor
if /I "%CHOICE%"=="F" python "%~dp0sentinel_agent.py" --server %SERVER% --inject fileless
if /I "%CHOICE%"=="M" python "%~dp0sentinel_agent.py" --server %SERVER% --inject cryptominer
if /I "%CHOICE%"=="A" python "%~dp0sentinel_agent.py" --server %SERVER% --inject-all --delay 8
if /I "%CHOICE%"=="Q" goto :eof
goto menu
