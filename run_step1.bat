@echo off
rem First45 - Step 1: create venv, install deps, test Gemma 4 on the PHP2Shell advisory.
cd /d "%~dp0"
if not exist logs mkdir logs
echo [1/3] Creating .venv ...
if not exist .venv py -3.12 -m venv .venv || python -m venv .venv
call .venv\Scripts\activate.bat
echo [2/3] Installing requirements (about 1 minute) ...
python -m pip install --upgrade pip > logs\pip.txt 2>&1
pip install -r requirements.txt >> logs\pip.txt 2>&1
echo pip exit code: %ERRORLEVEL%
echo [3/3] Asking Gemma 4 to read the PHP2Shell advisory ...
python gemma_client.py samples\php2shell_advisory.txt > samples\threat_php2shell.json 2> logs\step1_err.txt
echo exit code: %ERRORLEVEL% >> logs\step1_err.txt
type samples\threat_php2shell.json
type logs\step1_err.txt
echo DONE >> logs\step1_err.txt
echo.
echo ===== Step 1 finished. You can close this window. =====
pause
