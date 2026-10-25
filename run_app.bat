@echo off
rem First45 - start the web app (opens in your browser)
cd /d "%~dp0"
call .venv\Scripts\activate.bat
pip install -q -r requirements.txt
streamlit run app.py
pause
