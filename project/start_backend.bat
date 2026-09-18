@echo off
echo.
echo  ScamX - AI CyberShield Platform
echo  Starting Flask backend...
echo.
cd /d "%~dp0backend"
pip install -r requirements.txt --quiet
python main.py
pause
