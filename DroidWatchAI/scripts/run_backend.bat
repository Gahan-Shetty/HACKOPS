@echo off
REM scripts/run_backend.bat
REM Run this from the DroidWatchAI/ root directory

echo [DroidWatch AI] Starting backend server...

REM Install dependencies if needed
pip install -r requirements.txt

REM Start the Flask + SocketIO server
python -m backend.app

pause
