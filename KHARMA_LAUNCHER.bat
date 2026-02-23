@echo off
title KHARMA PROACTIVE SUITE - LAUNCHER
echo [*] Initializing Kharma Evolution Suite...
echo [*] Spawning Secure Web Server...

:: Start the server in a new minimized window
start /min cmd /c "python kharma/server.py"

echo [*] Waiting for server initialization...
timeout /t 3 /nobreak > nul

echo [*] Launching Dashboard in default browser...
start http://127.0.0.1:8085

echo.
echo [SUCCESS] KHARMA is now running in the background.
echo [INFO] Close the minimized "KHARMA" terminal to stop the server.
echo.
pause
