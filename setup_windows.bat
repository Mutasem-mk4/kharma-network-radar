@echo off
echo ===================================================
echo [ Kharma Radar - Windows Setup ]
echo ===================================================

REM Check for Python
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.7+ to use Kharma.
    exit /b 1
)

REM Install dependencies
echo [1/3] Installing dependencies...
pip install -r "%~dp0requirements.txt"

REM Create batch wrapper in a location that might be in PATH
set TARGET_DIR=%USERPROFILE%\.gemini\antigravity\bin
if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%"

echo [2/3] Creating executable wrapper...
set WRAPPER="%TARGET_DIR%\kharma.bat"
echo @echo off > %WRAPPER%
echo python "%~dp0kharma\main.py" %%* >> %WRAPPER%

echo [3/3] Finalizing setup...
echo.
echo ===================================================
echo Setup Complete!
echo.
echo NOTE: To run 'kharma' from anywhere, ensure this directory is in your PATH:
echo %TARGET_DIR%
echo.
echo You can run it now by typing: 
echo python "%~dp0kharma\main.py"
echo ===================================================
pause
