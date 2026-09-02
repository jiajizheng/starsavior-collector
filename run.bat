@echo off
setlocal

cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Virtual environment not found.
    echo Run setup.bat first.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" collect.py

echo.
pause
