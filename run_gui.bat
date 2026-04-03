@echo off
cd /d "%~dp0"
python ui\converter_gui.py
if errorlevel 1 (
    echo Python not found or error. Install Python 3 from https://python.org
    pause
)
