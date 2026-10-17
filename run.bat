@echo off
REM Simple runner for The Red Room CLI

REM Add src to Python path
set PYTHONPATH=%CD%\src;%PYTHONPATH%

REM Run the CLI
python src\redroom\cli.py %*
