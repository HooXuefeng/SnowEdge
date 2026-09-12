@echo off
setlocal
cd /d "%~dp0"
set JOB_EMBEDDED_WORKERS=0
set JOB_IMMEDIATE_ACCELERATOR=false
start "SnowEdge Worker" cmd /k start-worker.bat
timeout /t 1 /nobreak >nul
start "SnowEdge Web" cmd /k start.bat
endlocal
