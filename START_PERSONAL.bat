@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title SnowEdge V1.6
REM V1.6 supervisor launches worker.py and run.py after scripts\db-upgrade.py
set "QUIET=0"
if /I "%~1"=="/quiet" set "QUIET=1"

where python >nul 2>nul
if errorlevel 1 (
  if "%QUIET%"=="0" echo Python 3.11+ not found in PATH.
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  python -m venv .venv
  if errorlevel 1 exit /b 1
)
set "PY=%CD%\.venv\Scripts\python.exe"
"%PY%" -m pip install -q -r requirements.txt
if errorlevel 1 exit /b 1
if not exist ".env" (
  copy .env.example .env >nul
  powershell -NoProfile -Command "$p='.env'; $k=[guid]::NewGuid().ToString('N')+[guid]::NewGuid().ToString('N'); $s=Get-Content $p -Raw; $s=$s.Replace('replace-with-a-long-random-secret',$k).Replace('CHANGE-ME-IN-PRODUCTION',$k); Set-Content -Path $p -Value $s -NoNewline"
)
"%PY%" scripts\personal-supervisor.py --start
if errorlevel 1 exit /b 1
if "%QUIET%"=="1" exit /b 0
powershell -NoProfile -Command "$ok=$false; 1..60 | %% { try { $r=Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/api/health -TimeoutSec 1; if($r.StatusCode -eq 200){$ok=$true;break} } catch {}; Start-Sleep -Milliseconds 500 }; if($ok){Start-Process 'http://127.0.0.1:8000/'} else {Write-Host 'Workspace did not become ready. Check .runtime\launcher.log' }"
exit /b 0
