@echo off
setlocal
if not exist .venv (
  echo .venv not found. Run start.bat once first.
  exit /b 1
)
call .venv\Scripts\activate
python -m playwright install chromium
echo Chromium installation complete.
