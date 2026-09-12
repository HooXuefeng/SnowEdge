@echo off
setlocal
if not exist .venv (
  python -m venv .venv
)
call .venv\Scripts\activate
python -m pip install -r requirements.txt
if not exist .env (
  copy .env.example .env >nul
  powershell -NoProfile -Command "$p='.env'; $k=[guid]::NewGuid().ToString('N')+[guid]::NewGuid().ToString('N'); $s=Get-Content $p -Raw; $s=$s.Replace('replace-with-a-long-random-secret',$k); Set-Content -Path $p -Value $s -NoNewline"
  echo Generated a local APP_SECRET_KEY in .env
)
python run.py
