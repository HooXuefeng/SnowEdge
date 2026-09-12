#!/usr/bin/env bash
set -e
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
python -m pip install -r requirements.txt
if [ ! -f .env ]; then
  cp .env.example .env
  python - <<'PY'
from pathlib import Path
import secrets
p=Path('.env')
s=p.read_text()
s=s.replace('replace-with-a-long-random-secret', secrets.token_hex(32))
p.write_text(s)
PY
  echo "Generated a local APP_SECRET_KEY in .env"
fi
python run.py
