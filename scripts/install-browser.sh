#!/usr/bin/env bash
set -e
if [ ! -d ".venv" ]; then
  echo ".venv not found. Run start.sh once first."
  exit 1
fi
source .venv/bin/activate
python -m playwright install chromium
echo "Chromium installation complete."
