#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -x .venv/bin/python ]]; then
  qt_python="${PYTHON:-python3.12}"
  "$qt_python" -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12+ required"'
  "$qt_python" -m venv .venv
fi
qt_requirements_hash="$(.venv/bin/python -c 'import hashlib; print(hashlib.sha256(open("requirements.txt", "rb").read()).hexdigest())')"
if [[ ! -f .venv/.requirements.sha256 ]] || [[ "$(cat .venv/.requirements.sha256)" != "$qt_requirements_hash" ]]; then
  .venv/bin/python -m pip install -r requirements.txt
  printf '%s\n' "$qt_requirements_hash" > .venv/.requirements.sha256
fi
exec .venv/bin/python -m uvicorn api.main:app --host 127.0.0.1 --port "${PORT:-8000}"
