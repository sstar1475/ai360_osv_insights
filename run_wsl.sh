#!/bin/bash
# run_wsl.sh — запуск OSV Insights через WSL venv
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/env_wsl/bin/python3"

echo "[*] Starting OSV Insights via WSL venv..."
echo "[*] Project: $SCRIPT_DIR"
echo "[*] Python: $VENV_PYTHON"
echo ""

cd "$SCRIPT_DIR"
"$VENV_PYTHON" main.py
