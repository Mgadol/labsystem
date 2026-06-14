#!/bin/bash
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-/home/user/labsystem}"

# Pull latest changes
git pull origin claude/adoring-hamilton-wdvj0b 2>/dev/null || true

# Install dependencies
pip install -q -r requirements.txt --break-system-packages 2>/dev/null || pip install -q -r requirements.txt 2>/dev/null || true

# Start Flask app in background
pkill -f "python app.py" 2>/dev/null || true
nohup python app.py > /tmp/app.log 2>&1 &
