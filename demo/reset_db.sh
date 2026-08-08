#!/usr/bin/env bash
# Mini-SOAR — reset demo data (fresh DB + empty evidence folder).
# Run BEFORE the demo so alert IDs start at 1 and screenshots look clean.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Resetting Mini-SOAR demo data…"
rm -f data/minisoar.db
rm -f evidence/*.json 2>/dev/null || true

# Restart the server so it re-creates an empty DB
if pgrep -f "app/main.py" >/dev/null 2>&1; then
  echo "Restarting the server…"
  pkill -f "app/main.py" || true
  sleep 1
fi
(.venv/bin/python app/main.py > /tmp/minisoar.log 2>&1 &)
sleep 2

echo "Done. Dashboard: http://localhost:8080/"
echo "  total alerts: $(curl -s http://localhost:8080/api/stats | python3 -c 'import json,sys; print(json.load(sys.stdin)["total_alerts"])')"
