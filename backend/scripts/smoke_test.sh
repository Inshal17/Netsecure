#!/usr/bin/env bash
set -euo pipefail

echo "Checking backend health..."
curl -fsS http://127.0.0.1:8000/api/health || { echo "Backend not reachable"; exit 1; }
echo "Backend OK"

echo "Checking analyses list..."
curl -fsS http://127.0.0.1:8000/api/analyses | jq '. | length' || true
echo "Done"
