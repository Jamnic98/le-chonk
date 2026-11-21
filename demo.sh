#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ -z "${MISTRAL_API_KEY:-}" ] && [ -f .env ]; then set -a; . ./.env; set +a; fi

echo "== 0/3 self test (offline, no key needed) =="
python3 -m sentinel selftest || true

echo
echo "== 1/3 full security scan of bundled legacy samples =="
python3 -m sentinel demo --engine auto --out reports/demo

echo
echo "== 2/3 Python 2 -> 3 migration workflow =="
python3 -m sentinel migrate samples/python2 --engine auto --out reports/migration

echo
echo "== 3/3 web demo UI (loopback only) =="
echo "  python3 -m sentinel serve --port 8000   →  http://127.0.0.1:8000"
echo
echo "reports:"
ls -la reports reports/demo reports/migration 2>/dev/null || true
