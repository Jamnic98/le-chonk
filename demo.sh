#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ -z "${MISTRAL_API_KEY:-}" ] && [ -f .env ]; then set -a; . ./.env; set +a; fi

echo "== 0/5 self test (offline, no key needed) =="
python3 -m sentinel selftest || true

echo
echo "== 1/5 full security scan of bundled legacy samples =="
python3 -m sentinel demo --engine auto --out reports/demo

echo
echo "== 2/5 Python 2 -> 3 migration workflow =="
python3 -m sentinel migrate samples/python2 --engine auto --out reports/migration

if [ -n "${MISTRAL_API_KEY:-}" ]; then
  echo
  echo "== 3/5 synthesize voice command with Voxtral TTS =="
  python3 -m sentinel make-voice-demo --out reports/voice_command.wav
  echo
  echo "== 4/5 Voxtral STT -> voice command -> agentic scan =="
  python3 -m sentinel voice reports/voice_command.wav --dir samples --engine auto --out reports/voice --speak-summary
else
  echo
  echo "(skip voice demo: set MISTRAL_API_KEY in .env)"
fi

echo
echo "== 5/5 web demo UI (loopback only) =="
echo "  python3 -m sentinel serve --port 8000   →  http://127.0.0.1:8000"
echo
echo "reports:"
ls -la reports reports/demo reports/migration 2>/dev/null || true
