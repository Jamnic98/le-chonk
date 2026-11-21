# le-chonk
Mistral Ai Hackathon Repo

# 🛡 Legacy Sentinel

Agentic security scanner + migration advisor for **legacy codebases (COBOL, PHP, Python)**.
Point it at a codebase → it finds vulnerabilities with CWE mapping → returns **remediation steps + patches** → recommends and plans a **migration to a modern secure stack** (incl. a guided **Python 2 → 3** workflow with a *needs-to-change / what-changed* report). Voice-controllable end to end.

Built for a hackathon on **Mistral Large 4** with **Mistral Agents SDK**, **Studio Prompt Registry**, and **Voxtral**.

## Quickstart

```bash
cd legacy-sentinel
cp .env.example .env        # put your MISTRAL_API_KEY in .env

python3 -m sentinel selftest                          # offline self test (no key needed)
python3 -m sentinel demo --engine auto --out reports/demo     # scan bundled legacy samples
python3 -m sentinel migrate samples/python2 --out reports/migration   # Py2→Py3 workflow
python3 -m sentinel serve --port 8000                 # web demo UI → http://127.0.0.1:8000 (loopback only)
./demo.sh                                             # full end-to-end demo incl. voice
```

Engines: `auto` (Agents SDK if a key is present) → `sdk` (Mistral Agents SDK multi-agent) → `direct` (chat.completions + structured output) → `offline` (deterministic rules + playbook, no key, no network).

## Web UI (the SaaS demo)

`python3 -m sentinel serve` opens a single-page app with two workflows:

1. **🔍 Security scan** — load the demo codebase or drag & drop COBOL/PHP/Python files → run the agentic scan → findings with severity/CWE/evidence, per-finding remediation (steps, patch, tests, refs), migration recommendation (strategy, quick wins, phases, module table), agent trace, exports (HTML/Markdown/JSON/**SARIF**). **🎤 Voice command**: record with the mic — Voxtral transcribes, the command is executed, and **🔊 Play summary** speaks the report back (Voxtral TTS).
2. **🔄 Python 2 → 3 migration** — load the Py2 sample (or upload `.py`) → run the workflow → stepper (detect → agent plan → 2to3 diff → report) → **needs-to-change** table (file:line, issue, auto/review/manual, fix) and **what-changed** automated diff, plus checklist, test plan, risks.

## CLI

```bash
python3 -m sentinel scan <path> [--engine auto|sdk|direct|offline] [--out DIR]
python3 -m sentinel migrate <path> [--out DIR]                 # Py2→Py3 workflow
python3 -m sentinel voice <audio-file> --dir samples --speak-summary   # Voxtral STT → scan → TTS summary
python3 -m sentinel make-voice-demo --out reports/voice_command.wav    # synthesize demo command (Voxtral TTS)
python3 -m sentinel serve --host 127.0.0.1 --port 8000
```

Reports land in `reports/<run>/`: `report.json`, `report.sarif`, `report.md`, `index.html` (scan) and `migration.json`, `migration.md`, `index.html` (migration).

## Where we use Mistral (for the judges)

| Mistral tech | Where in the project | How |
|---|---|---|
| **Mistral Large 4** (`mistral-large-4`, 1M ctx, structured outputs) | `sentinel/engine_sdk.py`, `sentinel/engine_direct.py`, `sentinel/migrate.py` | Model for every agent: analyst subagents, remediation, migration advisor, Py2→3 planner; JSON-schema structured output via `output_type=` / `response_format` |
| **Mistral Agents SDK** (`from mistralai import agents`) | `sentinel/engine_sdk.py` | `agents.Agent(name="sentinel-orchestrator", model="mistral-large-4")` with **subagents** `cobol-analyst`, `php-analyst`, `python-analyst`, `remediation-agent`, `migration-advisor`; custom `@agents.tool`s `list_manifest` / `read_source`; parallel subagent fan-out; `output_type=ScanOutput`; live event trace (`on_event`) shown in UI/CLI. Same agent deploys as a **Mistral Workflow** via `agents deploy` (registered as a workflow under its name) |
| **Studio Prompt Registry** | registered: `sentinel-orchestrator`, `sentinel-analyst`, `sentinel-remediation`, `sentinel-migration-advisor`, `sentinel-py23-migration` | created via Studio/MCP; at runtime the app fetches them through the Prompts API (`prompts.load_registry_prompt`) and falls back to the bundled copies in `sentinel/prompts.py` |
| **Studio Skill** | registered: `legacy-remediation-playbook` (assets: playbook.md, cwe-rules.json) | remediation knowledge; local canonical copy in `sentinel/playbook.py`; deployed agents attach via `skills=[agents.RegistrySkill(...)]` |
| **Voxtral STT** (`voxtral-mini-transcribe-3`, `POST /v1/audio/transcriptions`) | `sentinel/voxtral.py`, `/api/voice`, CLI `voice` | mic (or audio file) → transcription with domain `context_bias` (COBOL, EXEC SQL, CWE, …) → parsed intent → agentic scan. `make-voice-demo` ships a canned command |
| **Voxtral TTS** (`voxtral-mini-tts-3-0`, `POST /v1/audio/speech`) | `sentinel/voxtral.py`, `/api/speak` | speaks the scan summary back in the UI; generates the demo voice command WAV |

## Security design (the product is a security tool — it must be secure itself)

- **Secret redaction before any model call**: `sentinel/redact.py` scrubs private keys, AWS keys, JWTs, bearer tokens, `password = "..."` assignments, connection-string passwords from all code sent to the LLM *and* from all evidence in reports (demo shows `[REDACTED]`).
- **Read-only scanning**: sources are never modified; migration diffs are computed on temp copies; repo access in production is read-only scoped tokens.
- **Loopback-only web server** (binds `127.0.0.1`); path-confined sample loading; request size caps; no telemetry, no third-party calls except Mistral API.
- **Key handling**: `MISTRAL_API_KEY` via env or `.env` (gitignored pattern); never logged or embedded in reports. Production posture: self-hosted/VPC endpoint (`MISTRAL_API_URL`), air-gap capable, audit log of what was sent to the model.
- **Deterministic backbone**: 22 built-in rules across COBOL/PHP/Python run without any model, so the tool still works offline/air-gapped and corroborates LLM findings (dedupe by file/line/CWE).

## Architecture

```
files (upload / drop / samples / repo path)
  → collect + redact (redact.py)            → deterministic rules (rules.py) ─┐
  → engine: agents-sdk orchestrator + subagents (engine_sdk.py)                  ├→ merge/dedupe → report
              └ fallback: direct structured-output pipeline (engine_direct.py) ┘      (json/sarif/md/html)
  → migration workflow: detect py2 (migrate.py) → lib2to3 diff → agent plan → needs/what-changed report
voice: mic → Voxtral STT → intent → scan → Voxtral TTS summary
web: webapp.py (stdlib, loopback) + web/index.html
```

## Layout

```
sentinel/    cli.py webapp.py scanner.py rules.py redact.py playbook.py prompts.py voxtral.py report.py
             engine_offline.py engine_direct.py engine_sdk.py migrate.py schemas.py
web/         index.html          # single-page demo UI
samples/     cobol/ php/ python/ python2/   # intentionally vulnerable demo codebases
demo.sh      reports/            # generated reports land here
```

## Config

| Env | Default | Purpose |
|---|---|---|
| `MISTRAL_API_KEY` | — | Mistral API key (`.env` supported) |
| `SENTINEL_MODEL` | `mistral-large-4` | model for all agents |
| `MISTRAL_API_URL` | `https://api.mistral.ai` | API root (point at VPC/self-hosted for air-gap) |
