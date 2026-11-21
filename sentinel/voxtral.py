from __future__ import annotations

import base64

import httpx

from . import prompts

STT_MODEL = "voxtral-mini-transcribe-3"
TTS_MODEL = "voxtral-mini-tts-3-0"
CONTEXT_BIAS = [
    "Legacy Sentinel", "COBOL", "PHP", "Python", "EXEC SQL", "SQL injection", "CWE",
    "vulnerability", "scan", "audit", "remediation", "migration", "password", "eval", "pickle",
]


def transcribe(api_key: str, audio: bytes, filename: str = "command.webm", mime: str = "audio/webm") -> str:
    import requests
    data = [("model", STT_MODEL), ("response_format", "json")]
    for term in CONTEXT_BIAS:
        data.append(("context_bias", term))
    r = requests.post(
        f"{prompts.API_URL}/v1/audio/transcriptions",
        headers={"Authorization": f"Bearer {api_key}"},
        data=data,
        files={"file": (filename, audio, mime)},
        timeout=180,
    )
    r.raise_for_status()
    return r.json().get("text", "").strip()


def speak(api_key: str, text: str, voice_id: str = "gb_jane_neutral") -> bytes:
    import base64
    r = httpx.post(
        f"{prompts.API_URL}/v1/audio/speech",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={"model": TTS_MODEL, "input": text[:4000], "voice_id": voice_id, "response_format": "wav"},
        timeout=120,
    )
    r.raise_for_status()
    ctype = r.headers.get("content-type", "")
    if "json" in ctype:
        payload = r.json()
        b64 = payload.get("audio_data") or payload.get("audio") or ""
        return base64.b64decode(b64)
    return r.content


def parse_command(text: str) -> dict:
    tl = text.lower()
    intent = "scan" if any(w in tl for w in ("scan", "audit", "find", "check", "review", "vulnerab", "risk", "security", "assess")) else "ask"
    lang = next((l for l in ("cobol", "php", "python") if l in tl), None)
    focus = next((w for w in ("sql", "password", "credential", "secret", "injection", "encryption", "eval") if w in tl), None)
    return {"intent": intent, "language": lang, "focus": focus, "raw": text}


VOICE_DEMO_TEXT = (
    "Sentinel, scan the legacy codebase for security vulnerabilities in the COBOL, PHP and Python files, "
    "list the top risks with remediation steps, and propose a migration plan."
)


def b64_to_bytes(b64: str) -> bytes:
    return base64.b64decode(b64)
