from __future__ import annotations

import re

_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S)),
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")),
    ("bearer", re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")),
    ("assignment", re.compile(
        r"(?i)(\b(?:password|passwd|pwd|db_pass|secret|secret_key|api[_-]?key|apikey|access[_-]?key|"
        r"auth[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|aws_secret)\b"
        r"\s*[:=]\s*[\"']?)([^\"'\s,;}{]{4,})")),
    ("connstr", re.compile(r"(?i)\b(password|pwd)\s*=\s*[^;\s\"']{3,}")),
]


def redact_text(text: str) -> tuple[str, int]:
    count = 0

    def make_repl(name: str):
        def repl(m: re.Match) -> str:
            nonlocal count
            count += 1
            if name == "assignment":
                return m.group(1) + "[REDACTED]"
            if name == "bearer":
                return m.group(1) + "[REDACTED]"
            return f"[REDACTED-{name.upper()}]"
        return repl

    for name, pat in _PATTERNS:
        text = pat.sub(make_repl(name), text)
    return text, count
