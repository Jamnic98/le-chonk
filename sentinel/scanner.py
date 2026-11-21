from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from . import engine_direct, engine_offline, prompts, rules
from .playbook import remediation_for
from .redact import redact_text
from .schemas import SEVERITY_ORDER, ScanReport

LANG_BY_EXT = {
    ".cbl": "cobol", ".cob": "cobol", ".cobol": "cobol", ".cpy": "cobol", ".cblcpy": "cobol",
    ".php": "php", ".php3": "php", ".php4": "php", ".phtml": "php",
    ".py": "python", ".pyw": "python",
}
IGNORE_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "__pycache__", ".venv", "venv", "dist", "build", "target", ".idea", ".vscode"}
IGNORE_FILES = {".sentinelignore"}
MAX_FILE_BYTES = 300_000
MAX_FILES = 300
MAX_FILE_CHARS = 60_000


def _lang_for(name: str) -> str | None:
    return LANG_BY_EXT.get(Path(name).suffix.lower())


def collect_from_path(root: str | Path) -> list[dict]:
    root = Path(root)
    files = []
    if root.is_file():
        candidates = [root]
    else:
        candidates = sorted(p for p in root.rglob("*") if p.is_file())
    for p in candidates:
        rel = str(p.relative_to(root)) if root.is_dir() else p.name
        if any(part in IGNORE_DIRS for part in p.parts):
            continue
        if p.name in IGNORE_FILES or p.suffix.lower() in (".min.js", ".lock", ".sum"):
            continue
        lang = _lang_for(p.name)
        if not lang:
            continue
        if p.stat().st_size > MAX_FILE_BYTES:
            continue
        if len(files) >= MAX_FILES:
            break
        files.append(_make_entry(rel, lang, p.read_text(encoding="utf-8", errors="replace")))
    return files


def collect_from_payload(payload: list[dict]) -> list[dict]:
    files = []
    for item in payload:
        lang = _lang_for(item["name"])
        if not lang:
            continue
        files.append(_make_entry(item["name"], lang, item.get("content", "")))
    return files


def _make_entry(path: str, lang: str, text: str) -> dict:
    redacted, n_redacted = redact_text(text)
    truncated = len(redacted) > MAX_FILE_CHARS
    if truncated:
        redacted = redacted[:MAX_FILE_CHARS] + "\n... [truncated by sentinel]"
    return {"path": path, "lang": lang, "text": text, "redacted": redacted, "redacted_count": n_redacted, "truncated": truncated}


def _dedupe(baseline: list[dict], llm: list[dict]) -> list[dict]:
    keys = {(f["file"], f["cwe"], f["line"] // 4) for f in llm}
    kept = []
    for b in baseline:
        k = (b["file"], b["cwe"], b["line"] // 4)
        if k in keys:
            continue
        kept.append(b)
    return llm + kept


def run_scan(target: str, files: list[dict], engine: str = "auto", out_dir: str | None = None,
             voice_command: str | None = None, log=print, progress=None) -> dict:
    def emit(ev: dict) -> None:
        if progress:
            try:
                progress(ev)
            except Exception:
                pass

    def step(i: int, state: str, detail: str = "") -> None:
        emit({"type": "step", "index": i, "state": state, "detail": detail})

    def plog(msg) -> None:
        log(msg)
        emit({"type": "trace", "line": str(msg)})

    key = os.environ.get("MISTRAL_API_KEY", "")
    model = prompts.MODEL
    step(1, "working", "running deterministic rules")
    baseline = []
    for i, f in enumerate(files):
        step(1, "working", f"rules scanning {f['path']} ({i + 1}/{len(files)})")
        baseline.extend(rules.findings_for_text(f["path"], f["lang"], f["text"]))
    step(1, "done", f"{len(baseline)} candidate findings")

    chosen = engine
    if chosen == "auto":
        if key:
            try:
                import mistralai.agents  # noqa: F401
                chosen = "sdk"
            except Exception:
                chosen = "direct"
        else:
            chosen = "offline"

    step(2, "working", f"engine: {chosen}")
    result = None
    if chosen in ("sdk", "direct") and key:
        if chosen == "sdk":
            try:
                from . import engine_sdk
                result = engine_sdk.run(files, key, model, target, plog, progress=progress)
            except Exception as e:
                plog(f"agents-sdk engine failed ({e}); falling back to direct engine")
                result = None
        if result is None:
            try:
                result = engine_direct.run(files, key, model, target, plog, progress=progress)
            except Exception as e:
                plog(f"direct engine failed ({e}); falling back to offline rules")
                result = None
    if result is None:
        chosen = "offline"
        result = engine_offline.run(files, plog)
    step(2, "done", f"engine {chosen} finished")

    step(3, "working", f"merging and deduping findings across {len(files)} file(s)")
    findings = _dedupe(baseline, result["findings"]) if chosen != "offline" else result["findings"]
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["file"], f["line"]))

    have = {r["finding_id"] for r in result["remediations"]}
    remediations = list(result["remediations"])
    for f in findings:
        if f["id"] not in have:
            remediations.append(remediation_for(f))
    step(3, "done", f"{len(findings)} findings, {len(remediations)} remediations")

    step(4, "working", "build report and write files")
    report = ScanReport(
        target=target,
        engine=result.get("engine", chosen),
        model=model if chosen != "offline" else "none (offline)",
        scanned_files=len(files),
        languages=sorted({f["lang"] for f in files}),
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        voice_command=voice_command,
        summary=result.get("summary") or engine_offline.compose_summary(findings),
        findings=findings,
        remediations=remediations,
        migration=result["migration"],
        trace=result.get("trace", []),
    )
    data = report.model_dump()
    if out_dir:
        from . import report as report_mod
        report_mod.write_all(data, out_dir, log)
    step(4, "done", "report ready")
    return data
