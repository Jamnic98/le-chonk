from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from mistralai.client import Mistral

from . import fetch, prompts, scanner
from .engine_direct import complete_json
from .schemas import SEVERITY_ORDER, MigrationResult


def _safe_rel_path(rel: str) -> str:
    p = PurePosixPath(rel.replace("\\", "/"))
    if not rel.strip() or p.is_absolute() or ".." in p.parts:
        raise ValueError(f"unsafe path in migration output: {rel!r}")
    return str(p)


def _write_files(root: Path, files: list) -> list[str]:
    written = []
    for f in files:
        rel = _safe_rel_path(f.path)
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(f.content, encoding="utf-8")
        written.append(rel)
    return written


def _counts(findings: list[dict]) -> dict:
    c: dict[str, int] = {}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    return dict(sorted(c.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9)))


def _render_md(data: dict) -> str:
    L = [f"# Report-driven migration — `{data['target']}`", "",
         f"- Engine: {data['engine']} · model {data['model']} · report: `{data['report']}` · {data['generated_at']}",
         "", f"> {data['summary']}", "",
         "## Findings before / after re-scan", "",
         "| Severity | Before | After |", "|---|---|---|"]
    keys = sorted(set(data["findings_before"]) | set(data["findings_after"]), key=lambda k: SEVERITY_ORDER.get(k, 9))
    for k in keys:
        L.append(f"| {k} | {data['findings_before'].get(k, 0)} | {data['findings_after'].get(k, 0)} |")
    L += ["", f"## Migrated files ({len(data['files_written'])})", ""]
    for c in data["changes"]:
        L.append(f"- `{c['path']}` — {c['change_summary']}")
    L += ["", "## Remaining risks", ""]
    L += [f"- {r}" for r in data["remaining_risks"]] or ["- none"]
    L += ["", "## Suggested tests", ""]
    L += [f"- {t}" for t in data["suggested_tests"]] or ["- none"]
    L += ["", f"Re-scan report: `{data['rescan_report']}`", ""]
    return "\n".join(L) + "\n"


def run_report_migration(target: str, report_path: str, out_dir: str, engine: str = "auto", langs: set[str] | None = None, log=print) -> dict:
    key = os.environ.get("MISTRAL_API_KEY", "")
    if not key:
        raise SystemExit("report-driven migration needs MISTRAL_API_KEY (Mistral Large 4 generates the migrated code)")
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path, cleanup = fetch.resolve_target(target)
    try:
        skip = scanner.REPO_SKIP_DIRS if fetch.is_repo_url(target) else None
        files = scanner.collect_from_path(path, skip_dirs=skip)
        files = scanner.filter_langs(files, langs)
        if not files:
            raise SystemExit("no supported files found in target (cobol/php/python)")
        client = Mistral(api_key=key, server_url=prompts.API_URL)
        log(f"  migration engineer ({prompts.MODEL}) rewriting code per {report_path} ...")
        payload = prompts.migration_code_payload(target, report, files)
        result = complete_json(client, prompts.MODEL, prompts.MIGRATION_CODE_SYSTEM, json.dumps(payload), MigrationResult, "MigrationResult", log)
        written = _write_files(out, result.files)
        log(f"  wrote {len(written)} migrated file(s) under {out}/")
        rescan_dir = out / "rescan"
        rescan_files = scanner.collect_from_path(out)
        log("  re-scanning migrated output ...")
        rescan = scanner.run_scan(str(out), rescan_files, engine=engine, out_dir=str(rescan_dir), log=log)
    finally:
        if cleanup:
            cleanup()
    before = _counts(report.get("findings", []))
    after = _counts(rescan["findings"])
    data = {
        "target": target,
        "report": str(report_path),
        "engine": "mistral-large-4",
        "model": prompts.MODEL,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": result.summary,
        "remaining_risks": result.remaining_risks,
        "suggested_tests": result.suggested_tests,
        "files_written": written,
        "changes": [{"path": f.path, "change_summary": f.change_summary} for f in result.files],
        "findings_before": before,
        "findings_after": after,
        "rescan_report": str(rescan_dir / "report.json"),
        "trace": [
            f"migration engineer ({prompts.MODEL}) generated the migrated codebase from the scan report",
            f"re-scan of migrated output: {sum(after.values())} findings remain (was {sum(before.values())})",
        ],
    }
    (out / "migration.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    (out / "migration.md").write_text(_render_md(data), encoding="utf-8")
    log(f"  migration report written to {out}/ (migration.json, migration.md)")
    return data
