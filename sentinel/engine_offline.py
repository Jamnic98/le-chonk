from __future__ import annotations

import re
from datetime import datetime, timezone

from . import rules
from .playbook import remediation_for


def run(files: list[dict], log=print) -> dict:
    findings = []
    for f in files:
        findings.extend(rules.findings_for_text(f["path"], f["lang"], f["text"]))
    findings.sort(key=lambda x: (x["file"], x["line"]))
    remediations = [remediation_for(f) for f in findings]
    migration = heuristic_migration(files, findings)
    summary = compose_summary(findings)
    return {
        "findings": findings,
        "remediations": remediations,
        "migration": migration,
        "summary": summary,
        "trace": ["offline deterministic rule engine (no model calls)"],
    }


def compose_summary(findings: list[dict]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    parts = [f"{v} {k}" for k, v in sorted(counts.items(), key=lambda kv: ["critical", "high", "medium", "low", "info"].index(kv[0]))]
    top = [f for f in findings if f["severity"] in ("critical", "high")][:3]
    s = f"{len(findings)} findings ({', '.join(parts) if parts else 'none'})."
    if top:
        s += " Top risks: " + "; ".join(f"{t['title']} in {t['file']}:{t['line']}" for t in top) + "."
    return s


def heuristic_migration(files: list[dict], findings: list[dict]) -> dict:
    langs = sorted({f["lang"] for f in files})
    modules, quick_wins, phases = [], [], [
        "Phase 1 - Stop the bleeding: rotate exposed secrets, fix critical injection/eval issues, add CI secret scanning and SAST gate.",
        "Phase 2 - Stabilize: upgrade runtimes to supported versions (PHP 8.x, Python 3.12+), pin dependencies, containerize.",
        "Phase 3 - Strangler fig: expose legacy entry points behind an API facade; migrate one module at a time with parity tests.",
        "Phase 4 - Cutover & decommission: reconcile data, remove old code paths, retire old runtimes.",
    ]
    if "php" in langs:
        php_text = "\n".join(f["text"] for f in files if f["lang"] == "php")
        if re.search(r"\bmysql_(connect|query|fetch)", php_text):
            quick_wins.append("ext/mysql was removed in PHP 7 - replace with PDO/mysqli (this alone blocks a class of SQLi).")
        modules.append({
            "component": "Web portal", "current": "Legacy PHP (ext/mysql, mixed logic/view)",
            "target": "PHP 8.3+ on Laravel 11 or Symfony 7 with PDO, CSRF middleware, templating with auto-escaping",
            "rationale": "Supported runtime, maintained framework, parameterized DB layer, secure defaults.",
            "effort": "XL", "risk": "medium", "order": 3,
        })
    if "python" in langs:
        py_text = "\n".join(f["text"] for f in files if f["lang"] == "python")
        if re.search(r"(?m)^\s*print\s+[^(]", py_text) or "except Exception, e" in py_text:
            quick_wins.append("Detected Python 2 syntax - migrate to Python 3.12+ first (2to3 + tests), then adopt a typed framework.")
        modules.append({
            "component": "Batch jobs", "current": "Python scripts (eval, pickle, shell=True)",
            "target": "Python 3.12+ typed code on FastAPI/Django or Celery workers, pinned deps, no eval/pickle/shell",
            "rationale": "Removes entire vuln classes (code exec, deserialization, command injection) and gets a supported runtime.",
            "effort": "M", "risk": "low", "order": 2,
        })
    if "cobol" in langs:
        quick_wins.append("Do not big-bang rewrite COBOL: put a REST facade (z/OS Connect / CICS TG) in front and migrate module by module.")
        modules.append({
            "component": "Core batch/online programs", "current": "COBOL on z/OS (CICS/IMS), VSAM files",
            "target": "Keep hardened COBOL behind an API facade; migrate selected modules to Java/Kotlin on JVM or .NET; reconcile VSAM data",
            "rationale": "Strangler-fig limits blast radius; each migrated module is parity-tested against the COBOL original.",
            "effort": "XL", "risk": "high", "order": 4,
        })
    return {
        "strategy": "Strangler fig / anti-corruption layer: wrap legacy entry points, migrate incrementally with parity tests. Security fixes first, framework moves second.",
        "summary": f"Stack detected: {', '.join(langs)}. " + "Apply security quick wins immediately, then migrate via a facade, module by module.",
        "quick_wins": quick_wins,
        "phases": phases,
        "modules": modules,
    }


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
