from __future__ import annotations

import json

from mistralai.client import Mistral

from . import prompts
from .schemas import FindingList, MigrationPlan, RemediationList

MAX_FILE_CHARS = 40_000
MAX_PAYLOAD_CHARS = 220_000


def _payload(files: list[dict], languages: set[str] | None = None) -> str:
    parts, total = [], 0
    for f in files:
        if languages and f["lang"] not in languages:
            continue
        body = f["redacted"][:MAX_FILE_CHARS]
        chunk = f"### {f['path']} ({f['lang']})\n```{f['lang']}\n{body}\n```\n"
        if total + len(chunk) > MAX_PAYLOAD_CHARS:
            parts.append(f"### {f['path']} ({f['lang']}) [truncated: file too large]\n")
            continue
        total += len(chunk)
        parts.append(chunk)
    return "\n".join(parts) or "(no files)"


def _complete_json(client: Mistral, model: str, system: str, user: str, schema_cls, name: str, log, retries: int = 4):
    import time
    last_err = None
    for attempt in range(retries):
        try:
            resp = client.chat.complete(
                model=model,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                response_format={"type": "json_schema", "json_schema": {"name": name, "schema": schema_cls.model_json_schema(), "strict": True}},
                temperature=0.1,
            )
            content = resp.choices[0].message.content
            if isinstance(content, list):
                content = "".join(getattr(c, "text", None) or (c.get("text", "") if isinstance(c, dict) else "") for c in content)
            log(f"  model call {name}: {resp.usage.prompt_tokens} prompt / {resp.usage.completion_tokens} completion tokens")
            return schema_cls.model_validate(json.loads(content))
        except Exception as e:
            last_err = e
            log(f"  {name} attempt {attempt + 1}/{retries} failed: {str(e)[:100]}; retrying" if attempt < retries - 1 else f"  {name} failed: {str(e)[:100]}")
            time.sleep(5 * (attempt + 1))
    raise last_err


def run(files: list[dict], api_key: str, model: str, target: str, log=print, progress=None, step_index: int = 2) -> dict:
    def pstep(detail: str) -> None:
        if progress:
            try:
                progress({"type": "step", "index": step_index, "state": "working", "detail": detail})
            except Exception:
                pass
    client = Mistral(api_key=api_key, server_url=prompts.API_URL)
    langs = sorted({f["lang"] for f in files})
    trace = ["direct engine: mistral-large-4 chat.completions with structured output"]
    findings = []
    for lang in langs:
        n = sum(1 for f in files if f["lang"] == lang)
        log(f"  analyzing {lang} files with Mistral Large 4 ...")
        pstep(f"{lang}-analyst reviewing {n} file(s)")
        system = prompts.load_registry_prompt(f"sentinel-analyst-{lang}", {"language": lang, "language_notes": prompts.LANGUAGE_NOTES[lang]}, api_key) or prompts.analyst_prompt(lang)
        out = _complete_json(client, model, system, _payload(files, {lang}), FindingList, "FindingList", log)
        for f in out.findings:
            findings.append(f.model_dump() | {"source": f"mistral-large-4 ({lang}-analyst)"})
        trace.append(f"{lang}-analyst reported {len(out.findings)} findings")
    findings.sort(key=lambda x: (x["file"], x["line"]))
    rem_in = json.dumps([{k: f[k] for k in ("id", "rule_id", "title", "cwe", "file", "line", "evidence", "description")} for f in findings])
    log("  remediation agent ...")
    pstep("remediation agent writing fixes, patches and tests")
    rems = _complete_json(client, model, prompts.REMEDIATION_SYSTEM, rem_in, RemediationList, "RemediationList", log)
    trace.append(f"remediation-agent produced {len(rems.remediations)} remediations")
    log("  migration advisor ...")
    pstep("migration advisor planning the move to a modern stack")
    mig = _complete_json(
        client, model, prompts.MIGRATION_SYSTEM,
        json.dumps({"manifest": [{"path": f["path"], "language": f["lang"]} for f in files], "findings": findings}),
        MigrationPlan, "MigrationPlan", log)
    trace.append("migration-advisor produced the plan")
    from .engine_offline import compose_summary
    return {
        "findings": findings,
        "remediations": [r.model_dump() for r in rems.remediations],
        "migration": mig.model_dump(),
        "summary": compose_summary(findings),
        "trace": trace,
    }
