from __future__ import annotations

import asyncio
import json

from mistralai import agents

from . import prompts
from .schemas import ScanOutput


_STATE: dict = {"manifest": [], "store": {}}


@agents.tool
def list_manifest() -> str:
    """List the files in the scanned target as a JSON array of {path, language, chars}."""
    return json.dumps(_STATE["manifest"])


@agents.tool
def read_source(path: str) -> str:
    """Read one source file of the scanned target. Read-only; contents are already secret-redacted."""
    if path not in _STATE["store"]:
        raise agents.ToolError(f"unknown path: {path}")
    return _STATE["store"][path]


def run(files: list[dict], api_key: str, model: str, target: str, log=print, progress=None, step_index: int = 2) -> dict:
    _STATE["store"] = {f["path"]: f["redacted"] for f in files}
    _STATE["manifest"] = [{"path": f["path"], "language": f["lang"], "chars": len(f["redacted"])} for f in files]

    subs = []
    for lang, notes in prompts.LANGUAGE_NOTES.items():
        subs.append(agents.Subagent(
            name=f"{lang}-analyst",
            description=f"Security analyst specialist for {lang} legacy code. Reports findings as a JSON array.",
            instructions=prompts.analyst_prompt(lang),
            tools=[list_manifest, read_source],
            builtins=agents.Builtins(subagents=False),
        ))
    subs.append(agents.Subagent(
        name="remediation-agent",
        description="Turns the findings JSON into concrete fixes: steps, patch, tests, references.",
        instructions=prompts.REMEDIATION_SYSTEM,
        tools=[],
        builtins=agents.Builtins(subagents=False),
    ))
    subs.append(agents.Subagent(
        name="migration-advisor",
        description="Recommends a phased strangler-fig migration to a modern secure stack.",
        instructions=prompts.MIGRATION_SYSTEM,
        tools=[list_manifest],
        builtins=agents.Builtins(subagents=False),
    ))

    orchestrator = agents.Agent(
        name="sentinel-orchestrator",
        model=model,
        instructions=prompts.ORCHESTRATOR_SYSTEM,
        tools=[list_manifest, read_source],
        subagents=subs,
    )

    trace: list[str] = ["agents-sdk: sentinel-orchestrator (mistral-large-4) with subagents " + ", ".join(s.name for s in subs)]

    def on_event(ev):
        try:
            name = type(ev).__name__
            line = None
            if name == "ToolCallEntry":
                tool = getattr(ev, "name", "") or getattr(getattr(ev, "tool_call", None), "name", "")
                line = f"tool call: {tool}"
            elif name == "TurnStarted":
                line = "turn started"
            elif "Subagent" in name:
                line = f"subagent event: {name} {getattr(ev, 'name', '')}".strip()
            if line:
                trace.append(line)
                if progress:
                    progress({"type": "trace", "line": line})
                    progress({"type": "step", "index": step_index, "state": "working", "detail": line})
        except Exception:
            pass

    async def go():
        return await orchestrator.run(prompts.orchestrator_task(target, files), output_type=ScanOutput, on_event=on_event)

    log("  starting sentinel-orchestrator + specialist subagents (Mistral Large 4) ...")
    state = asyncio.run(asyncio.wait_for(go(), timeout=540))

    if isinstance(state, agents.Completed):
        out = state.output
        if isinstance(out, ScanOutput):
            result = out.model_dump()
        elif isinstance(out, agents.InvalidOutput):
            result = ScanOutput.model_validate_json(state.text).model_dump()
        else:
            result = ScanOutput.model_validate_json(state.text).model_dump()
    else:
        raise RuntimeError(f"agent run did not complete: {type(state).__name__}")

    for f in result["findings"]:
        f["source"] = f"mistral-large-4 ({f.get('source') or 'agent'})" if not f.get("source", "").startswith("mistral") else f["source"]
    trace.append(f"orchestrator returned {len(result['findings'])} findings, {len(result['remediations'])} remediations")
    result["trace"] = trace
    result["engine"] = "mistral-agents-sdk"
    result["model"] = model
    return result
