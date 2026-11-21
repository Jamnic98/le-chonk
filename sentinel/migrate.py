from __future__ import annotations

import difflib
import html
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from mistralai.client import Mistral
from pydantic import BaseModel, Field

from . import prompts
from .redact import redact_text

PY2_RULES = [
    {"id": "py2-print", "title": "print statement", "pattern": r"^\s*print\s+(?!\()|^\s*print\s*>>", "flags": re.M, "change": "auto", "fix": "print(...) function", "after": "print('msg')"},
    {"id": "py2-except-comma", "title": "except E, e syntax", "pattern": r"except\s+[\w.]+\s*,\s*\w+\s*:", "flags": 0, "change": "auto", "fix": "except E as e:", "after": "except KeyError as e:"},
    {"id": "py2-raise-comma", "title": "raise E, msg syntax", "pattern": r"^\s*raise\s+[\w.]+\s*,", "flags": re.M, "change": "auto", "fix": "raise E(msg)", "after": "raise ValueError('too big')"},
    {"id": "py2-has-key", "title": "dict.has_key()", "pattern": r"\.has_key\s*\(", "flags": 0, "change": "auto", "fix": "key in dict", "after": "if 'amount' in r:"},
    {"id": "py2-xrange", "title": "xrange()", "pattern": r"\bxrange\s*\(", "flags": 0, "change": "auto", "fix": "range()", "after": "for i in range(n):"},
    {"id": "py2-raw-input", "title": "raw_input()", "pattern": r"\braw_input\s*\(", "flags": 0, "change": "auto", "fix": "input()", "after": "name = input('name? ')"},
    {"id": "py2-input-eval", "title": "input() evaluates input in Py2", "pattern": r"\binput\s*\(", "flags": 0, "change": "review", "fix": "raw_input + parse", "after": "port = int(input('Port? '))"},
    {"id": "py2-itermethods", "title": "iteritems/iterkeys/itervalues", "pattern": r"\.(iteritems|iterkeys|itervalues)\s*\(", "flags": 0, "change": "auto", "fix": "items()/keys()/values()", "after": "for k, v in d.items():"},
    {"id": "py2-builtin-types", "title": "basestring/unicode/long", "pattern": r"\b(basestring|unicode|long)\s*\(", "flags": 0, "change": "review", "fix": "str / str / int", "after": "isinstance(x, str)"},
    {"id": "py2-backticks", "title": "backtick repr", "pattern": r"`[^`\n]+`", "flags": 0, "change": "auto", "fix": "repr()", "after": "repr(x)"},
    {"id": "py2-octal", "title": "octal literal 0755", "pattern": r"(?<![\w.])0[0-7]{2,}\b", "flags": 0, "change": "auto", "fix": "0o755", "after": "os.chmod(p, 0o755)"},
    {"id": "py2-exec-stmt", "title": "exec statement", "pattern": r"^\s*exec\s+[^(]", "flags": re.M, "change": "auto", "fix": "exec(code)", "after": "exec(code)"},
    {"id": "py2-module-moves", "title": "moved stdlib module", "pattern": r"\b(?:import|from)\s+(urllib2|urlparse|ConfigParser|cPickle|Queue|StringIO|BaseHTTPServer|SocketServer|SimpleHTTPServer|Cookie|__builtin__|Tkinter|HTMLParser|xmlrpclib)\b", "flags": 0, "change": "auto", "fix": "py3 module path", "after": "import urllib.request, configparser, pickle"},
    {"id": "py2-file", "title": "file() builtin", "pattern": r"\bfile\s*\(", "flags": 0, "change": "auto", "fix": "open()", "after": "f = open(path, 'wb')"},
    {"id": "py2-execfile", "title": "execfile()", "pattern": r"\bexecfile\s*\(", "flags": 0, "change": "review", "fix": "exec(open(f).read())", "after": "exec(open(path).read())"},
    {"id": "py2-apply", "title": "apply()", "pattern": r"\bapply\s*\(", "flags": 0, "change": "review", "fix": "f(*args, **kw)", "after": "f(*args, **kw)"},
    {"id": "py2-cmp", "title": "cmp() builtin", "pattern": r"\bcmp\s*\(", "flags": 0, "change": "review", "fix": "(a>b)-(a<b)", "after": "(a > b) - (a < b)"},
    {"id": "py2-map-filter", "title": "map/filter return iterators in Py3", "pattern": r"^\s*\w+\s*=\s*(?:map|filter|zip)\s*\(", "flags": re.M, "change": "review", "fix": "wrap in list() if a list is needed", "after": "xs = list(map(f, items))"},
    {"id": "py2-reload", "title": "reload() moved", "pattern": r"\breload\s*\(", "flags": 0, "change": "review", "fix": "importlib.reload", "after": "importlib.reload(mod)"},
    {"id": "py2-dict-keys-index", "title": "indexing .keys()/.items()", "pattern": r"\.(?:keys|items|values)\s*\(\s*\)\s*\[", "flags": 0, "change": "review", "fix": "list(d.keys())[i]", "after": "list(d.keys())[0]"},
]

CHECKLIST = [
    "Add `from __future__ import print_function, division, unicode_literals` if the code must run on both 2 and 3 during transition.",
    "Review every `/` division for integer-division semantics changes.",
    "Review map/filter/zip results (iterators in Py3) and dict views (keys/items/values).",
    "Review input() (Py2 evals the input) -> use explicit parsing.",
    "Update third-party deps to Py3-compatible versions (MySQLdb -> mysqlclient/PyMySQL, etc.).",
    "Change shebangs to python3 and update CI images to 3.12+.",
    "Run the full test suite on Python 3.12+ and add tests for changed semantics.",
]

TEST_PLAN = [
    "Run existing unit tests under python3 -m pytest after mechanical conversion.",
    "Add tests around division, map/filter, dict views and input parsing (semantic changes).",
    "Smoke-test entry points (scripts, WSGI/HTTP handlers, batch jobs) on 3.12.",
]

RISKS = [
    "Semantic changes (division, iterators, input/eval) are not caught by 2to3 - manual review required.",
    "String/bytes boundaries change in Py3 (open(...,'wb'), socket, DB drivers) - test binary paths.",
]


class Py23Item(BaseModel):
    file: str
    line: int
    rule_id: str
    title: str
    evidence: str
    change: Literal["auto", "manual", "review"]
    before: str = ""
    after: str = ""
    explanation: str = ""


class Py23Plan(BaseModel):
    summary: str
    detected_py2: bool
    checklist: list[str] = Field(default_factory=list)
    items: list[Py23Item] = Field(default_factory=list)
    test_plan: list[str] = Field(default_factory=list)
    risks: list[str] = Field(default_factory=list)


MIGRATE_SYSTEM = """You are the Python 2 -> 3 migration agent of Legacy Sentinel. Input: JSON {files: [{path, content}], detected: [issues found by the deterministic detector]}.
Produce a migration plan as JSON only, no prose, matching the required schema:
- For every detected issue, and any other Py2 constructs you find (print statements, except E, e, raise E, msg, has_key, xrange, raw_input, input() eval semantics, iteritems, basestring/unicode/long, backticks, octal 0755, exec statement, moved stdlib modules urllib2/ConfigParser/cPickle/BaseHTTPServer/urlparse/Queue/StringIO, file(), execfile, apply, cmp, map/filter/zip iterator semantics, division semantics, .keys() indexing, reload), emit one item: {file, line, rule_id, title, evidence, change, before, after, explanation}.
- change: "auto" = safe mechanical fix (2to3 handles it), "review" = semantics change needing human review (division, map/filter, input, dict views), "manual" = needs a human decision.
- before/after: concrete code lines.
- checklist, test_plan, risks: practical lists for a Py2->3.12 migration.
Contents are already secret-redacted; never include real secrets."""


def detect_py2(files: list[dict]) -> list[dict]:
    issues = []
    for f in files:
        if f["lang"] != "python":
            continue
        lines = f["text"].splitlines()
        for rule in PY2_RULES:
            pat = re.compile(rule["pattern"], rule["flags"])
            for m in pat.finditer(f["text"]):
                line_no = f["text"].count("\n", 0, m.start()) + 1
                raw = lines[line_no - 1].strip() if line_no - 1 < len(lines) else m.group(0)
                issues.append({
                    "file": f["path"], "line": line_no, "rule_id": rule["id"], "title": rule["title"],
                    "evidence": redact_text(raw)[0][:220], "change": rule["change"], "fix": rule["fix"], "after": rule["after"],
                })
    issues.sort(key=lambda x: (x["file"], x["line"]))
    return issues


def run_2to3(path: str, text: str) -> tuple[str, str]:
    if importlib.util.find_spec("lib2to3") is None:
        return text, ""
    try:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td) / (Path(path).name or "mod.py")
            tmp.write_text(text, encoding="utf-8")
            subprocess.run([sys.executable, "-W", "ignore", "-m", "lib2to3", "-w", "-n", str(tmp)],
                           capture_output=True, timeout=90)
            new = tmp.read_text(encoding="utf-8")
    except Exception:
        return text, ""
    if new == text:
        return text, ""
    diff = "".join(difflib.unified_diff(
        text.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile=path, tofile=path + " (py3)"))
    return new, diff


def agent_plan(files: list[dict], issues: list[dict], api_key: str, model: str, log=print) -> dict | None:
    client = Mistral(api_key=api_key, server_url=prompts.API_URL)
    payload = {
        "files": [{"path": f["path"], "content": f["redacted"][:40_000]} for f in files if f["lang"] == "python"],
        "detected": issues,
    }
    import time
    last_err = None
    for attempt in range(4):
        try:
            resp = client.chat.complete(
                model=model,
                messages=[{"role": "system", "content": MIGRATE_SYSTEM},
                          {"role": "user", "content": json.dumps(payload)}],
                response_format={"type": "json_schema", "json_schema": {"name": "Py23Plan", "schema": Py23Plan.model_json_schema(), "strict": True}},
                temperature=0.1,
            )
            content = resp.choices[0].message.content
            if isinstance(content, list):
                content = "".join(getattr(c, "text", None) or (c.get("text", "") if isinstance(c, dict) else "") for c in content)
            log(f"  migration agent (Mistral Large 4): {resp.usage.prompt_tokens}/{resp.usage.completion_tokens} tokens")
            return Py23Plan.model_validate(json.loads(content)).model_dump()
        except Exception as e:
            last_err = e
            if attempt < 3:
                log(f"  migration agent attempt {attempt + 1}/4 failed: {str(e)[:100]}; retrying")
                time.sleep(5 * (attempt + 1))
    raise last_err


def deterministic_plan(issues: list[dict]) -> dict:
    items = [{
        "file": i["file"], "line": i["line"], "rule_id": i["rule_id"], "title": i["title"],
        "evidence": i["evidence"], "change": i["change"], "before": i["evidence"], "after": i["after"],
        "explanation": f"{i['title']}: {i['fix']}.",
    } for i in issues]
    n_auto = sum(1 for i in issues if i["change"] == "auto")
    n_review = sum(1 for i in issues if i["change"] == "review")
    return {
        "summary": f"Detected {len(issues)} Python 2 constructs ({n_auto} auto-fixable by 2to3, {n_review} need review). lib2to3 diff generated for mechanical fixes; review items need human decisions.",
        "detected_py2": bool(issues),
        "checklist": CHECKLIST,
        "items": items,
        "test_plan": TEST_PLAN,
        "risks": RISKS,
    }


def run_migration(target: str, files: list[dict], engine: str = "auto", out_dir: str | None = None, log=print, progress=None) -> dict:
    def step(i: int, state: str, detail: str = "") -> None:
        if progress:
            try:
                progress({"type": "step", "index": i, "state": state, "detail": detail})
            except Exception:
                pass

    def plog(msg) -> None:
        log(msg)
        if progress:
            try:
                progress({"type": "trace", "line": str(msg)})
            except Exception:
                pass

    py_files = [f for f in files if f["lang"] == "python"]
    step(0, "working", "detecting Python 2 constructs")
    issues = detect_py2(files)
    plog(f"detected {len(issues)} Python 2 constructs")
    step(0, "done", f"{len(issues)} constructs found")
    step(1, "working", "running lib2to3 for automated diffs")
    diffs = {}
    for f in py_files:
        _, diff = run_2to3(f["path"], f["text"])
        if diff:
            diffs[f["path"]] = diff
    plog(f"lib2to3 produced diffs for {len(diffs)} file(s)")
    step(1, "done", f"{len(diffs)} file(s) with automated diffs")

    key = os.environ.get("MISTRAL_API_KEY", "")
    trace = []
    plan = None
    step(2, "working", "building the migration plan")
    if key and engine in ("auto", "direct", "sdk"):
        try:
            plan = agent_plan(py_files, issues, key, prompts.MODEL, plog)
            trace.append(f"migration agent (mistral-large-4, structured output): {len(plan['items'])} planned changes")
        except Exception as e:
            plog(f"migration agent failed ({e}); using deterministic plan")
    if plan is None:
        plan = deterministic_plan(issues)
        trace.append("deterministic py2 detector + lib2to3 diff (offline)")
    step(2, "done", f"{len(plan['items'])} planned changes")

    seen = {(i["file"], i["line"] // 4, i["rule_id"]) for i in plan["items"]}
    for i in issues:
        k = (i["file"], i["line"] // 4, i["rule_id"])
        if k not in seen:
            plan["items"].append({
                "file": i["file"], "line": i["line"], "rule_id": i["rule_id"], "title": i["title"],
                "evidence": i["evidence"], "change": i["change"], "before": i["evidence"], "after": i["after"],
                "explanation": f"{i['title']}: {i['fix']}.",
            })
    plan["items"].sort(key=lambda x: (x["file"], x["line"]))

    step(3, "working", "write report")
    result = {
        "target": target,
        "engine": "mistral-large-4" if key and plan and trace and "migration agent" in trace[0] else "offline",
        "model": prompts.MODEL if key else "none (offline)",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": [f["path"] for f in py_files],
        "issues": issues,
        "plan": plan,
        "diffs": diffs,
        "summary": plan["summary"],
        "trace": trace,
    }
    if out_dir:
        write_reports(result, out_dir, log)
    step(3, "done", "report ready")
    return result


def _diff_html(diff: str) -> str:
    out = []
    for line in diff.splitlines():
        cls = "ctx"
        if line.startswith("+++") or line.startswith("---"):
            cls = "hdr"
        elif line.startswith("+"):
            cls = "add"
        elif line.startswith("-"):
            cls = "del"
        out.append(f'<span class="{cls}">{html.escape(line)}</span>')
    return "\n".join(out)


def render_md(r: dict) -> str:
    L = [f"# Python 2 → 3 migration report — `{r['target']}`", "",
         f"- Engine: {r['engine']} · model {r['model']} · {r['generated_at']}",
         f"- Files: {', '.join('`%s`' % f for f in r['files'])}", "", f"> {r['summary']}", "",
         "## Needs to change", "",
         "| File | Line | Issue | Change | Fix |", "|------|------|-------|--------|-----|"]
    for i in r["plan"]["items"]:
        L.append(f"| `{i['file']}` | {i['line']} | {i['title']} (`{i['rule_id']}`) | {i['change']} | {i['after']} |")
    L.append("")
    if r["diffs"]:
        L.append("## What changed (lib2to3 diff)")
        for path, diff in r["diffs"].items():
            L.append("")
            L.append(f"### `{path}`")
            L.append("```diff")
            L.append(diff.rstrip())
            L.append("```")
    L.append("")
    L.append("## Checklist")
    L += [f"- {c}" for c in r["plan"]["checklist"]]
    L.append("")
    L.append("## Test plan")
    L += [f"- {t}" for t in r["plan"]["test_plan"]]
    L.append("")
    L.append("## Risks")
    L += [f"- {x}" for x in r["plan"]["risks"]]
    return "\n".join(L) + "\n"


def render_html(r: dict) -> str:
    e = html.escape
    rows = "".join(
        f"<tr><td><code>{e(i['file'])}</code></td><td>{i['line']}</td><td>{e(i['title'])}</td>"
        f"<td><code>{e(i['rule_id'])}</code></td><td><span class='chg {i['change']}'>{i['change']}</span></td>"
        f"<td><code>{e(i['after'])}</code></td><td class='muted'>{e(i['explanation'])}</td></tr>"
        for i in r["plan"]["items"])
    diffs = "".join(
        f"<h3><code>{e(p)}</code></h3><pre class='diff'>{_diff_html(d)}</pre>"
        for p, d in r["diffs"].items())
    checklist = "".join(f"<li>{e(c)}</li>" for c in r["plan"]["checklist"])
    tests = "".join(f"<li>{e(t)}</li>" for t in r["plan"]["test_plan"])
    risks = "".join(f"<li>{e(x)}</li>" for x in r["plan"]["risks"])
    trace = "".join(f"<li>{e(t)}</li>" for t in r["trace"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Py2→Py3 migration — Legacy Sentinel</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:24px}}
.wrap{{max-width:1050px;margin:0 auto}} h1{{font-size:22px}} h2{{border-bottom:1px solid #30363d;padding-bottom:6px;margin-top:26px}}
.muted{{color:#8b949e;font-size:12px}} code{{background:#161b22;padding:1px 5px;border-radius:4px;font-size:12px}}
table{{border-collapse:collapse;width:100%;font-size:13px}} td,th{{border:1px solid #30363d;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#161b22}} .chg{{border-radius:8px;padding:1px 8px;font-size:11px}} .chg.auto{{background:#123a1d;color:#46a758}}
.chg.review{{background:#3a2d12;color:#ffc53d}} .chg.manual{{background:#3a1d1d;color:#e5484d}}
pre.diff{{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:10px;overflow:auto;font-size:12px;line-height:1.45}}
pre.diff .add{{color:#3fb950}} pre.diff .del{{color:#f85149}} pre.diff .hdr{{color:#58a6ff}} pre.diff .ctx{{color:#8b949e}}
ul{{font-size:13px}} .meta{{color:#8b949e;font-size:13px}}
</style></head><body><div class="wrap">
<h1>🔄 Python 2 → 3 migration report</h1>
<div class="meta">Target <code>{e(r['target'])}</code> · engine {e(r['engine'])} · model {e(r['model'])} · {e(r['generated_at'])}</div>
<p>{e(r['summary'])}</p>
<h2>Needs to change ({len(r['plan']['items'])} items)</h2>
<table><tr><th>File</th><th>Line</th><th>Issue</th><th>Rule</th><th>Change</th><th>Fix</th><th>Notes</th></tr>{rows}</table>
<h2>What changed (automated diff)</h2>
{diffs or '<p class="muted">No mechanical changes required.</p>'}
<h2>Checklist</h2><ul>{checklist}</ul>
<h2>Test plan</h2><ul>{tests}</ul>
<h2>Risks</h2><ul>{risks}</ul>
<h2>Trace</h2><ul>{trace}</ul>
<p class="muted">Legacy Sentinel · read-only (diffs computed on copies; sources never modified) · secrets redacted</p>
</div></body></html>"""


def write_reports(r: dict, out_dir: str, log=print) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "migration.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
    (out / "migration.md").write_text(render_md(r), encoding="utf-8")
    (out / "index.html").write_text(render_html(r), encoding="utf-8")
    log(f"  migration reports written to {out}/ (migration.json, migration.md, index.html)")
