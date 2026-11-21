from __future__ import annotations

import html
import json
from pathlib import Path

from .schemas import SEVERITY_ORDER

SEV_COLOR = {"critical": "#e5484d", "high": "#f76b15", "medium": "#ffc53d", "low": "#46a758", "info": "#6e7681"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def write_all(data: dict, out_dir: str, log=print) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": out / "report.json",
        "sarif": out / "report.sarif",
        "md": out / "report.md",
        "html": out / "index.html",
    }
    paths["json"].write_text(json.dumps(data, indent=2), encoding="utf-8")
    paths["sarif"].write_text(render_sarif(data), encoding="utf-8")
    paths["md"].write_text(render_md(data), encoding="utf-8")
    paths["html"].write_text(render_html(data), encoding="utf-8")
    log(f"  reports written to {out}/ (report.json, report.sarif, report.md, index.html)")
    return {k: str(v) for k, v in paths.items()}


def render_sarif(data: dict) -> str:
    results = []
    for f in data["findings"]:
        results.append({
            "ruleId": f["rule_id"],
            "level": SARIF_LEVEL.get(f["severity"], "note"),
            "message": {"text": f"{f['title']} — {f['description']} (confidence: {f['confidence']}, source: {f['source']})"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f["file"]},
                "region": {"startLine": f["line"], "snippet": {"text": f["evidence"]}},
            }}],
            "properties": {"cwe": f["cwe"], "severity": f["severity"], "confidence": f["confidence"], "id": f["id"]},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Legacy Sentinel", "version": "0.1.0",
                               "informationUri": "https://mistral.ai", "rules": []}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


def render_md(data: dict) -> str:
    L = []
    L.append(f"# Legacy Sentinel — security report")
    L.append("")
    L.append(f"- **Target:** `{data['target']}`")
    L.append(f"- **Engine:** {data['engine']} · **Model:** {data['model']}")
    L.append(f"- **Files scanned:** {data['scanned_files']} · **Languages:** {', '.join(data['languages'])}")
    L.append(f"- **Generated:** {data['generated_at']}")

    L.append("")
    L.append(f"> {data['summary']}")
    L.append("")
    L.append("## Findings")
    L.append("")
    rems = {r["finding_id"]: r for r in data["remediations"]}
    for f in sorted(data["findings"], key=lambda x: SEVERITY_ORDER.get(x["severity"], 9)):
        L.append(f"### [{f['severity'].upper()}] {f['title']} — `{f['cwe']}`")
        L.append(f"- **Where:** `{f['file']}:{f['line']}` · confidence {f['confidence']} · source {f['source']}")
        L.append(f"- **Evidence:** `{f['evidence']}`")
        L.append(f"- **Why it matters:** {f['description']}")
        r = rems.get(f["id"])
        if r:
            L.append(f"- **Fix:** {r['summary']}")
            for i, s in enumerate(r.get("steps", []), 1):
                L.append(f"  {i}. {s}")
            if r.get("patch"):
                L.append("  ```diff")
                L.append("  " + r["patch"].replace("\n", "\n  "))
                L.append("  ```")
        L.append("")
    m = data["migration"]
    L.append("## Migration plan")
    L.append("")
    L.append(f"**Strategy:** {m['strategy']}")
    L.append("")
    L.append(f"{m['summary']}")
    L.append("")
    if m.get("quick_wins"):
        L.append("**Quick wins:**")
        for q in m["quick_wins"]:
            L.append(f"- {q}")
        L.append("")
    L.append("**Phases:**")
    for p in m.get("phases", []):
        L.append(f"- {p}")
    L.append("")
    if m.get("modules"):
        L.append("| # | Component | Current | Target | Effort | Risk |")
        L.append("|---|-----------|---------|--------|--------|------|")
        for mod in sorted(m["modules"], key=lambda x: x["order"]):
            L.append(f"| {mod['order']} | {mod['component']} | {mod['current']} | {mod['target']} | {mod['effort']} | {mod['risk']} |")
        L.append("")
    if data.get("trace"):
        L.append("## Agent trace")
        L.append("")
        for t in data["trace"]:
            L.append(f"- {t}")
    return "\n".join(L) + "\n"


def render_html(data: dict) -> str:
    e = html.escape
    counts: dict[str, int] = {}
    for f in data["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    cards = "".join(
        f'<span class="stat" style="border-color:{SEV_COLOR[s]}"><b>{counts.get(s, 0)}</b> {s}</span>'
        for s in ("critical", "high", "medium", "low", "info"))
    rems = {r["finding_id"]: r for r in data["remediations"]}
    finding_html = []
    for f in sorted(data["findings"], key=lambda x: SEVERITY_ORDER.get(x["severity"], 9)):
        r = rems.get(f["id"])
        cwe_num = f["cwe"].split("-")[-1] if "-" in f["cwe"] else ""
        steps = "".join(f"<li>{e(s)}</li>" for s in (r or {}).get("steps", []))
        tests = "".join(f"<li>{e(t)}</li>" for t in (r or {}).get("tests", []))
        refs = "".join(f'<li><a href="{e(u)}">{e(u)}</a></li>' for u in (r or {}).get("references", []))
        patch = (r or {}).get("patch", "")
        finding_html.append(f"""
        <details class="finding" open>
          <summary>
            <span class="badge" style="background:{SEV_COLOR.get(f['severity'], '#888')}">{e(f['severity'])}</span>
            <b>{e(f['title'])}</b>
            <a class="cwe" href="https://cwe.mitre.org/data/definitions/{cwe_num}.html">{e(f['cwe'])}</a>
            <code>{e(f['file'])}:{f['line']}</code>
            <span class="muted">{e(f['source'])} · conf {e(f['confidence'])}</span>
          </summary>
          <pre class="evidence">{e(f['evidence'])}</pre>
          <p>{e(f['description'])}</p>
          {f'<div class="rem"><h4>Remediation — {e(r["summary"])}</h4><ol>{steps}</ol>' if r else ''}
          {f'<pre class="patch">{e(patch)}</pre>' if patch else ''}
          {f'<h4>Tests</h4><ul>{tests}</ul>' if tests else ''}
          {f'<h4>References</h4><ul>{refs}</ul>' if refs else ''}
          {'</div>' if r else ''}
        </details>""")
    mods = "".join(
        f"<tr><td>{m['order']}</td><td>{e(m['component'])}</td><td>{e(m['current'])}</td><td>{e(m['target'])}</td>"
        f"<td>{e(m['effort'])}</td><td>{e(m['risk'])}</td></tr>"
        for m in sorted(data["migration"].get("modules", []), key=lambda x: x["order"]))
    phases = "".join(f"<li>{e(p)}</li>" for p in data["migration"].get("phases", []))
    qw = "".join(f"<li>{e(q)}</li>" for q in data["migration"].get("quick_wins", []))
    trace = "".join(f"<li>{e(t)}</li>" for t in data.get("trace", []))
    
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Legacy Sentinel — report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:24px}}
 .wrap{{max-width:1000px;margin:0 auto}}
 h1{{font-size:22px}} h2{{margin-top:28px;border-bottom:1px solid #30363d;padding-bottom:6px}}
 .muted{{color:#8b949e;font-size:12px}} code{{background:#161b22;padding:1px 5px;border-radius:4px;font-size:12px}}
 .stats{{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}}
 .stat{{border:1px solid #30363d;border-radius:8px;padding:8px 14px;font-size:13px}}
 .finding{{border:1px solid #30363d;border-radius:8px;margin:10px 0;padding:10px 14px;background:#161b22}}
 .finding summary{{cursor:pointer;display:flex;gap:10px;align-items:center;flex-wrap:wrap}}
 .badge{{color:#fff;border-radius:10px;padding:2px 10px;font-size:11px;text-transform:uppercase}}
 .cwe{{color:#58a6ff;font-size:12px}} .evidence{{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:8px;overflow:auto;color:#ffa198}}
 .patch{{background:#0d1117;border:1px solid #238636;border-radius:6px;padding:8px;overflow:auto;color:#a5d6a7}}
 .rem h4{{margin:10px 0 4px;font-size:13px}} .rem ol,.rem ul{{margin:4px 0 8px 18px;font-size:13px;color:#c9d1d9}}
 a{{color:#58a6ff}} table{{border-collapse:collapse;width:100%;font-size:13px}}
 td,th{{border:1px solid #30363d;padding:6px 8px;text-align:left}} th{{background:#161b22}}
 .meta{{color:#8b949e;font-size:13px}} pre.trace{{font-size:12px;color:#8b949e}}
</style></head><body><div class="wrap">
<h1>🛡 Legacy Sentinel — security report</h1>
<div class="meta">Target <code>{e(data['target'])}</code> · engine {e(data['engine'])} · model {e(data['model'])} ·
{e(str(data['scanned_files']))} files · {e(', '.join(data['languages']))} · {e(data['generated_at'])}</div>
<p>{e(data['summary'])}</p>
<div class="stats">{cards}</div>
<h2>Findings ({len(data['findings'])})</h2>
{''.join(finding_html)}
<h2>Migration plan</h2>
<p><b>Strategy:</b> {e(data['migration']['strategy'])}</p>
<p>{e(data['migration']['summary'])}</p>
<h3>Quick wins</h3><ul>{qw}</ul>
<h3>Phases</h3><ol>{phases}</ol>
<h3>Modules</h3><table><tr><th>#</th><th>Component</th><th>Current</th><th>Target</th><th>Effort</th><th>Risk</th></tr>{mods}</table>
<h2>Agent trace</h2><pre class="trace">{trace}</pre>
<p class="muted">Generated by Legacy Sentinel · Mistral Large 4 (agentic) ·  secrets redacted before analysis · read-only scan</p>
</div></body></html>"""
