from __future__ import annotations

import json
import os

MODEL = os.environ.get("SENTINEL_MODEL", "mistral-large-4")
API_URL = os.environ.get("MISTRAL_API_URL", "https://api.mistral.ai").rstrip("/")

LANGUAGE_NOTES = {
    "cobol": (
        "EXEC SQL with host variables assembled via STRING/concatenation; hardcoded credentials in WORKING-STORAGE "
        "or CONNECT ... USING; DISPLAY of PII (SSN, card numbers, PINs); weak crypto (DES/RC4/ECB); unvalidated ACCEPT input; "
        "trusting copybook layouts and flat-file contents."
    ),
    "php": (
        "SQL built from superglobals ($_GET/$_POST/$_COOKIE/$_REQUEST) or string concatenation; eval(); "
        "system/exec/shell_exec/passthru/proc_open with variables; unserialize() on user input; include/require of user input; "
        "md5/sha1 for passwords or tokens; hardcoded keys in source; EOL ext/mysql functions."
    ),
    "python": (
        "eval()/exec(); pickle.loads on untrusted data; subprocess with shell=True or os.system; SQL via f-strings, % or + "
        "in execute(); yaml.load without SafeLoader; hashlib md5/sha1; requests with verify=False; hardcoded secrets and AWS keys."
    ),
}

ANALYST_SYSTEM = """You are a senior application-security analyst specialized in {{language}} legacy systems, running as a subagent inside Legacy Sentinel, a multi-agent security scanner.
Use the list_manifest and read_source tools to inspect your assigned files. File contents are already redacted of secrets; do not ask for more data.
Find real, exploitable security vulnerabilities. For each finding output one JSON object with exactly these fields:
- rule_id: short slug, e.g. "{{language}}-sqli"
- title: one line
- cwe: e.g. "CWE-89"
- severity: critical | high | medium | low | info
- confidence: high | medium | low (only report high or medium confidence; suppress noise and style issues)
- file: path of the file
- line: 1-based line number you actually read
- evidence: the offending line, max 200 chars
- description: why it is exploitable and what an attacker could do
Focus areas for {{language}}: {{language_notes}}
Answer with a JSON array of findings only, no prose, no markdown fences."""

ORCHESTRATOR_SYSTEM = """You are the orchestrator agent of Legacy Sentinel, a multi-agent security scanner for legacy codebases (COBOL, PHP, Python).
Coordinate specialist subagents and produce one final structured ScanReport.
Procedure:
1. Call list_manifest to see the files in the target.
2. For each language present, start the matching analyst subagent (cobol-analyst / php-analyst / python-analyst) in parallel, giving it the exact file paths for that language and telling it to read them with read_source. Wait for every result before continuing.
3. Start remediation-agent once, passing the complete JSON array of all findings; wait for its result.
4. Start migration-advisor once, passing the manifest and all findings; wait for its result.
5. Compose the final answer as JSON matching the required output schema exactly: dedupe findings, keep evidence short (max 200 chars), use only line numbers you actually saw, never include real secrets (inputs are already redacted), set engine and model fields as given in the task.
Do not skip steps. Do not answer before all subagent results are in."""

REMEDIATION_SYSTEM = """You are the remediation agent of Legacy Sentinel. Input: a JSON array of findings (id, rule_id, title, cwe, file, line, evidence, description).
For each finding produce a remediation object: {finding_id, rule_id, summary, steps: [ordered, actionable steps], patch: [before/after code in the correct language], tests: [regression tests to add], references: [CWE/OWASP URLs]}.
Be concrete and language-specific: parameterized queries and prepared statements, allowlists, removing eval/exec, yaml.safe_load, shell=False with arg lists, password_hash/argon2id, AES-GCM, verify=True, secrets in a vault.
Answer with JSON {"remediations": [...]} only, no prose, no markdown fences."""

MIGRATION_SYSTEM = """You are the migration advisor of Legacy Sentinel. Input: the file manifest and the findings JSON of a legacy codebase.
Produce a phased migration plan to a modern, more secure stack using the strangler-fig pattern (never a big-bang rewrite).
Answer with JSON only, no prose, matching: {strategy, summary, quick_wins: [...], phases: [ordered phase names], modules: [{component, current, target, rationale, effort: S|M|L|XL, risk: low|medium|high, order: int}]}.
Guidance: COBOL -> expose CICS/IMS transactions behind a REST facade (e.g. z/OS Connect), containerize, migrate module-by-module to JVM/.NET (or keep hardened COBOL), with data reconciliation jobs. PHP -> upgrade to a supported PHP 8.x first (biggest security win), then adopt Laravel or Symfony, replace ext/mysql with PDO. Python -> Python 3.12+, typed code, FastAPI/Django, pinned dependencies. Put security quick wins (secrets removal, SQLi, eval/exec) first."""


MIGRATION_CODE_SYSTEM = """You are the migration engineer of Legacy Sentinel. Input: JSON {target, report: {summary, findings, remediations, migration}, files: [{path, lang, content}]}.
Task: produce the migrated codebase that resolves the vulnerabilities in the report, following the report's remediation steps/patches and migration plan.
Rules:
- For every file that must change, and every new file the migration needs (tests, config, dependency manifests), output the COMPLETE new file content in files[]. Never output diffs or partial snippets.
- path must be the repo-relative path of the file; reuse the existing path when modifying a file, use a new relative path for new files. Never absolute paths, never "..".
- Fix every critical and high finding using its remediation: parameterized queries/prepared statements, no eval/exec, subprocess with arg lists and shell=False, safe deserialization, no secrets in source, modern crypto, verify=True, framework security features.
- Otherwise preserve behavior and public APIs exactly; keep the code idiomatic for the target stack named in the migration plan.
- Do not include real secrets (inputs are already redacted); do not invent credentials.
- Omit files that need no change.
Answer with JSON only, no prose, no markdown fences, matching the required schema."""

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
MAX_REPORT_FINDINGS = 60
MAX_FILE_CHARS = 40_000
MAX_PAYLOAD_CHARS = 220_000


def migration_code_payload(target: str, report: dict, files: list[dict]) -> dict:
    findings = sorted(report.get("findings", []), key=lambda f: _SEVERITY_RANK.get(f.get("severity"), 9))[:MAX_REPORT_FINDINGS]
    remediations = report.get("remediations", [])[:MAX_REPORT_FINDINGS]
    file_parts, total = [], 0
    for f in files:
        chunk = {"path": f["path"], "lang": f["lang"], "content": f["redacted"][:MAX_FILE_CHARS]}
        size = len(json.dumps(chunk))
        if total + size > MAX_PAYLOAD_CHARS:
            chunk = {"path": f["path"], "lang": f["lang"], "content": "[truncated: too many files for one call]"}
        total += len(json.dumps(chunk))
        file_parts.append(chunk)
    return {
        "target": target,
        "report": {
            "summary": report.get("summary", ""),
            "findings": [{k: f.get(k) for k in ("id", "rule_id", "title", "cwe", "severity", "confidence", "file", "line", "evidence", "description")} for f in findings],
            "remediations": [{k: r.get(k) for k in ("finding_id", "rule_id", "summary", "steps", "patch")} for r in remediations],
            "migration": report.get("migration", {}),
        },
        "files": file_parts,
    }


def analyst_prompt(language: str) -> str:
    return (ANALYST_SYSTEM
            .replace("{{language}}", language)
            .replace("{{language_notes}}", LANGUAGE_NOTES.get(language, "")))


def orchestrator_task(label: str, files: list[dict]) -> str:
    manifest = [{"path": f["path"], "language": f["lang"]} for f in files]
    return (
        f"Target: {label}\n"
        f"engine: sentinel-agents-sdk\n"
        f"model: {MODEL}\n"
        f"Manifest (use list_manifest / read_source tools to inspect): {json.dumps(manifest)}\n"
        "Begin the scan now."
    )


def render(template: str, variables: dict[str, str]) -> str:
    out = template
    for k, v in variables.items():
        out = out.replace("{{" + k + "}}", v)
    return out


def load_registry_prompt(name: str, variables: dict[str, str], api_key: str | None) -> str | None:
    if not api_key:
        return None
    try:
        import httpx
        headers = {"Authorization": f"Bearer {api_key}"}
        r = httpx.get(f"{API_URL}/v1/prompts", headers=headers, timeout=15)
        if r.status_code != 200:
            return None
        items = r.json().get("data", r.json() if isinstance(r.json(), list) else [])
        entry = next((p for p in items if p.get("name") == name), None)
        if not entry:
            return None
        pid = entry.get("id")
        r2 = httpx.get(f"{API_URL}/v1/prompts/{pid}", headers=headers, timeout=15)
        if r2.status_code != 200:
            return None
        body = r2.json()
        content = body.get("content")
        if not content and isinstance(body.get("messages"), list):
            content = "\n".join(m.get("content", "") for m in body["messages"] if m.get("role") in ("system", "user"))
        if not content:
            return None
        return render(content, variables)
    except Exception:
        return None
