from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import migrate as migrate_mod
from . import prompts, scanner, voxtral

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
SAMPLES = ROOT / "samples"
REPORTS = ROOT / "reports"
MAX_BODY = 30 * 1024 * 1024
LAST = {"scan": None, "migrate": None}


def _silent(*a) -> None:
    pass


def _sample_files(kind: str) -> list[dict]:
    dirs = [SAMPLES / "python2"] if kind == "py2" else [SAMPLES / "cobol", SAMPLES / "php", SAMPLES / "python"]
    out = []
    for d in dirs:
        for p in sorted(d.rglob("*")):
            if p.is_file():
                out.append({"name": str(p.relative_to(SAMPLES)), "content": p.read_text(encoding="utf-8", errors="replace")})
    return out


def _safe_path(p: str) -> Path:
    base = (ROOT / p).resolve()
    if str(base) != str(ROOT.resolve()) and not str(base).startswith(str(ROOT.resolve()) + os.sep):
        raise ValueError("path outside project root")
    return base


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def _send(self, body: bytes, ctype: str = "application/json", code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(json.dumps(obj).encode(), "application/json", code)

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("request body too large (max 30MB)")
        return self.rfile.read(n)

    def do_GET(self) -> None:
        u = urlparse(self.path)
        try:
            if u.path == "/":
                self._send((WEB / "marketing.html").read_bytes(), "text/html; charset=utf-8")
            elif u.path == "/app":
                self._send((WEB / "index.html").read_bytes(), "text/html; charset=utf-8")
            elif u.path == "/one-pager.pdf":
                self._send((WEB / "one-pager.pdf").read_bytes(), "application/pdf")
            elif u.path == "/api/health":
                sdk = True
                try:
                    import mistralai.agents  # noqa: F401
                except Exception:
                    sdk = False
                self._json({"ok": True, "model": prompts.MODEL,
                            "has_api_key": bool(os.environ.get("MISTRAL_API_KEY")), "agents_sdk": sdk})
            elif u.path == "/api/samples":
                kind = parse_qs(u.query).get("kind", ["legacy"])[0]
                self._json({"files": _sample_files(kind)})
            elif u.path == "/api/export":
                q = parse_qs(u.query)
                kind = q.get("kind", ["scan"])[0]
                fmt = q.get("fmt", ["json"])[0]
                base = LAST.get(kind)
                if not base:
                    self._json({"error": "no report yet"}, 404)
                    return
                names = {"scan": {"json": "report.json", "md": "report.md", "sarif": "report.sarif", "html": "index.html"},
                         "migrate": {"json": "migration.json", "md": "migration.md", "html": "index.html"}}
                ctypes = {"json": "application/json", "sarif": "application/json", "md": "text/markdown; charset=utf-8",
                          "html": "text/html; charset=utf-8"}
                self._send((Path(base) / names[kind][fmt]).read_bytes(), ctypes[fmt])
            else:
                self._json({"error": "not found"}, 404)
        except Exception as e:
            self._json({"error": str(e)}, 500)

    def do_POST(self) -> None:
        try:
            p = urlparse(self.path).path
            body = json.loads(self._body() or b"{}")
            key = os.environ.get("MISTRAL_API_KEY", "")
            if p == "/api/scan":
                files = scanner.collect_from_payload(body["files"]) if body.get("files") else scanner.collect_from_path(_safe_path(body.get("path", "samples")))
                out = REPORTS / f"web_scan_{int(time.time())}"
                data = scanner.run_scan(body.get("path", "upload"), files, engine=body.get("engine", "auto"),
                                        out_dir=str(out), voice_command=body.get("voice_command"), log=_silent)
                LAST["scan"] = str(out)
                self._json(data)
            elif p == "/api/voice":
                if not key:
                    self._json({"error": "MISTRAL_API_KEY not set on server"}, 400)
                    return
                audio = voxtral.b64_to_bytes(body["audio_b64"])
                t = voxtral.transcribe(key, audio, body.get("filename", "cmd.webm"))
                intent = voxtral.parse_command(t)
                files = scanner.collect_from_payload(body["files"]) if body.get("files") else scanner.collect_from_path(SAMPLES)
                out = REPORTS / f"web_voice_{int(time.time())}"
                data = scanner.run_scan("voice-command", files, engine=body.get("engine", "auto"),
                                        out_dir=str(out), voice_command=t, log=_silent)
                LAST["scan"] = str(out)
                self._json({"transcript": t, "intent": intent, "report": data})
            elif p == "/api/speak":
                if not key:
                    self._json({"error": "MISTRAL_API_KEY not set on server"}, 400)
                    return
                wav = voxtral.speak(key, str(body.get("text", ""))[:2000])
                self._send(wav, "audio/wav")
            elif p == "/api/migrate":
                files = scanner.collect_from_payload(body["files"]) if body.get("files") else scanner.collect_from_path(_safe_path(body.get("path", "samples/python2")))
                out = REPORTS / f"web_migrate_{int(time.time())}"
                res = migrate_mod.run_migration(body.get("path", "upload"), files, engine=body.get("engine", "auto"),
                                                out_dir=str(out), log=_silent)
                LAST["migrate"] = str(out)
                self._json(res)
            else:
                self._json({"error": "not found"}, 404)
        except Exception as e:
            self._json({"error": str(e)}, 500)


def serve(host: str, port: int) -> None:
    REPORTS.mkdir(exist_ok=True)
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"Legacy Sentinel web demo → http://{host}:{port}  (loopback only — Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
