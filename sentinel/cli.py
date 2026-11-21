from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_env() -> None:
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def _key() -> str:
    return os.environ.get("MISTRAL_API_KEY", "")


def _print_summary(data: dict) -> None:
    from .schemas import SEVERITY_ORDER
    counts: dict[str, int] = {}
    for f in data["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    order = sorted(counts.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))
    print(f"\n=== Legacy Sentinel report: {data['target']} ===")
    print(f"engine={data['engine']}  model={data['model']}  files={data['scanned_files']}  languages={','.join(data['languages'])}")
    print("findings:", ", ".join(f"{v} {k}" for k, v in order) or "none")
    print("summary:", data["summary"])
    if data.get("voice_command"):
        print("voice command (Voxtral):", data["voice_command"])
    print("\ntop findings:")
    for f in sorted(data["findings"], key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))[:8]:
        print(f"  [{f['severity']:8}] {f['cwe']} {f['title']} — {f['file']}:{f['line']}")
        print(f"             {f['evidence'][:130]}")
    if data.get("trace"):
        print("\nagent trace:")
        for t in data["trace"]:
            print("  -", t)


def cmd_scan(a) -> None:
    from . import scanner
    files = scanner.collect_from_path(a.path)
    if not files:
        print("no supported files found (cobol/php/python)")
        sys.exit(2)
    data = scanner.run_scan(a.path, files, engine=a.engine, out_dir=a.out, log=print)
    _print_summary(data)


def cmd_demo(a) -> None:
    a.path = str(ROOT / "samples")
    a.out = a.out or str(ROOT / "reports" / "demo")
    cmd_scan(a)


def cmd_migrate(a) -> None:
    from . import migrate, scanner
    files = scanner.collect_from_path(a.path)
    if not files:
        print("no python files found")
        sys.exit(2)
    res = migrate.run_migration(a.path, files, engine=a.engine, out_dir=a.out, log=print)
    print(f"\n=== Py2→Py3 migration workflow: {res['target']} ===")
    print("engine:", res["engine"], " model:", res["model"])
    print(res["summary"])
    print(f"\nneeds to change — {len(res['issues'])} constructs:")
    for i in res["issues"][:12]:
        print(f"  {i['file']}:{i['line']} [{i['change']:6}] {i['title']:32} {i['evidence'][:70]}")
    print(f"\nwhat changed — lib2to3 diffs for {len(res['diffs'])} file(s):")
    for p, d in res["diffs"].items():
        added = sum(1 for l in d.splitlines() if l.startswith("+") and not l.startswith("+++"))
        removed = sum(1 for l in d.splitlines() if l.startswith("-") and not l.startswith("---"))
        print(f"  {p}: +{added} / -{removed}")
    for t in res["trace"]:
        print("  trace:", t)


def cmd_voice(a) -> None:
    from . import scanner, voxtral
    key = _key()
    if not key:
        print("MISTRAL_API_KEY not set (put it in .env or the environment); cannot transcribe")
        sys.exit(2)
    audio = Path(a.audio).read_bytes()
    t = voxtral.transcribe(key, audio, Path(a.audio).name)
    print("Voxtral transcript:", t)
    intent = voxtral.parse_command(t)
    print("parsed intent:", intent)
    files = scanner.collect_from_path(a.dir)
    out = a.out or str(ROOT / "reports" / "voice")
    data = scanner.run_scan(a.dir, files, engine=a.engine, out_dir=out, voice_command=t, log=print)
    _print_summary(data)
    if a.speak_summary:
        wav = voxtral.speak(key, data["summary"])
        p = Path(out) / "summary.wav"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(wav)
        print("spoken summary (Voxtral TTS):", p)


def cmd_make_voice_demo(a) -> None:
    from . import voxtral
    key = _key()
    if not key:
        print("MISTRAL_API_KEY not set")
        sys.exit(2)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(voxtral.speak(key, voxtral.VOICE_DEMO_TEXT))
    print("wrote", out)


def cmd_selftest(a) -> None:
    from . import migrate, scanner
    samples = ROOT / "samples"
    files = scanner.collect_from_path(samples)
    data = scanner.run_scan(str(samples), files, engine="offline", out_dir=str(ROOT / "reports" / "selftest"), log=lambda *x: None)
    by_lang: dict[str, int] = {}
    for f in data["findings"]:
        lang = "cobol" if f["file"].endswith((".cbl", ".cob", ".cpy")) else ("php" if f["file"].endswith(".php") else "python")
        by_lang[lang] = by_lang.get(lang, 0) + 1
    ok = True
    for lang in ("cobol", "php", "python"):
        n = by_lang.get(lang, 0)
        good = n >= 2
        ok = ok and good
        print(f"  {lang}: {n} findings {'OK' if good else 'FAIL'}")
    py2 = scanner.collect_from_path(ROOT / "samples" / "python2")
    issues = migrate.detect_py2(py2)
    good = len(issues) >= 8
    ok = ok and good
    print(f"  py2 constructs detected: {len(issues)} {'OK' if good else 'FAIL'}")
    diffs = 0
    for f in py2:
        _, d = migrate.run_2to3(f["path"], f["text"])
        if d:
            diffs += 1
    good = diffs >= 2
    ok = ok and good
    print(f"  2to3 diffs: {diffs} file(s) {'OK' if good else 'FAIL'}")
    print("SELFTEST", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


def cmd_serve(a) -> None:
    from . import webapp
    webapp.serve(a.host, a.port)


def main(argv=None) -> None:
    _load_env()
    p = argparse.ArgumentParser(prog="sentinel", description="Legacy Sentinel — agentic legacy-code security scanner & migration advisor (COBOL/PHP/Python)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a file or directory")
    s.add_argument("path")
    s.add_argument("--engine", default="auto", choices=["auto", "sdk", "direct", "offline"])
    s.add_argument("--out", default=None)
    s.set_defaults(fn=cmd_scan)

    d = sub.add_parser("demo", help="scan the bundled sample codebases")
    d.add_argument("--engine", default="auto", choices=["auto", "sdk", "direct", "offline"])
    d.add_argument("--out", default=None)
    d.set_defaults(fn=cmd_demo)

    m = sub.add_parser("migrate", help="Python 2 -> 3 migration workflow (needs-to-change + what-changed report)")
    m.add_argument("path")
    m.add_argument("--engine", default="auto", choices=["auto", "direct", "offline"])
    m.add_argument("--out", default=None)
    m.set_defaults(fn=cmd_migrate)

    v = sub.add_parser("voice", help="transcribe a voice command with Voxtral and execute it")
    v.add_argument("audio")
    v.add_argument("--dir", default=str(ROOT / "samples"))
    v.add_argument("--engine", default="auto", choices=["auto", "sdk", "direct", "offline"])
    v.add_argument("--out", default=None)
    v.add_argument("--speak-summary", action="store_true")
    v.set_defaults(fn=cmd_voice)

    mv = sub.add_parser("make-voice-demo", help="synthesize the demo voice command with Voxtral TTS")
    mv.add_argument("--out", default=str(ROOT / "reports" / "voice_command.wav"))
    mv.set_defaults(fn=cmd_make_voice_demo)

    st = sub.add_parser("selftest", help="offline self test (no API key needed)")
    st.set_defaults(fn=cmd_selftest)

    sv = sub.add_parser("serve", help="run the web demo UI (loopback only)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.set_defaults(fn=cmd_serve)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
