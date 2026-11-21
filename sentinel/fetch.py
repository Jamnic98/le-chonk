from __future__ import annotations

import shutil
import subprocess
import tempfile


def is_repo_url(target: str) -> bool:
    return target.strip().startswith(("http://", "https://", "git@", "ssh://"))


def resolve_target(target: str) -> tuple[str, object | None]:
    if not is_repo_url(target):
        return target, None
    tmp = tempfile.mkdtemp(prefix="sentinel-clone-")
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", target.strip(), tmp],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        raise SystemExit(f"git clone failed for {target}:\n{proc.stderr.strip()}")
    return tmp, lambda: shutil.rmtree(tmp, ignore_errors=True)
