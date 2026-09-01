import json
import shutil
import subprocess
from pathlib import Path
from typing import Sequence

from kitelon_engine.context import ScanContext


def which(name: str) -> str | None:
    return shutil.which(name)


def run_cmd(
    args: Sequence[str],
    *,
    timeout: int = 3600,
    cwd: str | None = None,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
        check=check,
    )


def tool_path(ctx: ScanContext, name: str, skip_log: str) -> str | None:
    path = which(name)
    if not path:
        ctx.log(skip_log)
    return path


def hostname_from_url(value: str, fallback: str = "") -> str:
    host = value.split("://")[-1].split("/")[0].split(":")[0]
    return host or fallback


def iter_json_lines(path: Path):
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue
