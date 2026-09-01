

import json
from pathlib import Path
from typing import Any

from kitelon_engine.context import ScanContext
from kitelon_engine.tools.base import run_cmd, which


def run_webtech(ctx: ScanContext, url: str, output: Path) -> bool:
    webtech = which("webtech")
    if not webtech:
        ctx.log("webtech not found, skip tech fingerprint")
        return False

    args = [webtech, "-u", url, "--json"]
    ctx.log(f"running webtech on {url}")
    proc = run_cmd(args, timeout=180)
    output.parent.mkdir(parents=True, exist_ok=True)
    text = (proc.stdout or proc.stderr or "").strip()
    if text:
        output.write_text(text, encoding="utf-8")
    return output.is_file() and output.stat().st_size > 0


def parse_webtech_json(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    techs: list[dict[str, Any]] = []
    if isinstance(data, dict):
        for name, info in data.get("tech", {}).items():
            versions = []
            if isinstance(info, dict):
                versions = info.get("version", []) or []
            techs.append({"name": name, "versions": versions})
    return techs
