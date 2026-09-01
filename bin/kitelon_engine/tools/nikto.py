

import json
import re
from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.findings import FindingWriter
from kitelon_engine.tools.base import hostname_from_url, run_cmd, tool_path


def run_nikto(ctx: ScanContext, url: str, output: Path) -> bool:
    nikto = tool_path(ctx, "nikto", "nikto not found, skip")
    if not nikto:
        return False

    output.parent.mkdir(parents=True, exist_ok=True)
    json_out = output.with_suffix(".json")
    args = [nikto, "-h", url, "-Format", "json", "-output", str(json_out), "-nointeractive"]
    ctx.log(f"running nikto on {url}")
    run_cmd(args, timeout=3600)
    if json_out.is_file():
        output.write_text(json_out.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
        _import_nikto_json(ctx, url, json_out)
        return True

    text_out = output.with_suffix(".txt")
    args = [nikto, "-h", url, "-output", str(text_out), "-nointeractive"]
    run_cmd(args, timeout=3600)
    if text_out.is_file():
        output.write_text(text_out.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
        _import_nikto_text(ctx, url, text_out)
        return True
    return False


def _import_nikto_json(ctx: ScanContext, url: str, path: Path) -> None:
    host = hostname_from_url(url)
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return
    writer = FindingWriter(ctx.findings_path)
    items = data if isinstance(data, list) else data.get("vulnerabilities", [])
    for item in items:
        if not isinstance(item, dict):
            continue
        msg = str(item.get("msg") or item.get("message") or "").strip()
        if not msg:
            continue
        writer.emit_kv(
            severity="medium",
            name=f"nikto: {msg[:180]}",
            hostname=host,
            url=url,
            evidence=msg,
            source="nikto",
            source_file=str(path.name),
        )


def _import_nikto_text(ctx: ScanContext, url: str, path: Path) -> None:
    host = hostname_from_url(url)
    writer = FindingWriter(ctx.findings_path)
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "+ " not in line and "OSVDB" not in line:
            continue
        msg = re.sub(r"^\s*\+?\s*", "", line.strip())
        if len(msg) < 8:
            continue
        writer.emit_kv(
            severity="medium",
            name=f"nikto: {msg[:180]}",
            hostname=host,
            url=url,
            evidence=msg,
            source="nikto",
            source_file=str(path.name),
        )
