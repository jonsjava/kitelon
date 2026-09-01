

from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.tools.base import run_cmd, tool_path


def probe_url(ctx: ScanContext, url: str, output: Path) -> bool:
    httpx = tool_path(ctx, "httpx", "httpx not found, skip HTTP probe")
    if not httpx:
        return False

    args = [
        httpx,
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-follow-redirects",
        "-no-color",
        "-u",
        url,
        "-o",
        str(output),
    ]
    ctx.log(f"probing {url}")
    proc = run_cmd(args, timeout=120)
    output.parent.mkdir(parents=True, exist_ok=True)
    if proc.stdout.strip():
        output.write_text(proc.stdout, encoding="utf-8")
    return proc.returncode == 0
