

from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.tools.base import run_cmd, tool_path


def probe_tls(ctx: ScanContext, host: str, port: int, output: Path) -> bool:
    tlsx = tool_path(ctx, "tlsx", "tlsx not found, skip TLS probe")
    if not tlsx:
        return False

    target = f"{host}:{port}"
    args = [tlsx, "-u", target, "-json", "-silent"]
    ctx.log(f"running tlsx on {target}")
    proc = run_cmd(args, timeout=120)
    output.parent.mkdir(parents=True, exist_ok=True)
    text = proc.stdout.strip()
    if text:
        output.write_text(text, encoding="utf-8")
    return output.is_file() and output.stat().st_size > 0
