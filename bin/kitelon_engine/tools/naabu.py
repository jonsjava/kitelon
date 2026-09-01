

from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.tools.base import iter_json_lines, run_cmd, tool_path


def run_naabu(ctx: ScanContext, host: str, output: Path, *, top_ports: int = 1000) -> list[int]:
    naabu = tool_path(ctx, "naabu", "naabu not found, skip fast port discovery")
    if not naabu:
        return []

    json_out = output.with_suffix(".json")
    args = [
        naabu,
        "-host",
        host,
        "-top-ports",
        str(top_ports),
        "-json",
        "-o",
        str(json_out),
        "-silent",
    ]
    ctx.log(f"running naabu on {host}")
    run_cmd(args, timeout=1800)
    output.parent.mkdir(parents=True, exist_ok=True)
    ports: list[int] = []
    if json_out.is_file():
        output.write_text(json_out.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
        for row in iter_json_lines(json_out):
            port = row.get("port")
            if port:
                try:
                    ports.append(int(port))
                except (TypeError, ValueError):
                    continue
    return sorted(set(ports))
