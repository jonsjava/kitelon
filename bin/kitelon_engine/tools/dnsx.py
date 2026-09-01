

import json
from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.tools.base import iter_json_lines, run_cmd, tool_path


def resolve_hosts(ctx: ScanContext, hosts: list[str], output: Path) -> list[str]:
    dnsx = tool_path(ctx, "dnsx", "dnsx not found, skip")
    if not dnsx or not hosts:
        return hosts

    input_file = output.with_suffix(".in.txt")
    input_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    json_out = output.with_suffix(".json")
    args = [
        dnsx,
        "-l",
        str(input_file),
        "-json",
        "-o",
        str(json_out),
        "-silent",
    ]
    ctx.log(f"validating {len(hosts)} host(s) with dnsx")
    run_cmd(args, timeout=600)
    output.parent.mkdir(parents=True, exist_ok=True)
    live: list[str] = []
    if json_out.is_file():
        output.write_text(json_out.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
        for row in iter_json_lines(json_out):
            host = row.get("host") or row.get("domain")
            if host:
                live.append(str(host).lower())
    live_hosts_file = output.parent / "live_hosts.json"
    live_hosts_file.write_text(
        json.dumps({"hosts": sorted(set(live))}, indent=2),
        encoding="utf-8",
    )
    return sorted(set(live)) or hosts
