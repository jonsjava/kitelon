

import json
from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.tools.base import run_cmd, which


def enumerate_subdomains(ctx: ScanContext, domain: str, output: Path) -> list[str]:
    subfinder = which("subfinder")
    if not subfinder:
        ctx.log("subfinder not found, skip subdomain enum")
        return [domain]

    args = [
        subfinder,
        "-d",
        domain,
        "-silent",
        "-o",
        str(output),
        "-t",
        str(ctx.threads),
    ]
    ctx.log(f"enumerating subdomains for {domain}")
    run_cmd(args, timeout=1800)
    output.parent.mkdir(parents=True, exist_ok=True)

    hosts: set[str] = {domain}
    if output.is_file():
        for line in output.read_text(errors="replace").splitlines():
            line = line.strip().lower()
            if line:
                hosts.add(line)

    json_out = output.with_suffix(".json")
    json_out.write_text(json.dumps(sorted(hosts), indent=2), encoding="utf-8")
    return sorted(hosts)
