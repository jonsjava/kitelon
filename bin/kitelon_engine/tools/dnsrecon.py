import json
from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.tools.base import run_cmd, tool_path


def dnsrecon_types(axfr: bool) -> str:
    types = ["std", "srv", "brt"]
    if axfr:
        types.append("axfr")
    return ",".join(types)


def build_dnsrecon_args(
    binary: str,
    domain: str,
    output_json: Path,
    *,
    axfr: bool = False,
) -> list[str]:
    return [
        binary,
        "-d",
        domain,
        "-t",
        dnsrecon_types(axfr),
        "-j",
        str(output_json),
    ]


def run_dnsrecon(ctx: ScanContext, domain: str, output_json: Path) -> bool:
    binary = tool_path(ctx, "dnsrecon", "dnsrecon not found, skip")
    if not binary:
        return False

    axfr = bool(ctx.options.get("dnsrecon_axfr"))
    timeout = int(ctx.options.get("dnsrecon_timeout", 300))
    args = build_dnsrecon_args(binary, domain, output_json, axfr=axfr)
    ctx.log(f"running dnsrecon on {domain}")
    output_json.parent.mkdir(parents=True, exist_ok=True)
    proc = run_cmd(args, timeout=timeout)
    if proc.returncode != 0 and not output_json.is_file():
        ctx.log(f"dnsrecon exited {proc.returncode}")
        return False
    if output_json.is_file():
        return True
    payload = {"domain": domain, "stdout": proc.stdout[-8000:], "stderr": proc.stderr[-2000:]}
    output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return proc.returncode == 0
