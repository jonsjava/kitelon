from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.tools.base import run_cmd, which


def vulners_available() -> bool:
    for path in (
        Path("/usr/share/nmap/scripts/vulners.nse"),
        Path("/usr/local/share/nmap/scripts/vulners.nse"),
    ):
        if path.is_file():
            return True
    return False


def port_scan(
    ctx: ScanContext,
    host: str,
    output_xml: Path,
    *,
    ports: str = "1-10000",
    fast: bool = False,
    os_detect: bool = False,
    vulners: bool = False,
) -> bool:
    nmap = which("nmap")
    if not nmap:
        ctx.log("nmap not found, skip port scan")
        return False

    args = [nmap, "-Pn", "-sV", "-sC", "-oX", str(output_xml)]
    if fast:
        args.extend(["-T4", "-F"])
    else:
        args.append("-T3")

    if os_detect and not fast:
        args.extend(["-O", "--osscan-guess"])

    if vulners and not fast:
        if vulners_available():
            args.extend(["--script", "vulners"])
        else:
            ctx.log("vulners.nse not found, skip CVE script")

    args.extend(["-p", ports, host])

    scripts = []
    if os_detect and not fast:
        scripts.append("OS")
    if vulners and not fast and vulners_available():
        scripts.append("vulners")
    script_note = f" scripts={','.join(scripts)}" if scripts else ""
    ctx.log(f"running nmap on {host} ports={ports}{script_note}")

    proc = run_cmd(args, timeout=7200)
    if proc.returncode != 0:
        ctx.log(f"nmap failed: {proc.stderr[:200]}")
    output_xml.parent.mkdir(parents=True, exist_ok=True)
    if not output_xml.is_file() or output_xml.stat().st_size == 0:
        output_xml.write_text(proc.stdout, encoding="utf-8")
    return proc.returncode == 0


def full_port_scan(ctx: ScanContext, host: str, output_xml: Path) -> bool:
    os_detect = bool(ctx.options.get("enable_os_detect", True))
    vulners = bool(ctx.options.get("enable_vulners", True))
    return port_scan(
        ctx,
        host,
        output_xml,
        ports="-",
        fast=False,
        os_detect=os_detect,
        vulners=vulners,
    )
