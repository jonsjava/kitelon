

from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.tools.base import run_cmd, which


def run_theharvester(ctx: ScanContext, domain: str, output: Path) -> bool:
    harvester = which("theHarvester")
    if not harvester:
        ctx.log("theHarvester not found, skip")
        return False

    args = [harvester, "-d", domain, "-b", "all", "-f", str(output.with_suffix(""))]
    ctx.log(f"running theHarvester on {domain}")
    run_cmd(args, timeout=1800)
    return True


def run_whois(ctx: ScanContext, domain: str, output: Path) -> bool:
    whois = which("whois")
    if not whois:
        return False
    proc = run_cmd([whois, domain], timeout=120)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(proc.stdout, encoding="utf-8", errors="replace")
    return proc.returncode == 0
