import json
from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.tools.base import run_cmd


def metagoofil_script(install_dir: Path) -> Path | None:
    for candidate in (
        install_dir / "plugins" / "metagoofil" / "metagoofil.py",
        Path("/usr/share/kitelon/plugins/metagoofil/metagoofil.py"),
    ):
        if candidate.is_file():
            return candidate
    return None


def run_metagoofil(ctx: ScanContext, domain: str, out_dir: Path) -> bool:
    script = metagoofil_script(ctx.install_dir)
    if not script:
        ctx.log("metagoofil not found, skip")
        return False

    limit = int(ctx.options.get("metagoofil_limit", 25))
    types = str(ctx.options.get("metagoofil_types", "pdf,doc,xls")).strip() or "pdf,doc,xls"
    timeout = int(ctx.options.get("metagoofil_timeout", 600))
    out_dir.mkdir(parents=True, exist_ok=True)
    args = [
        "python3",
        str(script),
        "-d",
        domain,
        "-t",
        types,
        "-l",
        str(limit),
        "-o",
        str(out_dir),
    ]
    ctx.log(f"running metagoofil on {domain}")
    proc = run_cmd(args, timeout=timeout, cwd=str(script.parent))
    summary = {
        "domain": domain,
        "limit": limit,
        "types": types,
        "returncode": proc.returncode,
        "files": sorted(p.name for p in out_dir.iterdir() if p.is_file()),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if proc.returncode != 0:
        ctx.log(f"metagoofil exited {proc.returncode}")
    return proc.returncode == 0 or bool(summary["files"])
