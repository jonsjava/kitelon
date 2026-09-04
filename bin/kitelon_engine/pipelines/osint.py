from kitelon_engine.artifacts import Manifest
from kitelon_engine.context import ScanContext
from kitelon_engine.tools import censys as censys_tool
from kitelon_engine.tools import metagoofil as metagoofil_tool
from kitelon_engine.tools import osint as osint_tools
from kitelon_engine.tools import shodan as shodan_tool


def _opt(ctx: ScanContext, key: str, default: bool = True) -> bool:
    value = ctx.options.get(key, default)
    if value is None:
        return default
    return bool(value)


def run(ctx: ScanContext) -> int:
    manifest = Manifest(ctx)
    ctx.ensure_dirs()
    ctx.log(f"starting OSINT for {ctx.target}")

    whois_out = manifest.artifact_path("recon", "whois.txt")
    step = f"whois-{ctx.target}"
    if not manifest.should_skip(step, whois_out):
        osint_tools.run_whois(ctx, ctx.target, whois_out)
        manifest.step_done(step, str(whois_out.relative_to(ctx.loot_root)))

    harvest_out = manifest.artifact_path("recon", "theharvester")
    step = f"harvester-{ctx.target}"
    if not manifest.should_skip(step, harvest_out.with_suffix(".xml")):
        osint_tools.run_theharvester(ctx, ctx.target, harvest_out)
        manifest.step_done(step)

    if _opt(ctx, "enable_metagoofil", False):
        meta_dir = manifest.artifact_path("recon", "metagoofil")
        step = f"metagoofil-{ctx.target}"
        marker = meta_dir / "summary.json"
        if not manifest.should_skip(step, marker):
            metagoofil_tool.run_metagoofil(ctx, ctx.target, meta_dir)
            manifest.step_done(step, str(meta_dir.relative_to(ctx.loot_root)))

    shodan_out = manifest.artifact_path("recon", "shodan.json")
    step = f"shodan-{ctx.target}"
    if _opt(ctx, "enable_shodan") and not manifest.should_skip(step, shodan_out):
        shodan_tool.run_shodan(ctx, ctx.target, shodan_out)
        manifest.step_done(step, str(shodan_out.relative_to(ctx.loot_root)))

    censys_out = manifest.artifact_path("recon", "censys.json")
    step = f"censys-{ctx.target}"
    if _opt(ctx, "enable_censys") and not manifest.should_skip(step, censys_out):
        censys_tool.run_censys(ctx, ctx.target, censys_out)
        manifest.step_done(step, str(censys_out.relative_to(ctx.loot_root)))

    manifest.data["status"] = "completed"
    manifest.save()
    return 0
