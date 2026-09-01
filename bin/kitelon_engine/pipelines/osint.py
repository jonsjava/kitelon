from kitelon_engine.artifacts import Manifest
from kitelon_engine.context import ScanContext
from kitelon_engine.tools import osint as osint_tools


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

    manifest.data["status"] = "completed"
    manifest.save()
    return 0
