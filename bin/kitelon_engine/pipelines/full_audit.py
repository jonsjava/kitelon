from kitelon_engine.context import ScanContext
from kitelon_engine.pipelines import osint, simple, webscan


def run(ctx: ScanContext) -> int:
    ctx.options.update(
        {
            "osint": True,
            "recon": True,
            "fullportscan": True,
            "enable_nuclei": True,
            "enable_testssl": True,
            "enable_dirsearch": True,
        }
    )
    ctx.log(f"full-audit scan for {ctx.target}")
    osint.run(ctx)
    simple.recon(ctx)
    webscan.run(ctx)
    simple.vuln(ctx)
    return 0
