import subprocess

from kitelon_engine.artifacts import Manifest
from kitelon_engine.context import ScanContext
from kitelon_engine.pipelines import simple
from kitelon_engine.tools import zap


def run(ctx: ScanContext) -> int:
    manifest = Manifest(ctx)
    ctx.ensure_dirs()
    ctx.log(f"starting web-deep scan for {ctx.target}")

    simple.web(ctx)

    zap_script = ctx.install_dir / "bin" / "zap-scan.py"
    for port in (80, 443):
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{ctx.target}"
        out = manifest.artifact_path("tools", "zap", f"{ctx.target}-{port}.json")
        step = f"zap-{ctx.target}-{port}"
        if manifest.should_skip(step, out):
            continue
        if zap_script.is_file():
            subprocess.run(
                ["python3", str(zap_script), url, str(out)],
                capture_output=True,
                text=True,
                timeout=7200,
            )
            zap.import_zap_json(ctx, out, default_host=ctx.target)
            manifest.step_done(step, str(out.relative_to(ctx.loot_root)))

    manifest.data["status"] = "completed"
    manifest.save()
    return 0
