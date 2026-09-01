from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.pipelines import simple, webscan


def _targets_from_file(ctx: ScanContext) -> list[str]:
    target_file = ctx.options.get("target_file")
    if not target_file:
        return [ctx.target]
    path = Path(str(target_file))
    if not path.is_file():
        return [ctx.target]
    return [line.strip() for line in path.read_text(errors="replace").splitlines() if line.strip()]


def _run_batch(ctx: ScanContext, pipeline_fn, label: str) -> int:
    targets = _targets_from_file(ctx)
    ctx.log(f"batch {label}: {len(targets)} targets")
    for target in targets:
        sub = ScanContext(
            install_dir=ctx.install_dir,
            target=target,
            mode=ctx.mode,
            workspace=ctx.workspace,
            options=dict(ctx.options),
        )
        pipeline_fn(sub)
    return 0


def batch_ports(ctx: ScanContext) -> int:
    return _run_batch(ctx, simple.allports, "ports")


def batch_web(ctx: ScanContext) -> int:
    return _run_batch(ctx, simple.web, "web")


def batch_webdeep(ctx: ScanContext) -> int:
    return _run_batch(ctx, webscan.run, "web-deep")


def batch_vuln(ctx: ScanContext) -> int:
    return _run_batch(ctx, simple.vuln, "vuln")
