"""Dispatch a scan mode to its pipeline and return an exit code."""


from kitelon_engine.config import load_config, load_preset
from kitelon_engine.context import ScanContext, default_install_dir
from kitelon_engine.pipelines.registry import get_pipeline


def run_scan(
    *,
    target: str,
    mode: str = "normal",
    workspace: str,
    install_dir=None,
    options: dict | None = None,
    job_id: int | None = None,
) -> int:
    if not workspace or not str(workspace).strip():
        raise ValueError("workspace required")
    install = install_dir or default_install_dir()
    opts = dict(options or {})
    preset = opts.pop("preset", None)
    config = load_config(install)
    if preset:
        config = {**config, **load_preset(install, str(preset))}
    merged_options = {**config, **opts}

    ctx = ScanContext(
        install_dir=install,
        target=target,
        mode=(mode or "normal").lower().strip(),
        workspace=workspace,
        options=merged_options,
        job_id=job_id,
    )
    ctx.ensure_dirs()
    if ctx.findings_path.is_file() and not ctx.resume:
        ctx.findings_path.write_text("", encoding="utf-8")

    pipeline = get_pipeline(ctx.mode)
    return pipeline(ctx)
