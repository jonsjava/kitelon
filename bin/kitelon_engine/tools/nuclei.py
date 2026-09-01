

from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.findings import FindingWriter
from kitelon_engine.tools.base import hostname_from_url, run_cmd, tool_path


def run_nuclei(
    ctx: ScanContext,
    target_url: str,
    output: Path,
    *,
    templates: str | None = None,
    tags: str | None = None,
) -> bool:
    nuclei = tool_path(ctx, "nuclei", "nuclei not found, skip")
    if not nuclei:
        return False

    args = [
        nuclei,
        "-silent",
        "-stats",
        "-target",
        target_url,
        "-o",
        str(output),
        "-c",
        str(ctx.threads),
    ]
    tpl = templates or ctx.options.get("nuclei_templates")
    if tpl:
        args.extend(["-t", str(tpl)])
    if tags:
        args.extend(["-tags", tags])

    ctx.log(f"running nuclei on {target_url}")
    proc = run_cmd(args, timeout=7200)
    output.parent.mkdir(parents=True, exist_ok=True)
    if proc.stdout.strip() and not output.is_file():
        output.write_text(proc.stdout, encoding="utf-8")
    _import_nuclei_output(ctx, target_url, output)
    return proc.returncode == 0


def _import_nuclei_output(ctx: ScanContext, target_url: str, output: Path) -> None:
    if not output.is_file():
        return
    writer = FindingWriter(ctx.findings_path)
    host = hostname_from_url(target_url)
    for line in output.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        severity = "info"
        lower = line.lower()
        for level in ("critical", "high", "medium", "low", "info"):
            if f"[{level}]" in lower:
                severity = level
                break
        writer.emit_kv(
            severity=severity,
            name=line[:200],
            hostname=host,
            url=target_url,
            evidence=line,
            source="nuclei",
        )
