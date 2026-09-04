from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.tools.base import run_cmd, tool_path


def build_gau_args(
    binary: str,
    domain: str,
    *,
    providers: str,
    include_subs: bool,
) -> list[str]:
    args = [binary, "--providers", providers]
    if include_subs:
        args.append("--subs")
    args.append(domain.strip())
    return args


def _write_capped_lines(source: str, output: Path, max_urls: int) -> int:
    lines: list[str] = []
    for line in source.splitlines():
        url = line.strip()
        if not url:
            continue
        lines.append(url)
        if max_urls > 0 and len(lines) >= max_urls:
            break
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return len(lines)


def run_gau(ctx: ScanContext, domain: str, output_txt: Path) -> bool:
    binary = tool_path(ctx, "gau", "gau not found, skip")
    if not binary:
        return False

    providers = str(ctx.options.get("gau_providers", "wayback")).strip() or "wayback"
    include_subs = bool(ctx.options.get("gau_include_subs", True))
    max_urls = int(ctx.options.get("gau_max_urls", 500))
    timeout = int(ctx.options.get("gau_timeout", 300))
    args = build_gau_args(binary, domain, providers=providers, include_subs=include_subs)
    ctx.log(f"running gau on {domain}")
    proc = run_cmd(args, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout.strip():
        ctx.log(f"gau exited {proc.returncode}")
        return False
    count = _write_capped_lines(proc.stdout, output_txt, max_urls)
    ctx.log(f"gau wrote {count} URLs")
    return count > 0 or proc.returncode == 0
