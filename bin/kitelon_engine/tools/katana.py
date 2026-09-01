

from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.tools.base import iter_json_lines, run_cmd, tool_path


def crawl_urls(ctx: ScanContext, url: str, output: Path) -> list[str]:
    katana = tool_path(ctx, "katana", "katana not found, skip crawl")
    if not katana:
        return []

    json_out = output.with_suffix(".json")
    args = [
        katana,
        "-u",
        url,
        "-json",
        "-o",
        str(json_out),
        "-silent",
        "-d",
        "2",
    ]
    ctx.log(f"running katana on {url}")
    run_cmd(args, timeout=1800)
    output.parent.mkdir(parents=True, exist_ok=True)
    urls: list[str] = []
    if json_out.is_file():
        output.write_text(json_out.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
        for row in iter_json_lines(json_out):
            endpoint = row.get("url") or row.get("request", {}).get("endpoint")
            if endpoint:
                urls.append(str(endpoint))
    return sorted(set(urls))
