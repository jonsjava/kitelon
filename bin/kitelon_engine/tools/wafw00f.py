

import re
from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.findings import Finding, FindingWriter
from kitelon_engine.tools.base import hostname_from_url, run_cmd, tool_path


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1B\[[0-9;]*[a-zA-Z]", "", text)


def _summarize_waf_output(text: str) -> str | None:
    from kitelon_env import parse_waf  # noqa: E402

    return parse_waf(text)


def detect_waf(ctx: ScanContext, url: str, output: Path) -> str | None:
    wafw00f = tool_path(ctx, "wafw00f", "wafw00f not found, skip WAF detection")
    if not wafw00f:
        return None

    ctx.log(f"detecting WAF for {url}")
    proc = run_cmd([wafw00f, url], timeout=120)
    output.parent.mkdir(parents=True, exist_ok=True)
    combined = _strip_ansi(proc.stdout + proc.stderr)
    output.write_text(combined, encoding="utf-8", errors="replace")

    summary = _summarize_waf_output(combined)
    if summary and summary != "None detected":
        host = hostname_from_url(url)
        FindingWriter(ctx.findings_path).emit_kv(
            severity="info",
            name="WAF or security edge detected",
            hostname=host,
            url=url,
            evidence=summary,
            source="wafw00f",
        )
    return summary
