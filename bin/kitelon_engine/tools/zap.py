

import json
from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.findings import FindingWriter
from kitelon_engine.tools.base import hostname_from_url


def import_zap_json(ctx: ScanContext, path: Path, *, default_host: str | None = None) -> int:
    if not path.is_file():
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return 0

    alerts = data.get("site", [])
    if isinstance(alerts, list) and alerts and isinstance(alerts[0], dict):
        site_alerts = alerts[0].get("alerts", [])
    else:
        site_alerts = data.get("alerts", [])

    writer = FindingWriter(ctx.findings_path)
    count = 0
    for alert in site_alerts:
        if not isinstance(alert, dict):
            continue
        name = str(alert.get("alert") or alert.get("name") or "ZAP alert").strip()
        risk = str(alert.get("risk") or alert.get("riskdesc") or "info").lower()
        severity = "info"
        for level in ("critical", "high", "medium", "low"):
            if level in risk:
                severity = level
                break
        host = hostname_from_url(str(alert.get("host") or alert.get("url") or default_host or ctx.target), ctx.target)
        evidence = str(alert.get("desc") or alert.get("description") or "")[:2000]
        writer.emit_kv(
            severity=severity,
            name=name[:200],
            hostname=host,
            url=str(alert.get("url") or host),
            evidence=evidence,
            source="zap",
            source_file=path.name,
        )
        count += 1
    return count
