import json
from pathlib import Path

from kitelon_engine.context import ScanContext


def _censys_hosts(api_id: str, api_secret: str, domain: str, limit: int) -> list[dict]:
    from censys.search import CensysHosts

    client = CensysHosts(api_id, api_secret)
    query = f"services.tls.certificates.parsed.names: {domain} or dns.names: {domain}"
    rows: list[dict] = []
    for page in client.search(query, per_page=min(limit, 100), pages=1):
        for hit in page:
            rows.append(hit)
            if len(rows) >= limit:
                return rows
    return rows


def _censys_certs(api_id: str, api_secret: str, domain: str, limit: int) -> list[dict]:
    from censys.search import CensysCerts

    client = CensysCerts(api_id, api_secret)
    query = f"parsed.names: {domain}"
    rows: list[dict] = []
    for page in client.search(query, per_page=min(limit, 100), pages=1):
        for hit in page:
            rows.append(hit)
            if len(rows) >= limit:
                return rows
    return rows


def run_censys(ctx: ScanContext, domain: str, output_json: Path) -> bool:
    if not ctx.options.get("enable_censys", True):
        ctx.log("censys disabled, skip")
        return False
    api_id = str(ctx.options.get("censys_app_id", "")).strip()
    api_secret = str(ctx.options.get("censys_api_secret", "")).strip()
    if not api_id or not api_secret:
        ctx.log("CENSYS_APP_ID / CENSYS_API_SECRET not set, skip")
        return False

    try:
        from censys.search import CensysCerts, CensysHosts  # noqa: F401
    except ImportError:
        ctx.log("censys Python package not installed, skip")
        return False

    mode = str(ctx.options.get("censys_mode", "hosts")).strip().lower() or "hosts"
    limit = max(1, int(ctx.options.get("censys_max_results", 25)))
    _ = int(ctx.options.get("censys_timeout", 60))
    payload: dict = {"domain": domain, "mode": mode, "hosts": [], "certs": [], "errors": []}
    ctx.log(f"querying Censys ({mode}) for {domain}")

    try:
        if mode in ("hosts", "both"):
            payload["hosts"] = _censys_hosts(api_id, api_secret, domain, limit)
        if mode in ("certs", "both"):
            payload["certs"] = _censys_certs(api_id, api_secret, domain, limit)
    except Exception as exc:  # noqa: BLE001
        payload["errors"].append(str(exc))
        ctx.log(f"censys query failed: {exc}")

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return bool(payload["hosts"] or payload["certs"] or not payload["errors"])
