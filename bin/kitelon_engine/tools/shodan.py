import json
from pathlib import Path

from kitelon_engine.context import ScanContext


def run_shodan(ctx: ScanContext, domain: str, output_json: Path) -> bool:
    if not ctx.options.get("enable_shodan", True):
        ctx.log("shodan disabled, skip")
        return False
    api_key = str(ctx.options.get("shodan_api_key", "")).strip()
    if not api_key:
        ctx.log("SHODAN_API_KEY not set, skip")
        return False

    try:
        import shodan
    except ImportError:
        ctx.log("shodan Python package not installed, skip")
        return False

    max_results = max(1, int(ctx.options.get("shodan_max_results", 25)))
    timeout = int(ctx.options.get("shodan_timeout", 60))
    ctx.log(f"querying Shodan for {domain}")
    api = shodan.Shodan(api_key)
    payload: dict = {"domain": domain, "hosts": [], "subdomains": [], "errors": []}

    try:
        info = api.domain_info(domain)
        payload["subdomains"] = list(info.get("subdomains") or [])[:max_results]
        payload["tags"] = info.get("tags") or []
        for entry in info.get("data") or []:
            if len(payload["hosts"]) >= max_results:
                break
            payload["hosts"].append(
                {
                    "ip": entry.get("ip_str"),
                    "port": entry.get("port"),
                    "transport": entry.get("transport"),
                    "product": entry.get("product"),
                    "org": entry.get("org"),
                }
            )
    except Exception as exc:  # noqa: BLE001 — external API
        payload["errors"].append(str(exc))
        ctx.log(f"shodan domain lookup failed: {exc}")

    if not payload["hosts"]:
        try:
            query = f"hostname:{domain}"
            results = api.search(query, limit=max_results)
            for match in results.get("matches") or []:
                payload["hosts"].append(
                    {
                        "ip": match.get("ip_str"),
                        "port": match.get("port"),
                        "transport": match.get("transport"),
                        "product": match.get("product"),
                        "org": match.get("org"),
                    }
                )
        except Exception as exc:  # noqa: BLE001
            payload["errors"].append(str(exc))
            ctx.log(f"shodan search failed: {exc}")

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _ = timeout  # reserved for future request-level timeout wiring
    return bool(payload["hosts"] or payload["subdomains"] or not payload["errors"])
