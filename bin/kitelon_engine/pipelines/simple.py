"""Mode runners that share the same Manifest / loot / complete sequence."""

from kitelon_engine.artifacts import Manifest
from kitelon_engine.context import ScanContext
from kitelon_engine.pipelines.steps import port_discovery, recon_pass, web_stack
from kitelon_engine.tools import httpx, nmap, nuclei


def _begin(ctx: ScanContext, message: str) -> Manifest:
    manifest = Manifest(ctx)
    ctx.ensure_dirs()
    ctx.log(message)
    return manifest


def _complete(manifest: Manifest) -> int:
    manifest.data["status"] = "completed"
    manifest.save()
    return 0


def _http_ports(ports: list[int], *, fallback: list[int] | None = None) -> list[int]:
    web = [p for p in ports if p in (80, 443)]
    if web:
        return web
    return fallback or []


def normal(ctx: ScanContext) -> int:
    manifest = _begin(ctx, f"starting normal scan for {ctx.target}")
    if ctx.options.get("recon"):
        recon_pass(ctx, manifest)
    if ctx.options.get("osint"):
        from kitelon_engine.pipelines import osint as osint_pipeline

        osint_pipeline.run(ctx)
    ports = port_discovery(ctx, manifest, ctx.target, full=bool(ctx.options.get("fullportscan")))
    web_stack(ctx, manifest, ctx.target, _http_ports(ports, fallback=[443] if 443 in ports else [80]))
    return _complete(manifest)


def stealth(ctx: ScanContext) -> int:
    manifest = _begin(ctx, f"starting stealth scan for {ctx.target}")
    ctx.options.setdefault("threads", 5)
    ports = port_discovery(ctx, manifest, ctx.target, full=False)
    web_stack(ctx, manifest, ctx.target, (_http_ports(ports, fallback=[443, 80]) or [443])[:1])
    return _complete(manifest)


def web(ctx: ScanContext) -> int:
    manifest = _begin(ctx, f"starting web scan for {ctx.target}")
    web_stack(ctx, manifest, ctx.target, [80, 443])
    return _complete(manifest)


def web_http(ctx: ScanContext) -> int:
    port = ctx.port or 80
    manifest = _begin(ctx, f"starting web HTTP port scan for {ctx.target}:{port}")
    web_stack(ctx, manifest, ctx.target, [port])
    return _complete(manifest)


def web_https(ctx: ScanContext) -> int:
    port = ctx.port or 443
    manifest = _begin(ctx, f"starting web HTTPS port scan for {ctx.target}:{port}")
    web_stack(ctx, manifest, ctx.target, [port])
    return _complete(manifest)


def allports(ctx: ScanContext) -> int:
    manifest = _begin(ctx, f"starting full port scan for {ctx.target}")
    ports = port_discovery(ctx, manifest, ctx.target, full=True)
    web_ports = _http_ports(ports)
    if web_ports:
        web_stack(ctx, manifest, ctx.target, web_ports)
    return _complete(manifest)


def ports_only(ctx: ScanContext) -> int:
    manifest = _begin(ctx, f"starting ports-only scan for {ctx.target}")
    port_discovery(ctx, manifest, ctx.target, full=True)
    return _complete(manifest)


def ports_quick(ctx: ScanContext) -> int:
    manifest = _begin(ctx, f"starting ports-quick scan for {ctx.target}")
    port_discovery(ctx, manifest, ctx.target, full=False)
    return _complete(manifest)


def port(ctx: ScanContext) -> int:
    scan_port = ctx.port or 80
    manifest = _begin(ctx, f"scanning port {scan_port} on {ctx.target}")
    xml_out = manifest.artifact_path("nmap", f"{ctx.target}.xml")
    step = f"port-{ctx.target}-{scan_port}"
    if not manifest.should_skip(step, xml_out):
        nmap.port_scan(ctx, ctx.target, xml_out, ports=str(scan_port))
        manifest.step_done(step, str(xml_out.relative_to(ctx.loot_root)))
    return _complete(manifest)


def recon(ctx: ScanContext) -> int:
    manifest = _begin(ctx, f"starting recon for {ctx.target}")
    hosts = recon_pass(ctx, manifest)
    cap = int(ctx.options.get("max_hosts", 50))
    for host in hosts[:cap]:
        port_discovery(ctx, manifest, host, full=False)
    return _complete(manifest)


def vuln(ctx: ScanContext) -> int:
    manifest = _begin(ctx, f"starting vuln scan for {ctx.target}")
    for scheme, port in (("https", 443), ("http", 80)):
        url = f"{scheme}://{ctx.target}"
        httpx.probe_url(ctx, url, manifest.artifact_path("web", ctx.target, f"httpx-{port}.txt"))
        nuclei.run_nuclei(
            ctx, url, manifest.artifact_path("tools", "nuclei", f"{ctx.target}-{port}.txt")
        )
    return _complete(manifest)
