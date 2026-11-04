from kitelon_engine.artifacts import Manifest
from kitelon_engine.context import ScanContext
from kitelon_engine.pipelines import osint, simple, webscan
from kitelon_engine.pipelines.steps import port_discovery, recon_pass, ssl_stack


def run(ctx: ScanContext) -> int:
    ctx.options.update(
        {
            "osint": True,
            "recon": True,
            "fullportscan": True,
            "enable_nuclei": True,
            "enable_testssl": True,
            "enable_dirsearch": True,
        }
    )
    manifest = Manifest(ctx)
    ctx.ensure_dirs()
    ctx.log(f"full-audit scan for {ctx.target}")

    osint.run(ctx)

    # Recon first so we know the full host surface, then port-scan each host.
    # Track which discovered hosts expose 443 so SSL/TLS is tested across the
    # whole attack surface, not just the apex target.
    hosts = recon_pass(ctx, manifest)
    cap = int(ctx.options.get("max_hosts", 50))
    ssl_hosts: list[str] = []
    for host in hosts[:cap]:
        ports = port_discovery(ctx, manifest, host, full=False)
        if 443 in ports and host != ctx.target:
            ssl_hosts.append(host)

    # Apex web stack (includes testssl on 443) + deep web + apex vuln pass.
    webscan.run(ctx)
    simple.vuln(ctx)

    # SSL/TLS sweep over discovered HTTPS hosts (apex already covered above).
    for host in ssl_hosts:
        ctx.log(f"full-audit SSL/TLS check for {host}:443")
        ssl_stack(ctx, manifest, host, 443)

    manifest.data["status"] = "completed"
    manifest.save()
    return 0
