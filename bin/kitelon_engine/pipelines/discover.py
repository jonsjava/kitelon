"""CIDR discovery pipeline."""

import ipaddress
import json

from kitelon_engine.artifacts import Manifest
from kitelon_engine.context import ScanContext
from kitelon_engine.pipelines import simple
from kitelon_engine.tools import nmap


def run(ctx: ScanContext) -> int:
    manifest = Manifest(ctx)
    ctx.ensure_dirs()
    ctx.log(f"starting discover on {ctx.target}")

    try:
        network = ipaddress.ip_network(ctx.target, strict=False)
    except ValueError:
        ctx.log("invalid CIDR, falling back to normal scan")
        return simple.normal(ctx)

    live_hosts: list[str] = []
    for host in network.hosts():
        if len(live_hosts) >= int(ctx.options.get("max_hosts", 256)):
            break
        host_str = str(host)
        xml_out = manifest.artifact_path("nmap", f"{host_str}.xml")
        if nmap.port_scan(ctx, host_str, xml_out, ports="80,443,22,445", fast=True):
            live_hosts.append(host_str)

    hosts_file = manifest.artifact_path("recon", "live_hosts.json")
    hosts_file.write_text(json.dumps(live_hosts, indent=2), encoding="utf-8")

    for host in live_hosts:
        sub_ctx = ScanContext(
            install_dir=ctx.install_dir,
            target=host,
            mode="normal",
            workspace=ctx.workspace,
            options={**ctx.options, "fullportscan": False},
        )
        simple.normal(sub_ctx)

    manifest.data["status"] = "completed"
    manifest.save()
    return 0
