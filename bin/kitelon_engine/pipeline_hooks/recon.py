"""Registry-driven recon pipeline hooks."""

from __future__ import annotations

from kitelon_engine.artifacts import Manifest
from kitelon_engine.context import ScanContext
from kitelon_engine.plugin_registry import PluginRegistry, PluginSpec
from kitelon_engine.tools import dnsrecon, dnsx, gau, subfinder


def _opt(ctx: ScanContext, key: str, default: bool = False) -> bool:
    value = ctx.options.get(key, default)
    if value is None:
        return default
    return bool(value)


def _plugin_enabled(ctx: ScanContext, spec: PluginSpec) -> bool:
    if spec.always_on or not spec.config_option:
        return True
    return _opt(ctx, spec.config_option, default=False)


def run_plugin(
    ctx: ScanContext,
    manifest: Manifest,
    spec: PluginSpec,
    hosts: list[str],
) -> list[str]:
    """Run one recon plugin; return updated host list."""
    if not _plugin_enabled(ctx, spec):
        return hosts

    if spec.id == "subfinder":
        out = manifest.artifact_path("recon", "subdomains.txt")
        step = f"subfinder-{ctx.target}"
        if manifest.should_skip(step, out):
            if out.is_file():
                return [line.strip() for line in out.read_text(errors="replace").splitlines() if line.strip()]
            return hosts
        found = subfinder.enumerate_subdomains(ctx, ctx.target, out)
        manifest.step_done(step, str(out.relative_to(ctx.loot_root)))
        return found

    if spec.id == "dnsx":
        if not hosts:
            return hosts
        dnsx_out = manifest.artifact_path("recon", "dnsx.json")
        dnsx_step = f"dnsx-{ctx.target}"
        if manifest.should_skip(dnsx_step, dnsx_out):
            return hosts
        resolved = dnsx.resolve_hosts(ctx, hosts, dnsx_out)
        manifest.step_done(dnsx_step, str(dnsx_out.relative_to(ctx.loot_root)))
        return resolved

    if spec.id == "dnsrecon":
        dnsrecon_out = manifest.artifact_path("recon", "dnsrecon.json")
        dnsrecon_step = f"dnsrecon-{ctx.target}"
        if not manifest.should_skip(dnsrecon_step, dnsrecon_out):
            dnsrecon.run_dnsrecon(ctx, ctx.target, dnsrecon_out)
            manifest.step_done(dnsrecon_step, str(dnsrecon_out.relative_to(ctx.loot_root)))
        return hosts

    if spec.id == "gau":
        gau_out = manifest.artifact_path("recon", "gau-urls.txt")
        gau_step = f"gau-{ctx.target}"
        if not manifest.should_skip(gau_step, gau_out):
            gau.run_gau(ctx, ctx.target, gau_out)
            manifest.step_done(gau_step, str(gau_out.relative_to(ctx.loot_root)))
        return hosts

    ctx.log(f"recon hook not implemented for plugin {spec.id}")
    return hosts


def run_recon_pipeline(
    ctx: ScanContext,
    manifest: Manifest,
    registry: PluginRegistry,
) -> list[str]:
    hosts = [ctx.target]
    for spec in registry.for_pipeline("recon", ctx):
        hosts = run_plugin(ctx, manifest, spec, hosts)
    return hosts
