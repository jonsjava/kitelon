"""Shared pipeline steps."""

from functools import partial
from pathlib import Path
from collections.abc import Callable
import json

from kitelon_engine.artifacts import Manifest
from kitelon_engine.checks.headers import check_headers
from kitelon_engine.context import ScanContext
from kitelon_engine.tools import (
    dnsx,
    ffuf,
    gobuster,
    gowitness,
    httpx,
    katana,
    metasploit,
    naabu,
    nikto,
    nmap,
    nuclei,
    smb,
    subfinder,
    testssl,
    tlsx,
    wafw00f,
    webtech,
)
from kitelon_engine.tools.nmap_parse import import_nmap_enrichment, parse_open_ports


def _opt(ctx: ScanContext, key: str, default: bool = True) -> bool:
    value = ctx.options.get(key, default)
    if value is None:
        return default
    return bool(value)


def _url_live(httpx_out: Path) -> bool:
    if not httpx_out.is_file():
        return False
    text = httpx_out.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return False
    first = text.splitlines()[0]
    return any(code in first for code in ("200", "301", "302", "401", "403"))


def _run_step(manifest: Manifest, step: str, out: Path, work: Callable[[], None]) -> None:
    if manifest.should_skip(step, out):
        return
    work()
    manifest.step_done(step, str(out.relative_to(manifest.ctx.loot_root)))


def write_ports_json(manifest: Manifest, host: str, ports: list[int]) -> Path:
    out = manifest.artifact_path("ports", f"{host}.json")
    out.write_text(json.dumps({"host": host, "ports": ports}, indent=2), encoding="utf-8")
    return out


def web_stack(ctx: ScanContext, manifest: Manifest, host: str, ports: list[int] | None = None) -> None:
    ports = ports or [80, 443]
    wordlist = Path(ctx.options.get("wordlist_dir", ctx.install_dir / "wordlists")) / "web-brute-common.txt"

    for port in ports:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
        httpx_out = manifest.artifact_path("web", host, f"httpx-{port}.txt")

        def run(enabled: bool, name: str, out: Path, work: Callable[[], None]) -> None:
            if enabled:
                _run_step(manifest, name, out, work)

        run(_opt(ctx, "enable_httpx"), f"httpx-{host}-{port}", httpx_out, partial(httpx.probe_url, ctx, url, httpx_out))

        webtech_out = manifest.artifact_path("web", host, f"webtech-{port}.json")
        run(_opt(ctx, "enable_webtech"), f"webtech-{host}-{port}", webtech_out, partial(webtech.run_webtech, ctx, url, webtech_out))

        shot = manifest.artifact_path("screenshots", f"{host}-{port}.png")
        run(_opt(ctx, "enable_gowitness") and _url_live(httpx_out), f"gowitness-{host}-{port}", shot, partial(gowitness.capture_screenshot, ctx, url, shot))

        waf_out = manifest.artifact_path("web", host, f"waf-{port}.txt")
        run(_opt(ctx, "enable_wafw00f"), f"waf-{host}-{port}", waf_out, partial(wafw00f.detect_waf, ctx, url, waf_out))

        title_out = manifest.artifact_path("web", host, "title.txt")
        if httpx_out.is_file() and not title_out.is_file():
            title_out.write_text(httpx_out.read_text(errors="replace")[:500], encoding="utf-8")

        headers_step = f"headers-{host}-{port}"
        if not manifest.is_step_done(headers_step):
            check_headers(ctx, url, host)
            manifest.step_done(headers_step)

        nuclei_out = manifest.artifact_path("tools", "nuclei", f"{host}-{port}.txt")
        run(_opt(ctx, "enable_nuclei"), f"nuclei-{host}-{port}", nuclei_out, partial(nuclei.run_nuclei, ctx, url, nuclei_out))

        katana_out = manifest.artifact_path("tools", "katana", f"{host}-{port}.json")
        run(_opt(ctx, "enable_katana"), f"katana-{host}-{port}", katana_out, partial(katana.crawl_urls, ctx, url, katana_out))

        ssl_out = manifest.artifact_path("ssl", f"{host}-{port}.json")
        run(port == 443 and _opt(ctx, "enable_testssl"), f"testssl-{host}-{port}", ssl_out, partial(testssl.run_testssl, ctx, host, port, ssl_out))

        tlsx_out = manifest.artifact_path("ssl", f"{host}-{port}-tlsx.json")
        run(port == 443 and _opt(ctx, "enable_tlsx"), f"tlsx-{host}-{port}", tlsx_out, partial(tlsx.probe_tls, ctx, host, port, tlsx_out))

        nikto_out = manifest.artifact_path("tools", "nikto", f"{host}-{port}.json")
        run(_opt(ctx, "enable_nikto") and _url_live(httpx_out), f"nikto-{host}-{port}", nikto_out, partial(nikto.run_nikto, ctx, url, nikto_out))

        brute_out = manifest.artifact_path("tools", "gobuster", f"{host}-{port}.txt")
        run(_opt(ctx, "enable_dirsearch") or _opt(ctx, "enable_gobuster"), f"brute-{host}-{port}", brute_out, partial(gobuster.run_dirsearch, ctx, url, wordlist, brute_out))

        ffuf_out = manifest.artifact_path("tools", "ffuf", f"{host}-{port}.json")
        run(_opt(ctx, "enable_ffuf") and _url_live(httpx_out), f"ffuf-{host}-{port}", ffuf_out, partial(ffuf.run_ffuf, ctx, url, wordlist, ffuf_out))


def service_stack(ctx: ScanContext, manifest: Manifest, host: str, ports: list[int]) -> None:
    if 445 in ports and (_opt(ctx, "enable_enum4linux") or _opt(ctx, "enable_smbmap")):
        enum_out = manifest.artifact_path("tools", "smb", f"{host}-enum4linux.json")
        if _opt(ctx, "enable_enum4linux"):
            _run_step(manifest, f"enum4linux-{host}", enum_out, partial(smb.run_enum4linux, ctx, host, enum_out))
        smbmap_out = manifest.artifact_path("tools", "smb", f"{host}-smbmap.txt")
        if _opt(ctx, "enable_smbmap"):
            _run_step(manifest, f"smbmap-{host}", smbmap_out, partial(smb.run_smbmap, ctx, host, smbmap_out))

    if 22 in ports and _opt(ctx, "enable_ssh_audit"):
        ssh_out = manifest.artifact_path("tools", "ssh", f"{host}-22.txt")
        _run_step(manifest, f"ssh-audit-{host}", ssh_out, partial(smb.run_ssh_audit, ctx, host, 22, ssh_out))


def port_discovery(ctx: ScanContext, manifest: Manifest, host: str, *, full: bool = False) -> list[int]:
    xml_out = manifest.artifact_path("nmap", f"{host}.xml")
    step = f"nmap-{'full' if full else 'default'}-{host}"
    if manifest.should_skip(step, xml_out):
        return parse_open_ports(xml_out)

    naabu_ports: list[int] = []
    if _opt(ctx, "enable_naabu") and not full:
        naabu_out = manifest.artifact_path("tools", "naabu", f"{host}.json")
        naabu_step = f"naabu-{host}"
        if not manifest.should_skip(naabu_step, naabu_out):
            naabu_ports = naabu.run_naabu(ctx, host, naabu_out)
            manifest.step_done(naabu_step, str(naabu_out.relative_to(ctx.loot_root)))

    fast = ctx.mode == "stealth"
    os_detect = bool(ctx.options.get("enable_os_detect", True)) and not fast
    vulners = bool(ctx.options.get("enable_vulners", True)) and not fast

    if full:
        nmap.full_port_scan(ctx, host, xml_out)
    else:
        nmap.port_scan(
            ctx,
            host,
            xml_out,
            fast=fast,
            os_detect=os_detect,
            vulners=vulners,
        )
    manifest.step_done(step, str(xml_out.relative_to(ctx.loot_root)))

    os_out = manifest.artifact_path("nmap", f"osfingerprint-{host}.txt")
    import_nmap_enrichment(ctx, host, xml_out, os_artifact=os_out)

    ports = parse_open_ports(xml_out)
    if naabu_ports:
        ports = sorted(set(ports) | set(naabu_ports))
    write_ports_json(manifest, host, ports)
    service_stack(ctx, manifest, host, ports)

    if _opt(ctx, "enable_metasploit") and ctx.mode != "stealth":
        msf_dir = manifest.artifact_path("tools", "metasploit", host)
        msf_summary = msf_dir / "summary.json"
        msf_step = f"metasploit-{host}"
        if not manifest.should_skip(msf_step, msf_summary):
            if metasploit.run_host_scanners(ctx, host, xml_out, msf_dir):
                manifest.step_done(msf_step, str(msf_summary.relative_to(ctx.loot_root)))

    return ports


def recon_pass(ctx: ScanContext, manifest: Manifest) -> list[str]:
    if not _opt(ctx, "enable_subfinder"):
        return [ctx.target]

    out = manifest.artifact_path("recon", "subdomains.txt")
    step = f"subfinder-{ctx.target}"
    if manifest.should_skip(step, out):
        if out.is_file():
            hosts = [line.strip() for line in out.read_text(errors="replace").splitlines() if line.strip()]
        else:
            hosts = [ctx.target]
    else:
        hosts = subfinder.enumerate_subdomains(ctx, ctx.target, out)
        manifest.step_done(step, str(out.relative_to(ctx.loot_root)))

    if _opt(ctx, "enable_dnsx") and hosts:
        dnsx_out = manifest.artifact_path("recon", "dnsx.json")
        dnsx_step = f"dnsx-{ctx.target}"
        if not manifest.should_skip(dnsx_step, dnsx_out):
            hosts = dnsx.resolve_hosts(ctx, hosts, dnsx_out)
            manifest.step_done(dnsx_step, str(dnsx_out.relative_to(ctx.loot_root)))

    domains_json = manifest.artifact_path("recon", "domains.json")
    domains_json.write_text(json.dumps({"domain": ctx.target, "hosts": hosts}, indent=2), encoding="utf-8")
    return hosts
