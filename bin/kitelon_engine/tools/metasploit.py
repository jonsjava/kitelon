"""Metasploit auxiliary modules via msfconsole."""

import json
import re
import tempfile
from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.findings import Finding, FindingWriter
from kitelon_engine.tools.base import run_cmd, which
from kitelon_engine.tools.nmap_parse import parse_nmap_services

MSF_LINE = re.compile(r"^\[\+\]\s*(.+)$", re.MULTILINE)
MSF_VULN = re.compile(r"(VULNERABLE|CVE-\d{4}-\d+)", re.IGNORECASE)

HTTP_PORTS = frozenset({80, 443, 8000, 8080, 8443, 8888})
HTTP_SERVICES = frozenset({"http", "https", "ssl/http", "http-proxy", "http-alt", "ssl/http-proxy"})

PORT_MODULES: dict[int, list[str]] = {
    21: ["auxiliary/scanner/ftp/ftp_version"],
    25: ["auxiliary/scanner/smtp/smtp_version"],
    53: ["auxiliary/scanner/dns/dns_amp"],
    110: ["auxiliary/scanner/pop3/pop3_version"],
    143: ["auxiliary/scanner/imap/imap_version"],
    445: [
        "auxiliary/scanner/smb/smb_version",
        "auxiliary/scanner/smb/smb_ms17_010",
    ],
    3306: ["auxiliary/scanner/mysql/mysql_version"],
    5432: ["auxiliary/scanner/postgres/postgres_version"],
    6379: ["auxiliary/scanner/redis/redis_server"],
    27017: ["auxiliary/scanner/mongodb/mongodb_login"],
    3389: ["auxiliary/scanner/rdp/rdp_scanner"],
    5985: ["auxiliary/scanner/winrm/winrm_auth_methods"],
}

HTTP_MODULES = [
    "auxiliary/scanner/http/http_version",
    "auxiliary/scanner/http/robots_txt",
]


def modules_for_service(port: int, service: str) -> list[str]:
    modules: list[str] = list(PORT_MODULES.get(port, []))
    svc = (service or "").lower()

    if port in HTTP_PORTS or svc in HTTP_SERVICES or "http" in svc:
        modules.extend(HTTP_MODULES)

    seen: set[str] = set()
    ordered: list[str] = []
    for module in modules:
        if module not in seen:
            seen.add(module)
            ordered.append(module)
    return ordered


def _module_slug(module: str) -> str:
    return module.replace("/", "_").replace("auxiliary_scanner_", "")


def _write_resource_script(host: str, port: int, module: str) -> Path:
    lines = [
        f"use {module}",
        f"set RHOSTS {host}",
        f"set RPORT {port}",
        "set THREADS 5",
        "run",
        "exit",
    ]
    rc_file = tempfile.NamedTemporaryFile(
        mode="w",
        prefix="kitelon-msf-",
        suffix=".rc",
        delete=False,
        encoding="utf-8",
    )
    rc_file.write("\n".join(lines) + "\n")
    rc_file.close()
    return Path(rc_file.name)


def _run_msfconsole(ctx: ScanContext, script: Path, *, timeout: int) -> tuple[int, str]:
    msf = which("msfconsole")
    if not msf:
        return 127, "msfconsole not found"
    proc = run_cmd([msf, "-q", "-r", str(script)], timeout=timeout)
    return proc.returncode, proc.stdout + proc.stderr


def _import_nmap(ctx: ScanContext, host: str, nmap_xml: Path, out_dir: Path) -> None:
    msf = which("msfconsole")
    if not msf or not nmap_xml.is_file():
        return
    script_path = out_dir / "db_import.rc"
    script_path.write_text(
        "\n".join(
            [
                f"db_import {nmap_xml.resolve()}",
                "hosts",
                "services",
                "exit",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    timeout = int(ctx.options.get("msf_module_timeout", 300))
    rc, text = _run_msfconsole(ctx, script_path, timeout=timeout)
    (out_dir / "db_import.txt").write_text(text, encoding="utf-8", errors="replace")
    if rc != 0:
        ctx.log(f"metasploit db_import exited {rc} for {host}")


def _import_module_output(
    ctx: ScanContext,
    host: str,
    port: int,
    module: str,
    output: Path,
) -> None:
    if not output.is_file():
        return
    text = output.read_text(encoding="utf-8", errors="replace")
    writer = FindingWriter(ctx.findings_path)
    for match in MSF_LINE.finditer(text):
        line = match.group(1).strip()
        if len(line) < 4:
            continue
        severity = "medium" if MSF_VULN.search(line) else "info"
        writer.emit(
            Finding(
                severity=severity,
                name=f"metasploit {module.split('/')[-1]}: {line[:160]}",
                hostname=host,
                url=f"{host}:{port}",
                evidence=line,
                source="metasploit",
                source_file=output.name,
                metadata={"module": module, "port": port},
            )
        )


def run_host_scanners(
    ctx: ScanContext,
    host: str,
    nmap_xml: Path,
    out_dir: Path,
) -> bool:
    msf = which("msfconsole")
    if not msf:
        ctx.log("msfconsole missing, skip Metasploit pass")
        return False

    out_dir.mkdir(parents=True, exist_ok=True)
    services = parse_nmap_services(nmap_xml)
    if not services:
        ctx.log(f"metasploit: no open services in {nmap_xml.name}")
        return False

    _import_nmap(ctx, host, nmap_xml, out_dir)

    timeout = int(ctx.options.get("msf_module_timeout", 420))
    max_modules = int(ctx.options.get("msf_max_modules", 12))
    ran: list[dict[str, str | int]] = []

    for svc in services:
        for module in modules_for_service(svc.port, svc.service):
            if len(ran) >= max_modules:
                ctx.log(f"metasploit: module cap ({max_modules}) reached for {host}")
                break
            slug = _module_slug(module)
            output = out_dir / f"{svc.port}-{slug}.txt"
            ctx.log(f"metasploit {module} on {host}:{svc.port}")
            script = _write_resource_script(host, svc.port, module)
            try:
                rc, text = _run_msfconsole(ctx, script, timeout=timeout)
            finally:
                script.unlink(missing_ok=True)
            output.write_text(text, encoding="utf-8", errors="replace")
            _import_module_output(ctx, host, svc.port, module, output)
            ran.append({"port": svc.port, "module": module, "exit_code": rc})
        if len(ran) >= max_modules:
            break

    summary_path = out_dir / "summary.json"
    summary_path.write_text(
        json.dumps({"host": host, "modules": ran}, indent=2),
        encoding="utf-8",
    )
    ctx.log(f"metasploit finished {len(ran)} module(s) on {host}")
    return bool(ran)
