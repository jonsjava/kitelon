import json
import re
from pathlib import Path
from typing import Any

from kitelon_db import insert_discovered_url, insert_scan_run, insert_service, insert_technology, insert_web_endpoint
from kitelon_engine.tools.ffuf import parse_ffuf_json
from kitelon_engine.tools.webtech import parse_webtech_json


def parse_services_from_nmap(conn: Any, workspace_id: int, loot_dir: Path) -> None:
    nmap_dir = loot_dir / "artifacts" / "nmap"
    if not nmap_dir.is_dir():
        return
    import xml.etree.ElementTree as ET

    for xml_file in sorted(nmap_dir.glob("*.xml")):
        hostname = xml_file.stem.replace("nmap-", "", 1)
        try:
            root = ET.parse(xml_file).getroot()
        except ET.ParseError:
            continue
        for port_el in root.findall(".//port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_id = port_el.get("portid")
            if not port_id or not port_id.isdigit():
                continue
            proto = port_el.get("protocol") or "tcp"
            service = port_el.find("service")
            product = service.get("product") if service is not None else None
            version = service.get("version") if service is not None else None
            cpe = None
            if service is not None:
                for cpe_el in service.findall("cpe"):
                    if cpe_el.text:
                        cpe = cpe_el.text
                        break
            insert_service(
                conn,
                workspace_id,
                hostname,
                int(port_id),
                proto,
                product=product,
                version=version,
                cpe=cpe,
            )


def parse_httpx_artifacts(conn: Any, workspace_id: int, loot_dir: Path) -> None:
    web_dir = loot_dir / "artifacts" / "web"
    if not web_dir.is_dir():
        return
    for host_dir in web_dir.iterdir():
        if not host_dir.is_dir():
            continue
        hostname = host_dir.name
        for httpx_file in host_dir.glob("httpx-*.txt"):
            match = re.search(r"httpx-(\d+)\.txt$", httpx_file.name)
            port = int(match.group(1)) if match else None
            line = httpx_file.read_text(encoding="utf-8", errors="replace").strip().splitlines()
            if not line:
                continue
            first = line[0]
            status_match = re.search(r"\[(\d+)\]", first)
            status = int(status_match.group(1)) if status_match else None
            title_match = re.search(r"\[([^\]]+)\]\s*http", first)
            title = title_match.group(1) if title_match else None
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{hostname}" if port in (80, 443) else f"{scheme}://{hostname}:{port}"
            screenshot = loot_dir / "artifacts" / "screenshots" / f"{hostname}-{port}.png"
            insert_web_endpoint(
                conn,
                workspace_id,
                hostname,
                url,
                port=port,
                status_code=status,
                title=title[:200] if title else None,
                screenshot_path=str(screenshot.relative_to(loot_dir)) if screenshot.is_file() else None,
            )


def parse_webtech(conn: Any, workspace_id: int, loot_dir: Path) -> None:
    web_dir = loot_dir / "artifacts" / "web"
    if not web_dir.is_dir():
        return
    for host_dir in web_dir.iterdir():
        if not host_dir.is_dir():
            continue
        hostname = host_dir.name
        for tech_file in host_dir.glob("webtech-*.json"):
            match = re.search(r"webtech-(\d+)\.json$", tech_file.name)
            port = int(match.group(1)) if match else None
            for tech in parse_webtech_json(tech_file):
                version = ", ".join(tech.get("versions") or []) or None
                insert_technology(
                    conn,
                    workspace_id,
                    hostname,
                    tech["name"],
                    port=port,
                    version=version,
                )


def parse_dir_brute(conn: Any, workspace_id: int, loot_dir: Path) -> None:
    gobuster_dir = loot_dir / "artifacts" / "tools" / "gobuster"
    if gobuster_dir.is_dir():
        for path in gobuster_dir.glob("*"):
            match = re.match(r"^(.+)-(\d+)\.txt$", path.name)
            if not match:
                continue
            hostname, port = match.group(1), match.group(2)
            scheme = "https" if port == "443" else "http"
            base = f"{scheme}://{hostname}" if port in ("80", "443") else f"{scheme}://{hostname}:{port}"
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                url = line if line.startswith("http") else f"{base.rstrip('/')}/{line.lstrip('/')}"
                insert_discovered_url(conn, workspace_id, hostname, url, "gobuster")

    ffuf_dir = loot_dir / "artifacts" / "tools" / "ffuf"
    if ffuf_dir.is_dir():
        for path in ffuf_dir.glob("*.json"):
            match = re.match(r"^(.+)-(\d+)\.json$", path.name)
            hostname = match.group(1) if match else path.stem
            for hit in parse_ffuf_json(path):
                url = str(hit.get("url") or "")
                if not url:
                    continue
                status = hit.get("status")
                try:
                    status_code = int(status) if status is not None else None
                except (TypeError, ValueError):
                    status_code = None
                insert_discovered_url(conn, workspace_id, hostname, url, "ffuf", status_code)


def parse_katana_urls(conn: Any, workspace_id: int, loot_dir: Path) -> None:
    katana_dir = loot_dir / "artifacts" / "tools" / "katana"
    if not katana_dir.is_dir():
        return
    for path in katana_dir.glob("*.json"):
        match = re.match(r"^(.+)-(\d+)\.json$", path.name)
        hostname = match.group(1) if match else path.stem
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = row.get("url") or row.get("request", {}).get("endpoint")
            if url:
                insert_discovered_url(conn, workspace_id, hostname, str(url), "katana")


def parse_manifest_scan_run(conn: Any, workspace_id: int, loot_dir: Path) -> None:
    manifest = loot_dir / "manifest.json"
    if not manifest.is_file():
        return
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return
    insert_scan_run(
        conn,
        workspace_id,
        scan_id=data.get("scan_id"),
        mode=data.get("mode"),
        target=data.get("target"),
        options_json=data.get("options") or {},
        steps_json=data.get("steps") or data.get("completed_steps") or [],
        started_at=data.get("started_at"),
        finished_at=data.get("finished_at"),
    )
