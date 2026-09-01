#!/usr/bin/env python3

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from kitelon_db import (
    get_connection,
    insert_notification,
    insert_vulnerability,
    mark_imported,
    normalize_severity,
)

NESSUS_SEVERITY = {
    "0": "INFO",
    "1": "LOW",
    "2": "MEDIUM",
    "3": "HIGH",
    "4": "CRITICAL",
}

BURP_SEVERITY = {
    "information": "INFO",
    "info": "INFO",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}


def _text(elem: ET.Element | None, tag: str, default: str = "") -> str:
    if elem is None:
        return default
    child = elem.find(tag)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def _nessus_severity(item: ET.Element) -> str:
    raw = item.get("severity") or _text(item, "severity", "0")
    if raw.isdigit():
        return NESSUS_SEVERITY.get(raw, "UNKNOWN")
    return normalize_severity(raw)


def parse_nessus_xml(content: bytes | str) -> list[dict[str, Any]]:
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")
    root = ET.fromstring(content)
    findings: list[dict[str, Any]] = []

    for report_host in root.iter("ReportHost"):
        hostname = report_host.get("name") or _text(report_host, "host-ip", "unknown")
        for item in report_host.findall("ReportItem"):
            plugin_name = item.get("pluginName") or _text(item, "plugin_name", "Nessus finding")
            port = item.get("port") or _text(item, "port")
            protocol = item.get("protocol") or _text(item, "protocol")
            svc = item.get("svc_name") or _text(item, "svc_name")
            plugin_output = _text(item, "plugin_output")
            cvss = _text(item, "cvss_base_score")
            evidence_parts = [plugin_output]
            if cvss:
                evidence_parts.append(f"CVSS: {cvss}")
            if svc:
                evidence_parts.append(f"Service: {svc}")
            url = ""
            if port and port not in ("0", ""):
                scheme = "https" if svc in ("https", "ssl") or port == "443" else "http"
                url = f"{scheme}://{hostname}:{port}"

            findings.append(
                {
                    "hostname": hostname,
                    "severity": _nessus_severity(item),
                    "name": plugin_name,
                    "url": url or None,
                    "evidence": "\n".join(p for p in evidence_parts if p)[:4000] or None,
                    "meta": {
                        "plugin_id": item.get("pluginID"),
                        "port": port,
                        "protocol": protocol,
                    },
                }
            )
    return findings


def parse_burp_xml(content: bytes | str) -> list[dict[str, Any]]:
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")
    root = ET.fromstring(content)
    findings: list[dict[str, Any]] = []

    for issue in root.findall(".//issue"):
        name = _text(issue, "name", "Burp finding")
        host_elem = issue.find("host")
        hostname = "unknown"
        if host_elem is not None:
            hostname = (host_elem.text or "").strip() or host_elem.get("hostname") or host_elem.get("ip") or "unknown"
        path = _text(issue, "path")
        location = _text(issue, "location")
        severity_raw = _text(issue, "severity", "info").lower()
        severity = BURP_SEVERITY.get(severity_raw, normalize_severity(severity_raw))
        detail = _text(issue, "issueDetail") or _text(issue, "issueBackground")
        url = location or path
        if url and not url.startswith("http") and hostname != "unknown":
            url = f"https://{hostname}{path if path.startswith('/') else '/' + path if path else ''}"

        findings.append(
            {
                "hostname": hostname,
                "severity": severity,
                "name": name,
                "url": url or None,
                "evidence": detail[:4000] if detail else None,
                "meta": {"serial": _text(issue, "serialNumber")},
            }
        )
    return findings


def parse_burp_json(content: bytes | str) -> list[dict[str, Any]]:
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")
    data = json.loads(content)
    issues = data if isinstance(data, list) else data.get("issues") or data.get("issue") or []
    findings: list[dict[str, Any]] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        hostname = issue.get("host") or issue.get("hostname") or "unknown"
        if isinstance(hostname, dict):
            hostname = hostname.get("hostname") or hostname.get("ip") or "unknown"
        name = issue.get("name") or issue.get("issueName") or "Burp finding"
        severity_raw = str(issue.get("severity") or "info").lower()
        severity = BURP_SEVERITY.get(severity_raw, normalize_severity(severity_raw))
        path = issue.get("path") or ""
        url = issue.get("url") or issue.get("location")
        if not url and path and hostname != "unknown":
            url = f"https://{hostname}{path if path.startswith('/') else '/' + path}"
        detail = issue.get("issueDetail") or issue.get("issueBackground") or issue.get("description")
        findings.append(
            {
                "hostname": str(hostname),
                "severity": severity,
                "name": str(name),
                "url": url,
                "evidence": str(detail)[:4000] if detail else None,
                "meta": {},
            }
        )
    return findings


def parse_scanner_export(
    filename: str, content: bytes, scanner: str | None = None
) -> list[dict[str, Any]]:
    lower = filename.lower()
    text_start = content[:256].lstrip()
    kind = (scanner or "").strip().lower()
    if kind == "nessus" or lower.endswith(".nessus") or b"NessusClientData" in content[:4096]:
        return parse_nessus_xml(content)
    if kind == "burp":
        if lower.endswith(".json"):
            try:
                return parse_burp_json(content)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid Burp JSON: {filename}") from exc
        try:
            findings = parse_burp_xml(content)
        except ET.ParseError:
            findings = []
        if not findings:
            return parse_nessus_xml(content)
        return findings
    if lower.endswith(".json"):
        try:
            return parse_burp_json(content)
        except json.JSONDecodeError:
            pass
    if lower.endswith(".xml") or text_start.startswith(b"<?xml") or text_start.startswith(b"<"):
        try:
            return parse_burp_xml(content)
        except ET.ParseError:
            return parse_nessus_xml(content)
    raise ValueError(f"unsupported import format: {filename}")


def import_findings(
    conn: Any,
    workspace_id: int,
    findings: list[dict[str, Any]],
    *,
    source_file: str,
    source_label: str,
) -> int:
    count = 0
    for row in findings:
        insert_vulnerability(
            conn,
            workspace_id,
            row["hostname"],
            row["severity"],
            row["name"],
            row.get("url"),
            row.get("evidence"),
            source_file,
        )
        count += 1
    insert_notification(
        conn,
        workspace_id,
        f"Imported {count} finding(s) from {source_label} ({source_file})",
    )
    return count


def refresh_workspace_stats(conn: Any, workspace_id: int) -> None:
    """Recompute vulnerability stats from PostgreSQL after external import."""
    from kitelon_db import set_stat

    total = conn.execute(
        "SELECT COUNT(*) AS c FROM vulnerabilities WHERE workspace_id = %s",
        (workspace_id,),
    ).fetchone()["c"]
    set_stat(conn, workspace_id, "vulnerabilities_total", int(total))
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        key = f"vuln_{level.lower()}_total"
        n = conn.execute(
            """
            SELECT COUNT(*) AS c FROM vulnerabilities
            WHERE workspace_id = %s AND severity = %s
            """,
            (workspace_id, level),
        ).fetchone()["c"]
        set_stat(conn, workspace_id, key, int(n))


def save_import_file(
    conn: Any,
    workspace_id: int,
    loot_dir: Path,
    scanner: str,
    filename: str,
    content: bytes,
) -> str:
    from kitelon_storage import artifacts_enabled, normalize_rel_path, store_artifact

    safe = re.sub(r"[^\w.\-]+", "_", filename) or "import.xml"
    rel = normalize_rel_path(f"vulnerabilities/imports/{scanner}-{safe}")
    if artifacts_enabled():
        store_artifact(conn, workspace_id, loot_dir, rel, content)
    else:
        dest_dir = loot_dir / "vulnerabilities" / "imports"
        dest_dir.mkdir(parents=True, exist_ok=True)
        (dest_dir / f"{scanner}-{safe}").write_bytes(content)
    return Path(rel).name


def import_scanner_file(
    workspace_id: int,
    loot_dir: Path,
    scanner: str,
    filename: str,
    content: bytes,
) -> dict[str, Any]:
    findings = parse_scanner_export(filename, content, scanner)
    if not findings:
        raise ValueError("no findings parsed from upload")
    with get_connection() as conn:
        saved_name = save_import_file(conn, workspace_id, loot_dir, scanner, filename, content)
        count = import_findings(
            conn,
            workspace_id,
            findings,
            source_file=saved_name,
            source_label=scanner.upper(),
        )
        refresh_workspace_stats(conn, workspace_id)
        mark_imported(conn, workspace_id)
    return {"imported": count, "saved_as": saved_name, "scanner": scanner}
