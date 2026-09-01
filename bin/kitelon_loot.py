#!/usr/bin/env python3
"""Kitelon: import workspace loot into PostgreSQL and generate reports."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_BIN_DIR = Path(__file__).resolve().parent
if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))

from kitelon_db import (
    clear_workspace_data,
    db_enabled,
    ensure_workspace,
    fix_loot_workspace_layout,
    get_connection,
    host_vuln_counts,
    is_workspace_loot_dir,
    insert_domain,
    insert_notification,
    insert_vulnerability,
    list_domains,
    list_hosts,
    list_hosts_by_names,
    list_notifications,
    list_vulns,
    list_vulns_for_hosts,
    log,
    mark_imported,
    normalize_severity,
    set_stat,
    stat_value,
    upsert_host,
    update_host_risk_scores,
    RISK_WEIGHTS,
)
from kitelon_storage import (  # noqa: E402
    archive_loot_directory,
    artifact_api_url,
    artifacts_enabled,
    fs_mirror_enabled,
    normalize_rel_path,
    store_artifact,
    store_file_from_disk,
)
from kitelon_env import ENV_REPORT_CSS, build_environments, render_environment_section  # noqa: E402

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5,
}

SEVERITY_CSS = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#17a2b8",
    "INFO": "#6c757d",
    "UNKNOWN": "#adb5bd",
}


def severity_rank(raw: str) -> int:
    return SEVERITY_ORDER.get(normalize_severity(raw), 99)


def parse_nmap_xml(conn: Any, workspace_id: int, loot_dir: Path) -> None:
    nmap_dirs = [loot_dir / "artifacts" / "nmap", loot_dir / "nmap"]
    xml_files: list[Path] = []
    for nmap_dir in nmap_dirs:
        if nmap_dir.is_dir():
            xml_files.extend(sorted(nmap_dir.glob("*.xml")))
            xml_files.extend(sorted(nmap_dir.glob("nmap-*.xml")))
    if not xml_files:
        return

    for xml_file in xml_files:
        target = xml_file.stem.replace("nmap-", "", 1)
        try:
            root = ET.parse(xml_file).getroot()
        except ET.ParseError:
            log(f"skip invalid nmap xml: {xml_file.name}")
            continue

        hostname = target
        ip = None
        mac = None
        os_guess = None
        ports: list[str] = []

        for host in root.findall("host"):
            for addr in host.findall("address"):
                addr_type = addr.get("addrtype")
                if addr_type == "ipv4":
                    ip = addr.get("addr") or ip
                elif addr_type == "mac":
                    mac = addr.get("addr") or mac

            for osmatch in host.findall("./os/osmatch"):
                os_guess = (osmatch.get("name") or os_guess or "")[:80] or os_guess

            for port in host.findall("./ports/port"):
                if port.find("state") is not None and port.find("state").get("state") != "open":
                    continue
                port_id = port.get("portid")
                proto = port.get("protocol") or "tcp"
                service = port.find("service")
                svc_name = service.get("name") if service is not None else ""
                version = service.get("product") if service is not None else ""
                if service is not None and service.get("version"):
                    version = f"{version} {service.get('version')}".strip()
                label = f"{port_id}/{proto}"
                if svc_name:
                    label += f" ({svc_name}"
                    if version:
                        label += f" {version}"
                    label += ")"
                ports.append(label)

        ports_file = xml_file.parent / f"ports-{target}.txt"
        if not ports and ports_file.is_file():
            file_ports = [
                line.strip()
                for line in ports_file.read_text(errors="replace").splitlines()
                if line.strip()
            ]
            if file_ports:
                ports = [p if "/" in p else f"{p}/tcp" for p in file_ports]

        if not ports:
            json_ports_file = loot_dir / "artifacts" / "ports" / f"{target}.json"
            if json_ports_file.is_file():
                try:
                    import json

                    data = json.loads(json_ports_file.read_text(encoding="utf-8"))
                    ports = [f"{p}/tcp" for p in data.get("ports", [])]
                except (json.JSONDecodeError, TypeError):
                    ports = []

        mac_file = xml_file.parent / f"macaddress-{target}.txt"
        if mac_file.is_file() and not mac:
            mac = mac_file.read_text(errors="replace").strip()[:17] or None

        os_file = xml_file.parent / f"osfingerprint-{target}.txt"
        if os_file.is_file() and not os_guess:
            os_guess = os_file.read_text(errors="replace").strip()[:80] or None

        risk = 0.0
        risk_file = loot_dir / "vulnerabilities" / f"vulnerability-risk-{target}.txt"
        if risk_file.is_file():
            try:
                risk = float(risk_file.read_text(errors="replace").strip() or 0)
            except ValueError:
                risk = 0.0

        live = 1 if ip or ports else 0
        upsert_host(
            conn,
            workspace_id,
            hostname=hostname,
            ip=ip,
            mac=mac,
            os_guess=os_guess,
            is_live=live,
            risk_score=risk,
            open_ports=", ".join(ports) if ports else None,
        )


def parse_domains(conn: Any, workspace_id: int, loot_dir: Path) -> None:
    domains: set[str] = set()

    recon_json = loot_dir / "artifacts" / "recon" / "domains.json"
    if recon_json.is_file():
        try:
            import json

            data = json.loads(recon_json.read_text(encoding="utf-8"))
            domains.update(h.lower() for h in data.get("hosts", []) if h)
            if data.get("domain"):
                domains.add(str(data["domain"]).lower())
        except json.JSONDecodeError:
            pass

    sub_file = loot_dir / "artifacts" / "recon" / "subdomains.txt"
    if sub_file.is_file():
        domains.update(line.strip().lower() for line in sub_file.read_text(errors="replace").splitlines() if line.strip())

    domains_dir = loot_dir / "domains"
    if domains_dir.is_dir():
        targets_file = domains_dir / "targets.txt"
        if targets_file.is_file():
            domains.update(line.strip().lower() for line in targets_file.read_text(errors="replace").splitlines() if line.strip())
        sorted_file = domains_dir / "domains-all-sorted.txt"
        if sorted_file.is_file():
            domains.update(line.strip().lower() for line in sorted_file.read_text(errors="replace").splitlines() if line.strip())

    manifest = loot_dir / "manifest.json"
    if manifest.is_file() and not domains:
        try:
            import json

            data = json.loads(manifest.read_text(encoding="utf-8"))
            if data.get("target"):
                domains.add(str(data["target"]).lower())
        except json.JSONDecodeError:
            pass

    targets = domains
    for fqdn in sorted(domains):
        insert_domain(conn, workspace_id, fqdn, 1 if fqdn in targets else 0)
        upsert_host(conn, workspace_id, fqdn, is_live=0)


def parse_web_titles(conn: Any, workspace_id: int, loot_dir: Path) -> None:
    candidates: list[Path] = []
    for base in (loot_dir / "artifacts" / "web", loot_dir / "web"):
        if not base.is_dir():
            continue
        for host_dir in base.iterdir():
            if host_dir.is_dir():
                title = host_dir / "title.txt"
                if title.is_file():
                    candidates.append(title)
        candidates.extend(base.glob("title-*"))

    for title_file in candidates:
        if title_file.parent.name not in ("web", "artifacts"):
            target = title_file.parent.name
            title = title_file.read_text(errors="replace").strip()
            if title:
                upsert_host(conn, workspace_id, target, web_title=title[:200])
            continue

        name = title_file.name
        match = re.match(r"title-(https?)-(.+)\.txt$", name)
        if match:
            target = match.group(2).split("-port")[0]
        else:
            continue
        title = title_file.read_text(errors="replace").strip()
        if title:
            upsert_host(conn, workspace_id, target, web_title=title[:200])


def parse_findings_jsonl(conn: Any, workspace_id: int, loot_dir: Path) -> None:
    from kitelon_engine.findings import parse_findings_jsonl as load_findings

    findings_path = loot_dir / "findings.jsonl"
    for row in load_findings(findings_path):
        severity = normalize_severity(str(row.get("severity", "info")))
        name = str(row.get("name", "")).strip()
        if not name:
            continue
        url = str(row.get("url", "")).strip()
        hostname = str(row.get("hostname", "")).strip()
        if not hostname:
            host_match = re.search(r"://([^/:]+)", url)
            hostname = host_match.group(1) if host_match else url
        evidence = str(row.get("evidence", ""))
        source_file = str(row.get("source_file", "findings.jsonl"))
        insert_vulnerability(
            conn,
            workspace_id,
            hostname,
            severity,
            name,
            url or hostname,
            evidence,
            source_file,
            source=str(row.get("source") or "") or None,
            cve=str(row.get("cve") or "") or None,
            cwe=str(row.get("cwe") or "") or None,
        )
        upsert_host(conn, workspace_id, hostname)


def parse_notifications(conn: Any, workspace_id: int, loot_dir: Path) -> None:
    scans_dir = loot_dir / "scans"
    if not scans_dir.is_dir():
        return

    notifications: list[str] = []
    for fname in ("notifications.txt", "notifications_new.txt"):
        path = scans_dir / fname
        if path.is_file():
            notifications.extend(line.strip() for line in path.read_text(errors="replace").splitlines() if line.strip())

    for message in notifications[-500:]:
        insert_notification(conn, workspace_id, message)


def compute_workspace_stats(conn: Any, workspace_id: int, loot_dir: Path) -> None:
    scans_dir = loot_dir / "scans"
    stats: dict[str, int] = {}

    def count_lines(path: Path) -> int:
        if not path.is_file():
            return 0
        return sum(1 for line in path.read_text(errors="replace").splitlines() if line.strip())

    stats["notifications_total"] = count_lines(scans_dir / "notifications.txt")
    stats["notifications_new_total"] = count_lines(scans_dir / "notifications_new.txt")
    stats["tasks_total"] = count_lines(scans_dir / "tasks.txt")

    manifest = loot_dir / "manifest.json"
    if manifest.is_file() and not stats["tasks_total"]:
        try:
            import json

            data = json.loads(manifest.read_text(encoding="utf-8"))
            steps = data.get("steps") or data.get("completed_steps") or []
            if isinstance(steps, list):
                stats["tasks_total"] = len(steps)
        except json.JSONDecodeError:
            pass

    tasks_running = scans_dir / "tasks-running.txt"
    if tasks_running.is_file():
        try:
            stats["tasks_running_total"] = int(tasks_running.read_text(errors="replace").strip() or 0)
        except ValueError:
            stats["tasks_running_total"] = 0

    scheduled = list(scans_dir.glob("scheduled/*.sh")) if (scans_dir / "scheduled").is_dir() else []
    stats["scheduled_tasks_total"] = len(scheduled)

    notif_text = (scans_dir / "notifications.txt").read_text(errors="replace") if (scans_dir / "notifications.txt").is_file() else ""
    stats["host_status_changes_total"] = notif_text.count("Host status")
    stats["port_changes_total"] = notif_text.count("Port change")

    domain_new = list((loot_dir / "domains").glob("domains_new-*.txt")) if (loot_dir / "domains").is_dir() else []
    stats["domain_changes_total"] = sum(count_lines(p) for p in domain_new)

    url_files = []
    web_dir = loot_dir / "web"
    if web_dir.is_dir():
        url_files.extend(web_dir.glob("dirsearch-new-*.txt"))
        url_files.extend(web_dir.glob("spider-new-*.txt"))
    stats["url_changes_total"] = sum(count_lines(p) for p in url_files)

    stats["hosts_total"] = conn.execute(
        "SELECT COUNT(*) AS c FROM hosts WHERE workspace_id = %s", (workspace_id,)
    ).fetchone()["c"]
    stats["domains_total"] = conn.execute(
        "SELECT COUNT(*) AS c FROM domains WHERE workspace_id = %s", (workspace_id,)
    ).fetchone()["c"]
    stats["vulnerabilities_total"] = conn.execute(
        "SELECT COUNT(*) AS c FROM vulnerabilities WHERE workspace_id = %s", (workspace_id,)
    ).fetchone()["c"]

    for level in SEVERITY_ORDER:
        if level == "UNKNOWN":
            continue
        stats[f"vuln_{level.lower()}_total"] = conn.execute(
            """
            SELECT COUNT(*) AS c FROM vulnerabilities
            WHERE workspace_id = %s AND severity = %s
            """,
            (workspace_id, level),
        ).fetchone()["c"]

    risk_total = 0
    for level, weight in RISK_WEIGHTS.items():
        risk_total += int(stats.get(f"vuln_{level.lower()}_total", 0)) * weight
    stats["workspace_risk_score"] = risk_total

    for key, value in stats.items():
        set_stat(conn, workspace_id, key, int(value))


def write_legacy_totals(loot_dir: Path, stats: dict[str, int]) -> None:
    scans_dir = loot_dir / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    mapping = {
        "notifications_total.txt": "notifications_total",
        "notifications_new_total.txt": "notifications_new_total",
        "tasks-running_total.txt": "tasks_running_total",
        "tasks_total.txt": "tasks_total",
        "scheduled_tasks_total.txt": "scheduled_tasks_total",
        "host_status_changes_total.txt": "host_status_changes_total",
        "port_changes_total.txt": "port_changes_total",
        "domain_changes_total.txt": "domain_changes_total",
        "url_changes_total.txt": "url_changes_total",
    }
    for filename, key in mapping.items():
        (scans_dir / filename).write_text(str(stats.get(key, 0)), encoding="utf-8")

    vuln_score = loot_dir / "vulnerabilities" / "vuln_score_total.txt"
    vuln_score.parent.mkdir(parents=True, exist_ok=True)
    vuln_score.write_text(str(stats.get("workspace_risk_score", 0)), encoding="utf-8")


def import_loot(loot_dir: Path, workspace: str) -> None:
    loot_dir = loot_dir.resolve()
    if not loot_dir.is_dir():
        raise ValueError(f"loot directory not found: {loot_dir}")

    if not db_enabled():
        log("DB_ENABLED=0: skipping PostgreSQL import")
        return

    loot_root = loot_dir.parent.parent
    fix_loot_workspace_layout(loot_root)
    from kitelon_db import confined_workspace_loot_path  # noqa: E402

    canonical = confined_workspace_loot_path(loot_root, workspace)
    if canonical != loot_dir and is_workspace_loot_dir(canonical):
        loot_dir = canonical

    with get_connection() as conn:
        workspace_id = ensure_workspace(conn, workspace, loot_root=loot_root)
        clear_workspace_data(conn, workspace_id)

        parse_domains(conn, workspace_id, loot_dir)
        parse_nmap_xml(conn, workspace_id, loot_dir)
        parse_web_titles(conn, workspace_id, loot_dir)
        parse_findings_jsonl(conn, workspace_id, loot_dir)
        parse_notifications(conn, workspace_id, loot_dir)
        from kitelon_loot_enrich import (  # noqa: E402
            parse_dir_brute,
            parse_httpx_artifacts,
            parse_katana_urls,
            parse_manifest_scan_run,
            parse_services_from_nmap,
            parse_webtech,
        )

        parse_services_from_nmap(conn, workspace_id, loot_dir)
        parse_httpx_artifacts(conn, workspace_id, loot_dir)
        parse_webtech(conn, workspace_id, loot_dir)
        parse_dir_brute(conn, workspace_id, loot_dir)
        parse_katana_urls(conn, workspace_id, loot_dir)
        parse_manifest_scan_run(conn, workspace_id, loot_dir)
        from kitelon_testssl import import_testssl_findings  # noqa: E402

        import_testssl_findings(conn, workspace_id, loot_dir)
        update_host_risk_scores(conn, workspace_id)
        compute_workspace_stats(conn, workspace_id, loot_dir)
        mark_imported(conn, workspace_id)
        if artifacts_enabled():
            archived = archive_loot_directory(conn, workspace_id, loot_dir)
            log(f"archived {archived} artifact(s) to PostgreSQL")

    from kitelon_testssl import write_ssl_html_report  # noqa: E402

    write_ssl_html_report(loot_dir, workspace)

    log(f"imported loot from {loot_dir} into PostgreSQL (workspace={workspace})")


def write_host_csv(loot_dir: Path, workspace: str) -> Path:
    reports_dir = loot_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    csv_path = reports_dir / "host-table-report.csv"

    with get_connection() as conn:
        ws = conn.execute(
            "SELECT id FROM workspaces WHERE alias = %s", (workspace,)
        ).fetchone()
        if not ws:
            raise ValueError(f"workspace not found in database: {workspace}")
        workspace_id = int(ws["id"])
        hosts = list_hosts(conn, workspace_id, limit=100000)

        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "hostname",
                    "ip",
                    "mac",
                    "os",
                    "live",
                    "open_ports",
                    "web_title",
                    "risk_score",
                    "critical",
                    "high",
                    "medium",
                    "low",
                    "info",
                ]
            )
            for host in hosts:
                counts = host_vuln_counts(conn, workspace_id, host["hostname"])
                writer.writerow(
                    [
                        host["hostname"],
                        host["ip"] or "",
                        host["mac"] or "",
                        host["os_guess"] or "",
                        host["is_live"],
                        host["open_ports"] or "",
                        host["web_title"] or "",
                        host["risk_score"],
                        counts["critical"],
                        counts["high"],
                        counts["medium"],
                        counts["low"],
                        counts["info"],
                    ]
                )

    log(f"wrote {csv_path}")
    if artifacts_enabled():
        with get_connection() as conn:
            store_file_from_disk(conn, workspace_id, loot_dir, csv_path)
    return csv_path


def severity_badge(sev: str) -> str:
    label = normalize_severity(sev)
    color = SEVERITY_CSS.get(label, "#adb5bd")
    return (
        f"<span class='badge sev-{label.lower()}' "
        f"style='background:{color}'>{html.escape(label)}</span>"
    )


def vuln_count_badges(counts: dict[str, int]) -> str:
    parts: list[str] = []
    for key, label in (
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
        ("info", "Info"),
    ):
        count = counts.get(key, 0)
        if not count:
            continue
        sev = label.upper() if label != "Info" else "INFO"
        color = SEVERITY_CSS.get(sev, "#adb5bd")
        parts.append(
            f"<span class='mini-badge' style='background:{color}' "
            f"title='{label}'>{count}</span>"
        )
    return " ".join(parts) if parts else "<span class='muted'>-</span>"


def risk_score_class(score: int | float | None) -> str:
    if score is None:
        return "risk-none"
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "risk-none"
    if value <= 0:
        return "risk-none"
    if value >= 80:
        return "risk-high"
    if value >= 40:
        return "risk-medium"
    return "risk-low"


SUMMARY_STAT_DEFS: list[tuple[str, str, str]] = [
    ("workspace_risk_score", "Risk score", "risk"),
    ("hosts_total", "Hosts", ""),
    ("domains_total", "Domains", ""),
    ("vulnerabilities_total", "Findings", ""),
    ("vuln_critical_total", "Critical", "critical"),
    ("vuln_high_total", "High", "high"),
    ("port_changes_total", "Port changes", ""),
    ("tasks_total", "Scan tasks", ""),
]


def render_summary_stats_html(values: dict[str, int]) -> str:
    """Risk score banner on top; remaining metrics in a wrapped tile row."""
    hero_key, hero_label, hero_css = SUMMARY_STAT_DEFS[0]
    hero_mod = f" stat-{hero_css}" if hero_css else ""
    hero = (
        f"<div class='stat-hero{hero_mod}'>"
        f"<div class='stat-hero-copy'>"
        f"<span class='stat-hero-label'>{html.escape(hero_label)}</span>"
        f"<span class='stat-hero-sub'>Workspace aggregate from imported findings</span>"
        f"</div>"
        f"<span class='stat-hero-num'>{values.get(hero_key, 0)}</span>"
        f"</div>"
    )
    metrics: list[str] = []
    for key, label, css in SUMMARY_STAT_DEFS[1:]:
        mod = f" stat-{css}" if css else ""
        metrics.append(
            f"<div class='stat-metric{mod}'>"
            f"<span class='stat-num'>{values.get(key, 0)}</span>"
            f"<span class='stat-label'>{html.escape(label)}</span>"
            f"</div>"
        )
    return (
        f"<div class='summary-dashboard'>{hero}"
        f"<div class='stats-grid'>{''.join(metrics)}</div></div>"
    )


def format_evidence(raw: str | None, limit: int = 180) -> str:
    text = (raw or "").strip()
    if not text:
        return "<span class='muted'>-</span>"
    escaped = html.escape(text)
    if len(text) <= limit:
        return f"<code class='evidence'>{escaped}</code>"
    short = html.escape(text[:limit].rstrip()) + "…"
    return (
        f"<details class='evidence-details'>"
        f"<summary><code class='evidence'>{short}</code></summary>"
        f"<pre class='evidence-full'>{escaped}</pre>"
        f"</details>"
    )


def format_url(raw: str | None) -> str:
    from urllib.parse import urlparse

    url = (raw or "").strip()
    if not url:
        return "<span class='muted'>-</span>"
    safe = html.escape(url)
    try:
        parsed = urlparse(url)
    except ValueError:
        parsed = None
    if parsed and parsed.scheme in ("http", "https") and parsed.netloc:
        return f"<a class='ext-link' href='{safe}' target='_blank' rel='noopener'>{safe}</a>"
    return f"<code>{safe}</code>"


REPORT_CSS = """
    :root {
      --bg: #0f1117;
      --panel: #171b24;
      --text: #e8ecf1;
      --muted: #9aa4b2;
      --accent: #e74c3c;
      --border: #2a3140;
      --row-alt: rgba(255,255,255,.025);
      --link: #7cb5ff;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      font-size: 15px;
    }
    .page { max-width: 1100px; margin: 0 auto; }
    header {
      padding: 1.75rem 2rem 1.25rem;
      border-bottom: 1px solid var(--border);
      background: linear-gradient(180deg, #1b2130, var(--panel));
    }
    h1 { margin: 0 0 .35rem; font-size: 1.85rem; letter-spacing: -.02em; }
    .sub { color: var(--muted); font-size: .95rem; }
    .links { margin-top: .75rem; }
    .links a {
      color: var(--link);
      margin-right: 1rem;
      text-decoration: none;
    }
    .links a:hover { text-decoration: underline; }
    main { padding: 1.5rem 2rem 3rem; }
    section {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.25rem 1.35rem;
      margin-bottom: 1.35rem;
    }
    h2 {
      margin: 0 0 1rem;
      font-size: 1.15rem;
      color: #fff;
      display: flex;
      align-items: baseline;
      gap: .5rem;
      flex-wrap: wrap;
    }
    h2 .count {
      color: var(--muted);
      font-size: .85rem;
      font-weight: 500;
    }
    h3.sev-heading {
      margin: 1.25rem 0 .65rem;
      font-size: .95rem;
      display: flex;
      align-items: center;
      gap: .5rem;
    }
    h3.sev-heading:first-child { margin-top: 0; }
    .summary-section {
      background: transparent;
      border: none;
      padding: 0;
      margin-bottom: 1.5rem;
    }
    .summary-dashboard {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    .stat-hero {
      display: flex;
      flex-direction: row;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 1.25rem 1.5rem;
      background: linear-gradient(120deg, rgba(231, 76, 60, .18), #11151d 58%);
      border: 1px solid var(--border);
      border-radius: 12px;
    }
    .stat-hero-copy {
      display: flex;
      flex-direction: column;
      gap: .2rem;
      min-width: 0;
    }
    .stat-hero-num {
      font-size: 3rem;
      font-weight: 800;
      line-height: 1;
      color: #fff;
      flex-shrink: 0;
    }
    .stat-hero-label {
      color: #fff;
      font-size: .85rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .08em;
    }
    .stat-hero-sub {
      color: var(--muted);
      font-size: .82rem;
    }
    .stat-hero.stat-risk .stat-hero-num { color: var(--accent); }
    .stats-grid {
      display: flex;
      flex-wrap: wrap;
      gap: .75rem;
    }
    .stat-metric {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: .35rem;
      flex: 1 1 calc(25% - .75rem);
      min-width: 9.5rem;
      background: #11151d;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem .75rem;
      text-align: center;
    }
    .stat-metric .stat-num {
      font-size: 1.75rem;
      font-weight: 700;
      line-height: 1;
      color: #fff;
    }
    .stat-metric .stat-label {
      color: var(--muted);
      font-size: .72rem;
      text-transform: uppercase;
      letter-spacing: .04em;
    }
    .stat-metric.stat-critical .stat-num { color: #dc3545; }
    .stat-metric.stat-high .stat-num { color: #fd7e14; }
    @media (max-width: 720px) {
      .stat-hero {
        flex-direction: column;
        align-items: flex-start;
      }
      .stat-metric {
        flex: 1 1 calc(50% - .75rem);
        min-width: calc(50% - .75rem);
      }
    }
    .table-wrap {
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: 8px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: .88rem;
    }
    th, td {
      padding: .65rem .75rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
      text-align: left;
    }
    th {
      color: var(--muted);
      font-weight: 600;
      font-size: .72rem;
      text-transform: uppercase;
      letter-spacing: .04em;
      background: #11151d;
      position: sticky;
      top: 0;
      z-index: 1;
    }
    tbody tr:nth-child(even) td { background: var(--row-alt); }
    tbody tr:hover td { background: rgba(255,255,255,.04); }
    tbody tr:last-child td { border-bottom: none; }
    .col-host { min-width: 9rem; word-break: break-word; }
    .col-finding { min-width: 14rem; word-break: break-word; }
    .col-url { min-width: 10rem; max-width: 18rem; word-break: break-all; }
    .col-ports { min-width: 8rem; max-width: 14rem; }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: .82rem;
      word-break: break-word;
    }
    code.ports { display: block; white-space: pre-wrap; }
    .badge {
      display: inline-block;
      padding: .2rem .55rem;
      border-radius: 999px;
      color: #111;
      font-size: .68rem;
      font-weight: 700;
      letter-spacing: .03em;
      white-space: nowrap;
    }
    .mini-badge {
      display: inline-block;
      min-width: 1.35rem;
      padding: .12rem .35rem;
      border-radius: 999px;
      color: #111;
      font-size: .72rem;
      font-weight: 700;
      text-align: center;
      margin-right: .15rem;
    }
    .risk-pill {
      display: inline-block;
      min-width: 2rem;
      padding: .15rem .45rem;
      border-radius: 6px;
      font-weight: 700;
      font-size: .82rem;
      text-align: center;
    }
    .risk-high { background: rgba(220,53,69,.2); color: #ff8a96; }
    .risk-medium { background: rgba(253,126,20,.18); color: #ffb366; }
    .risk-low { background: rgba(46,204,113,.15); color: #7dcea0; }
    .risk-none { color: var(--muted); }
    .muted { color: var(--muted); }
    .ext-link { color: var(--link); word-break: break-all; }
    .evidence-details summary {
      cursor: pointer;
      list-style: none;
    }
    .evidence-details summary::-webkit-details-marker { display: none; }
    .evidence-full {
      margin: .5rem 0 0;
      padding: .65rem .75rem;
      background: #11151d;
      border: 1px solid var(--border);
      border-radius: 6px;
      white-space: pre-wrap;
      word-break: break-word;
      font-size: .78rem;
      max-height: 12rem;
      overflow: auto;
    }
    .domain-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
      gap: .35rem .85rem;
      list-style: none;
      margin: 0;
      padding: 0;
    }
    .domain-grid li {
      padding: .35rem .5rem;
      background: #11151d;
      border: 1px solid var(--border);
      border-radius: 6px;
      font-size: .88rem;
      word-break: break-all;
    }
    .domain-grid .target { border-color: #3d4a63; }
    .notif-list {
      margin: 0;
      padding-left: 1.1rem;
    }
    .notif-list li { margin: .4rem 0; }
    .empty-row td {
      color: var(--muted);
      font-style: italic;
      padding: 1rem .75rem;
    }
    .subset-banner { margin-top: .5rem; color: #ffb366; }
    @media print {
      :root {
        --bg: #fff;
        --panel: #fff;
        --text: #1a1a1a;
        --muted: #555;
        --border: #ddd;
        --row-alt: #f7f7f9;
        --link: #0645ad;
      }
      body { font-size: 11pt; background: #fff; color: #1a1a1a; }
      header { background: #fff; border-bottom: 2px solid #333; }
      section { break-inside: avoid-page; box-shadow: none; }
      h3.sev-heading { break-after: avoid; }
      .table-wrap { overflow: visible; border: none; }
      th { background: #eee; color: #333; position: static; }
      .evidence-details[open] summary { display: none; }
      .evidence-full { max-height: none; border-color: #ccc; background: #f9f9f9; }
      a { color: #0645ad; text-decoration: none; }
    }
"""


def subset_report_paths(loot_dir: Path, hostnames: list[str]) -> tuple[Path, Path]:
    digest = hashlib.sha256("\n".join(sorted(hostnames)).encode()).hexdigest()[:12]
    reports_dir = loot_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    html_path = reports_dir / f"subset-{digest}.html"
    pdf_path = reports_dir / f"subset-{digest}.pdf"
    return html_path, pdf_path


def compute_subset_stats(
    conn: Any, workspace_id: int, hosts: list[dict[str, Any]], vulns: list[dict[str, Any]]
) -> dict[str, int]:
    stats: dict[str, int] = {"hosts_total": len(hosts), "domains_total": 0}
    stats["vulnerabilities_total"] = len(vulns)
    for level in SEVERITY_ORDER:
        if level == "UNKNOWN":
            continue
        stats[f"vuln_{level.lower()}_total"] = sum(
            1 for v in vulns if normalize_severity(v["severity"]) == level
        )
    risk_scores = [float(h.get("risk_score") or 0) for h in hosts]
    stats["workspace_risk_score"] = int(max(risk_scores)) if risk_scores else 0
    stats["port_changes_total"] = 0
    stats["tasks_total"] = 0
    return stats


def write_html_report(
    loot_dir: Path,
    workspace: str,
    hostnames: list[str] | None = None,
    output_path: Path | None = None,
) -> Path:
    report_path = output_path or (loot_dir / "kitelon-report.html")
    host_filter = [h.strip() for h in (hostnames or []) if h and h.strip()] or None

    with get_connection() as conn:
        ws = conn.execute(
            "SELECT * FROM workspaces WHERE alias = %s", (workspace,)
        ).fetchone()
        if not ws:
            raise ValueError(f"workspace not found in database: {workspace}")
        workspace_id = int(ws["id"])
        imported_label = (
            ws["last_imported_at"].isoformat()
            if ws.get("last_imported_at")
            else "unknown"
        )

        hosts = list_hosts(conn, workspace_id, limit=10000)
        domains = list_domains(conn, workspace_id, limit=500)
        vulns = list_vulns(conn, workspace_id, limit=1000)
        if host_filter:
            host_set = set(host_filter)
            hosts = [h for h in hosts if h["hostname"] in host_set]
            missing = host_set - {h["hostname"] for h in hosts}
            if missing:
                hosts.extend(list_hosts_by_names(conn, workspace_id, sorted(missing)))
            vulns = list_vulns_for_hosts(conn, workspace_id, list(host_set), limit=5000)
            domains = [d for d in domains if d["fqdn"] in host_set]
            notifications = []
            subset_stats = compute_subset_stats(conn, workspace_id, hosts, vulns)
            stats_html = render_summary_stats_html(subset_stats)
        else:
            notifications = list_notifications(conn, workspace_id, limit=100)
            stats_html = render_summary_stats_html(
                {
                    key: stat_value(conn, workspace_id, key)
                    for key, _, _ in SUMMARY_STAT_DEFS
                }
            )
        vulns.sort(key=lambda row: (severity_rank(row["severity"]), row["hostname"], row["name"]))

        host_rows = []
        for host in hosts:
            counts = host_vuln_counts(conn, workspace_id, host["hostname"])
            risk_class = risk_score_class(host.get("risk_score"))
            risk_value = host.get("risk_score")
            risk_display = (
                f"<span class='risk-pill {risk_class}'>{html.escape(str(risk_value))}</span>"
                if risk_value not in (None, "")
                else "<span class='muted'>-</span>"
            )
            ports = html.escape(host["open_ports"] or "")
            host_rows.append(
                "<tr>"
                f"<td class='col-host'><strong>{html.escape(host['hostname'])}</strong></td>"
                f"<td>{html.escape(host['ip'] or '-')}</td>"
                f"<td>{html.escape(host['os_guess'] or '-')}</td>"
                f"<td class='col-ports'><code class='ports'>{ports or '-'}</code></td>"
                f"<td>{html.escape(host['web_title'] or '-')}</td>"
                f"<td>{risk_display}</td>"
                f"<td>{vuln_count_badges(counts)}</td>"
                "</tr>"
            )

        sev_counts: dict[str, int] = {}
        for vuln in vulns:
            label = normalize_severity(vuln["severity"])
            sev_counts[label] = sev_counts.get(label, 0) + 1

        findings_sections: list[str] = []
        if vulns:
            current_sev = None
            rows: list[str] = []
            for vuln in vulns:
                sev = normalize_severity(vuln["severity"])
                if sev != current_sev:
                    if rows:
                        findings_sections.append(
                            "<div class='table-wrap'><table>"
                            "<thead><tr>"
                            "<th>Host</th><th>Finding</th><th>URL</th><th>Evidence</th>"
                            "</tr></thead><tbody>"
                            + "".join(rows)
                            + "</tbody></table></div>"
                        )
                        rows = []
                    current_sev = sev
                    findings_sections.append(
                        f"<h3 class='sev-heading'>{severity_badge(sev)} "
                        f"<span class='count'>{sev_counts.get(sev, 0)} finding(s)</span></h3>"
                    )
                rows.append(
                    "<tr>"
                    f"<td class='col-host'>{html.escape(vuln['hostname'])}</td>"
                    f"<td class='col-finding'>{html.escape(vuln['name'])}</td>"
                    f"<td class='col-url'>{format_url(vuln.get('url'))}</td>"
                    f"<td>{format_evidence(vuln.get('evidence'))}</td>"
                    "</tr>"
                )
            if rows:
                findings_sections.append(
                    "<div class='table-wrap'><table>"
                    "<thead><tr>"
                    "<th>Host</th><th>Finding</th><th>URL</th><th>Evidence</th>"
                    "</tr></thead><tbody>"
                    + "".join(rows)
                    + "</tbody></table></div>"
                )
        findings_html = (
            "".join(findings_sections)
            if findings_sections
            else "<p class='muted'>No findings imported yet.</p>"
        )

        domain_items = "".join(
            f"<li class='{'target' if row['is_target'] else ''}'>"
            f"{'<strong>Target</strong> · ' if row['is_target'] else ''}"
            f"{html.escape(row['fqdn'])}</li>"
            for row in domains
        )
        notif_items = "".join(
            f"<li>{html.escape(str(row['message']))}</li>" for row in notifications
        )

        subset_label = ""
        if host_filter:
            shown = ", ".join(html.escape(h) for h in host_filter[:8])
            extra = len(host_filter) - 8
            if extra > 0:
                shown += f" … +{extra} more"
            subset_label = (
                f"<div class='sub subset-banner'>Subset report: {len(host_filter)} host(s): {shown}</div>"
            )

        env_hostnames = sorted({h["hostname"] for h in hosts})
        env_profiles = build_environments(env_hostnames, loot_dir, conn, workspace_id)
        env_html = render_environment_section(
            env_profiles,
            workspace,
            for_client=True,
        )

        content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Kitelon Report: {html.escape(workspace)}</title>
  <style>{REPORT_CSS}{ENV_REPORT_CSS}</style>
</head>
<body>
  <div class="page">
    <header>
      <h1>Kitelon Workspace Report</h1>
      <div class="sub">Workspace: <strong>{html.escape(workspace)}</strong> · Last import: {html.escape(imported_label)}</div>
      {subset_label}
    </header>
    <main>
      <section class="summary-section">
        {stats_html}
      </section>
      <section>
        <h2>Observed environment &amp; security controls
          <span class="count">{len(env_profiles)} host(s)</span></h2>
        {env_html}
      </section>
      <section>
        <h2>Findings <span class="count">{len(vulns)} total</span></h2>
        {findings_html}
      </section>
      <section>
        <h2>Hosts <span class="count">{len(hosts)} total</span></h2>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Host</th><th>IP</th><th>OS</th><th>Ports</th><th>Web title</th>
                <th>Risk</th><th>Findings</th>
              </tr>
            </thead>
            <tbody>
              {''.join(host_rows) if host_rows else '<tr class="empty-row"><td colspan="7">No hosts imported yet.</td></tr>'}
            </tbody>
          </table>
        </div>
      </section>
      <section>
        <h2>Domains <span class="count">{len(domains)} shown</span></h2>
        <ul class="domain-grid">{domain_items or '<li class="muted">No domains discovered.</li>'}</ul>
      </section>
      <section>
        <h2>Recent notifications <span class="count">{len(notifications)} shown</span></h2>
        <ul class="notif-list">{notif_items or '<li class="muted">No notifications.</li>'}</ul>
      </section>
    </main>
  </div>
</body>
</html>
"""

        rel = normalize_rel_path(report_path.relative_to(loot_dir))
        if fs_mirror_enabled() or not artifacts_enabled():
            report_path.write_text(content, encoding="utf-8")
        if artifacts_enabled():
            store_artifact(conn, workspace_id, loot_dir, rel, content)
        log(f"wrote {rel}")
        return report_path


def generate_reports(
    loot_dir: Path,
    workspace: str,
    hostnames: list[str] | None = None,
) -> Path:
    if not db_enabled():
        log("DB_ENABLED=0: skipping report generation from PostgreSQL")
        return loot_dir / "kitelon-report.html"
    if hostnames:
        html_path, _ = subset_report_paths(loot_dir, hostnames)
        from kitelon_pentest_report import write_pentest_html_report  # noqa: E402

        write_pentest_html_report(loot_dir, workspace, hostnames=hostnames)
        write_html_report(loot_dir, workspace, hostnames=hostnames, output_path=html_path)
        return html_path
    write_host_csv(loot_dir, workspace)
    from kitelon_testssl import process_testssl_scans  # noqa: E402

    process_testssl_scans(loot_dir, workspace)
    from kitelon_pentest_report import write_pentest_html_report  # noqa: E402

    write_pentest_html_report(loot_dir, workspace)
    return write_html_report(loot_dir, workspace)


def main() -> None:
    parser = argparse.ArgumentParser(description="Kitelon loot importer and report generator")
    parser.add_argument("--loot-dir", required=True, help="Workspace loot directory")
    parser.add_argument("--workspace", required=True, help="Workspace alias")
    parser.add_argument(
        "--action",
        choices=("all", "import", "report"),
        default="all",
        help="Run import, report generation, or both",
    )
    parser.add_argument(
        "--hosts",
        help="Comma-separated hostnames for subset HTML report",
    )
    args = parser.parse_args()

    loot_dir = Path(args.loot_dir)
    hostnames = [h.strip() for h in args.hosts.split(",")] if args.hosts else None
    if args.action in ("all", "import"):
        import_loot(loot_dir, args.workspace)
    if args.action in ("all", "report"):
        generate_reports(loot_dir, args.workspace, hostnames=hostnames)


if __name__ == "__main__":
    main()
