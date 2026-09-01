#!/usr/bin/env python3
"""Parse testssl.sh JSON output and generate Kitelon-styled SSL/TLS reports."""

from __future__ import annotations

import argparse
import html
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import quote

_BIN_DIR = Path(__file__).resolve().parent
if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))

from kitelon_db import (  # noqa: E402
    ensure_workspace,
    get_connection,
    insert_notification,
    insert_vulnerability,
    log,
    normalize_severity,
    set_stat,
    upsert_host,
)
from kitelon_loot import REPORT_CSS, severity_badge  # noqa: E402
from kitelon_storage import (  # noqa: E402
    artifact_api_url,
    artifacts_enabled,
    fs_mirror_enabled,
    normalize_rel_path,
    store_artifact,
    store_file_from_disk,
)

SSL_REPORT_INDEX = "reports/ssl-report.html"

from kitelon_env import (  # noqa: E402
    SSL_REPORT_CSS,
    SSL_REPORT_INDEX_PDF,
    extract_ssl_rating,
    grade_from_testssl_log,
    ssl_report_pdf_rel_path,
    ssl_report_rel_path,
)

TESTSSL_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "WARN": "LOW",
    "WARNING": "LOW",
    "INFO": "INFO",
    "OK": "INFO",
    "NOT ok": "HIGH",
    "NOT OK": "HIGH",
    "FATAL": "CRITICAL",
    "DEBUG": "INFO",
}


def _map_testssl_severity(raw: str) -> str:
    text = (raw or "").strip()
    upper = text.upper()
    if upper in TESTSSL_SEVERITY_MAP:
        return TESTSSL_SEVERITY_MAP[upper]
    if "not ok" in text.lower():
        return "HIGH"
    if "critical" in upper:
        return "CRITICAL"
    if "high" in upper:
        return "HIGH"
    if "medium" in upper:
        return "MEDIUM"
    if "low" in upper or "warn" in upper:
        return "LOW"
    return normalize_severity(text)


def _should_import_finding(severity: str, finding: str) -> bool:
    sev = _map_testssl_severity(severity)
    text = finding.lower()
    if sev in ("CRITICAL", "HIGH", "MEDIUM"):
        return True
    if "vulnerable" in text or "not ok" in text or "expired" in text:
        return True
    if "sslv2" in text or "sslv3" in text or "rc4" in text or "weak" in text:
        return True
    return sev == "LOW" and ("deprecated" in text or "insecure" in text)


def _iter_finding_dicts(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, list):
        for item in node:
            yield from _iter_finding_dicts(item)
    elif isinstance(node, dict):
        if "finding" in node and ("severity" in node or "id" in node):
            yield node
        for value in node.values():
            if isinstance(value, (list, dict)):
                yield from _iter_finding_dicts(value)


def parse_testssl_file(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return {"target": "", "port": "", "findings": []}

    target = ""
    port = ""
    findings: list[dict[str, str]] = []

    match = re.match(r"testssl-(.+)-(\d+)\.json$", path.name)
    if match:
        target, port = match.group(1), match.group(2)
    else:
        alt = re.match(r"(.+)-(\d+)\.json$", path.name)
        if alt:
            target, port = alt.group(1), alt.group(2)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"target": target, "port": port, "findings": findings}

    if isinstance(data, dict):
        target = str(data.get("targetHost") or data.get("host") or target)
        port = str(data.get("port") or port)

    for item in _iter_finding_dicts(data):
        finding = str(item.get("finding") or "").strip()
        if not finding:
            continue
        sev = str(item.get("severity") or item.get("level") or "INFO")
        entry = {
            "id": str(item.get("id") or item.get("cwe") or ""),
            "severity": sev,
            "finding": finding,
            "cve": str(item.get("cve") or ""),
            "cwe": str(item.get("cwe") or ""),
        }
        findings.append(entry)

    result = {"target": target, "port": port, "findings": findings}
    rating = extract_ssl_rating(result)
    if not rating.get("grade"):
        log_path = path.with_suffix(".log")
        if log_path.is_file():
            grade = grade_from_testssl_log(log_path.read_text(encoding="utf-8", errors="replace"))
            if grade:
                findings.append(
                    {
                        "id": "overall_grade",
                        "severity": "OK",
                        "finding": grade,
                        "cve": "",
                        "cwe": "",
                    }
                )
                result["findings"] = findings
    return result


def _scan_label(scan: dict[str, Any]) -> str:
    host = scan.get("target") or "unknown"
    port = scan.get("port") or "443"
    return f"{host}:{port}"


def _check_label(item: dict[str, Any]) -> str:
    """Human-readable name for the testssl check being evaluated."""
    check_id = str(item.get("id") or "").strip()
    if check_id:
        return check_id.replace("_", " ")
    meta = [p for p in (item.get("cwe"), item.get("cve")) if p]
    if meta:
        return " · ".join(str(p) for p in meta)
    return "General"


def _finding_rows(scan: dict[str, Any]) -> str:
    rows: list[str] = []
    for item in scan.get("findings") or []:
        sev = _map_testssl_severity(item.get("severity", "INFO"))
        check = html.escape(_check_label(item))
        rows.append(
            "<tr>"
            f"<td>{severity_badge(sev)}</td>"
            f"<td><code>{check}</code></td>"
            f"<td>{html.escape(item.get('finding', ''))}</td>"
            "</tr>"
        )
    if not rows:
        return "<tr class='empty-row'><td colspan='3'>No SSL/TLS findings recorded.</td></tr>"
    return "".join(rows)


def _grade_css_class(grade: str | None) -> str:
    if not grade:
        return "grade-unknown"
    g = grade.strip().upper()
    if g == "A+":
        return "grade-aplus"
    if g == "A-":
        return "grade-aminus"
    if g.startswith("A"):
        return "grade-a"
    if g.startswith("B"):
        return "grade-b"
    if g.startswith("C"):
        return "grade-c"
    if g in ("D", "E", "F", "T", "M"):
        return f"grade-{g.lower()}"
    return "grade-unknown"


def _render_grade_hero(scan: dict[str, Any]) -> str:
    rating = extract_ssl_rating(scan)
    grade = rating.get("grade")
    score = rating.get("score")
    caps = rating.get("cap_reasons") or []
    warnings = rating.get("warnings") or []
    label = _scan_label(scan)

    if grade:
        letter_html = (
            f'<div class="ssl-grade-letter {_grade_css_class(grade)}">'
            f"{html.escape(grade)}</div>"
        )
        title = "Overall grade"
    else:
        letter_html = '<div class="ssl-grade-letter grade-unknown">?</div>'
        title = "Overall grade"
        grade = None

    score_html = (
        f'<p class="score">Final score: {html.escape(score)}</p>'
        if score
        else ""
    )
    caps_html = ""
    note_items = caps + [f"Warning: {w}" for w in warnings]
    if note_items:
        caps_html = (
            "<ul class='ssl-grade-caps'>"
            + "".join(f"<li>{html.escape(c)}</li>" for c in note_items[:8])
            + "</ul>"
        )

    return (
        f'<div class="ssl-grade-hero">'
        f"{letter_html}"
        f'<div class="ssl-grade-meta">'
        f"<h2>{html.escape(title)}: {html.escape(label)}</h2>"
        f"{score_html}"
        f"{caps_html}"
        f"</div></div>"
    )


def _ssl_pdf_download_name(
    workspace: str, hostname: str | None = None, port: str | None = None
) -> str:
    if hostname:
        safe_host = re.sub(r"[^\w.-]+", "-", hostname).strip("-") or "host"
        return f"kitelon-{workspace}-ssl-{safe_host}-{port or 443}.pdf"
    return f"kitelon-{workspace}-ssl-report.pdf"


def _ssl_pdf_api_path(
    workspace: str, hostname: str | None = None, port: str | None = None
) -> str:
    ws = quote(workspace, safe="")
    if hostname:
        host = quote(hostname, safe="")
        return (
            f"/api/v1/workspaces/{ws}/hosts/{host}/ssl-report.pdf"
            f"?port={int(port or 443)}"
        )
    return f"/api/v1/workspaces/{ws}/ssl-report.pdf"


def _render_pdf_toolbar(
    workspace: str,
    pdf_rel: str,
    *,
    hostname: str | None = None,
    port: str | None = None,
) -> str:
    download_name = _ssl_pdf_download_name(workspace, hostname, port)
    pdf_api = _ssl_pdf_api_path(workspace, hostname, port)
    rel_href = html.escape(pdf_rel, quote=True)
    api_href = html.escape(pdf_api, quote=True)
    fname = html.escape(download_name, quote=True)
    return f"""      <div class="report-toolbar no-print">
        <a class="report-pdf-btn" id="ssl-pdf-link" href="{rel_href}" download="{fname}">Download PDF</a>
      </div>
      <script>
      (function () {{
        const link = document.getElementById("ssl-pdf-link");
        if (!link) return;
        const apiUrl = "{api_href}";
        const filename = "{fname}";
        link.addEventListener("click", async function (ev) {{
          if (location.protocol === "file:") return;
          ev.preventDefault();
          link.setAttribute("aria-busy", "true");
          link.textContent = "Preparing PDF…";
          try {{
            let key = sessionStorage.getItem("kitelon_api_key") || "";
            let res = await fetch(apiUrl, {{
              headers: key ? {{ "X-API-Key": key }} : {{}}
            }});
            if (res.status === 401) {{
              key = prompt("Kitelon API key required by server:") || "";
              if (!key) throw new Error("401 unauthorized");
              sessionStorage.setItem("kitelon_api_key", key);
              res = await fetch(apiUrl, {{ headers: {{ "X-API-Key": key }} }});
            }}
            if (!res.ok) throw new Error(await res.text());
            const blob = await res.blob();
            const blobUrl = URL.createObjectURL(blob);
            const dl = document.createElement("a");
            dl.href = blobUrl;
            dl.download = filename;
            document.body.appendChild(dl);
            dl.click();
            dl.remove();
            URL.revokeObjectURL(blobUrl);
          }} catch (err) {{
            alert(err && err.message ? err.message : String(err));
          }} finally {{
            link.removeAttribute("aria-busy");
            link.textContent = "Download PDF";
          }}
        }});
      }})();
      </script>
"""


def _render_host_ssl_page(scan: dict[str, Any], workspace: str) -> str:
    label = _scan_label(scan)
    host = scan.get("target") or "unknown"
    port = str(scan.get("port") or "443")
    pdf_rel = ssl_report_pdf_rel_path(host, port)
    findings = scan.get("findings") or []
    issues = [
        f for f in findings
        if _map_testssl_severity(f.get("severity", "")) != "INFO"
        or "not ok" in f.get("finding", "").lower()
    ]
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SSL/TLS: {html.escape(label)}</title>
  <style>{REPORT_CSS}{SSL_REPORT_CSS}</style>
</head>
<body>
  <div class="page">
    <header>
      <h1>SSL/TLS Report</h1>
      <div class="sub">Workspace: <strong>{html.escape(workspace)}</strong> · {html.escape(label)}</div>
{_render_pdf_toolbar(workspace, pdf_rel, hostname=host, port=port)}
    </header>
    <main>
      {_render_grade_hero(scan)}
      <section>
        <h2>Findings <span class="count">{len(findings)} check(s) · {len(issues)} notable</span></h2>
        <div class="table-wrap"><table class="ssl-findings-table">
          <thead><tr><th>Severity</th><th>Check</th><th>Finding</th></tr></thead>
          <tbody>{_finding_rows(scan)}</tbody>
        </table></div>
      </section>
    </main>
  </div>
</body>
</html>
"""


def _render_ssl_index(scans: list[dict[str, Any]], workspace: str) -> str:
    rows: list[str] = []
    for scan in scans:
        label = _scan_label(scan)
        host = scan.get("target") or "unknown"
        port = scan.get("port") or "443"
        rel = ssl_report_rel_path(host, str(port))
        rating = extract_ssl_rating(scan)
        grade = rating.get("grade") or "-"
        grade_class = _grade_css_class(rating.get("grade"))
        href = artifact_api_url(workspace, rel) if artifacts_enabled() else rel
        rows.append(
            "<tr>"
            f"<td>{html.escape(host)}</td>"
            f"<td>{html.escape(str(port))}</td>"
            f'<td><span class="ssl-grade-letter {grade_class}" '
            f'style="width:2.5rem;height:2.5rem;font-size:1.1rem;display:inline-flex">'
            f"{html.escape(grade)}</span></td>"
            f'<td><a href="{html.escape(href, quote=True)}">Open report ↗</a></td>'
            "</tr>"
        )
    body = (
        "".join(rows)
        if rows
        else "<tr class='empty-row'><td colspan='4'>No SSL/TLS scans recorded.</td></tr>"
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SSL/TLS Reports: {html.escape(workspace)}</title>
  <style>{REPORT_CSS}{SSL_REPORT_CSS}</style>
</head>
<body>
  <div class="page">
    <header>
      <h1>SSL/TLS Reports</h1>
      <div class="sub">Workspace: <strong>{html.escape(workspace)}</strong> · {len(scans)} target(s)</div>
      <div class="sub">Select a host below: each target has its own report with overall grade.</div>
{_render_pdf_toolbar(workspace, SSL_REPORT_INDEX_PDF)}
    </header>
    <main>
      <div class="table-wrap"><table class="ssl-index-table">
        <thead><tr><th>Host</th><th>Port</th><th>Grade</th><th>Report</th></tr></thead>
        <tbody>{body}</tbody>
      </table></div>
    </main>
  </div>
</body>
</html>
"""


def _write_ssl_pdf(
    conn: Any,
    workspace_id: int,
    loot_dir: Path,
    pdf_rel: str,
    html_content: str,
) -> None:
    try:
        from report import ReportError, export_pdf_bytes  # noqa: WPS433
    except ImportError:
        log("report module unavailable: skipping SSL PDF")
        return
    try:
        pdf_bytes = export_pdf_bytes(html_content=html_content)
    except ReportError as exc:
        log(f"SSL PDF skipped ({exc})")
        return
    if fs_mirror_enabled():
        pdf_path = loot_dir / pdf_rel
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        pdf_path.write_bytes(pdf_bytes)
    if artifacts_enabled():
        store_artifact(
            conn,
            workspace_id,
            loot_dir,
            pdf_rel,
            pdf_bytes,
            content_type="application/pdf",
        )
    log(f"wrote {pdf_rel}")


def write_ssl_html_report(
    loot_dir: Path,
    workspace: str,
    scans: list[dict[str, Any]] | None = None,
) -> Path | None:
    loot_dir = loot_dir.resolve()
    if scans is None:
        scans = load_testssl_scans(loot_dir)
    if not scans:
        return None

    with get_connection() as conn:
        ws = conn.execute(
            "SELECT id FROM workspaces WHERE alias = %s", (workspace,)
        ).fetchone()
        if not ws:
            return None
        workspace_id = int(ws["id"])

        for scan in scans:
            host = scan.get("target") or "unknown"
            port = str(scan.get("port") or "443")
            rel = ssl_report_rel_path(host, port)
            pdf_rel = ssl_report_pdf_rel_path(host, port)
            content = _render_host_ssl_page(scan, workspace)
            report_path = loot_dir / rel
            if fs_mirror_enabled():
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(content, encoding="utf-8")
            if artifacts_enabled():
                store_artifact(conn, workspace_id, loot_dir, rel, content)
            _write_ssl_pdf(conn, workspace_id, loot_dir, pdf_rel, content)
            log(f"wrote {rel}")

        index_content = _render_ssl_index(scans, workspace)
        index_path = loot_dir / SSL_REPORT_INDEX
        index_rel = normalize_rel_path(SSL_REPORT_INDEX)
        if fs_mirror_enabled():
            index_path.parent.mkdir(parents=True, exist_ok=True)
            index_path.write_text(index_content, encoding="utf-8")
        if artifacts_enabled():
            store_artifact(conn, workspace_id, loot_dir, index_rel, index_content)
        _write_ssl_pdf(conn, workspace_id, loot_dir, SSL_REPORT_INDEX_PDF, index_content)
        set_stat(conn, workspace_id, "ssl_scans_total", len(scans))

    log(f"wrote {index_rel}")
    return index_path


def load_testssl_scans(loot_dir: Path) -> list[dict[str, Any]]:
    candidates: list[Path] = []
    for base in (loot_dir / "artifacts" / "ssl", loot_dir / "web"):
        if base.is_dir():
            candidates.extend(sorted(base.glob("*.json")))
            candidates.extend(sorted(base.glob("testssl-*.json")))
    scans: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in candidates:
        key = path.name
        if key in seen:
            continue
        seen.add(key)
        parsed = parse_testssl_file(path)
        if parsed.get("findings"):
            scans.append(parsed)
    return scans


def _testssl_source_file(host: str, port: str) -> str:
    return f"testssl-{host}-{port}.json"


def _testssl_paths(loot_dir: Path, host: str, port: str) -> tuple[Path, Path]:
    web_dir = loot_dir / "web"
    base = f"testssl-{host}-{port}"
    return web_dir / f"{base}.json", web_dir / f"{base}.log"


def parse_target_port(target: str, port: str | None = None) -> tuple[str, str]:
    text = (target or "").strip()
    text = re.sub(r"^https?://", "", text, flags=re.I)
    if "/" in text:
        text = text.split("/", 1)[0]
    if ":" in text and text.count(":") == 1:
        host, maybe_port = text.rsplit(":", 1)
        if maybe_port.isdigit():
            text = host
            port = port or maybe_port
    return text, port or "443"


def _is_valid_testssl_script(path: Path) -> bool:
    from kitelon_engine.tools.testssl import _is_valid_testssl_script as _valid

    return _valid(path)


def find_testssl_binary(install_dir: Path | None = None) -> Path | None:
    from kitelon_engine.tools.testssl import find_testssl_binary as _find

    return _find(install_dir)


def delete_vulnerabilities_by_source(
    conn: Any, workspace_id: int, source_file: str
) -> int:
    cur = conn.execute(
        """
        DELETE FROM vulnerabilities
        WHERE workspace_id = %s AND source_file = %s
        """,
        (workspace_id, source_file),
    )
    return int(getattr(cur, "rowcount", 0) or 0)


def import_testssl_scan(
    conn: Any,
    workspace_id: int,
    scan: dict[str, Any],
    *,
    replace: bool = False,
) -> int:
    host = scan.get("target") or "unknown"
    port = scan.get("port") or "443"
    url = f"https://{host}:{port}" if port else f"https://{host}"
    source = _testssl_source_file(host, port)
    if replace:
        delete_vulnerabilities_by_source(conn, workspace_id, source)
    count = 0
    for item in scan.get("findings") or []:
        if not _should_import_finding(item.get("severity", ""), item.get("finding", "")):
            continue
        sev = _map_testssl_severity(item.get("severity", "INFO"))
        name = item.get("finding", "SSL finding")
        if not name.lower().startswith("ssl"):
            name = f"SSL/TLS: {name}"
        evidence_parts = [p for p in (item.get("id"), item.get("cve"), item.get("cwe")) if p]
        evidence = " · ".join(evidence_parts) if evidence_parts else None
        insert_vulnerability(
            conn,
            workspace_id,
            host,
            sev,
            name[:500],
            url,
            evidence,
            source,
        )
        count += 1
    return count


def import_testssl_findings(conn: Any, workspace_id: int, loot_dir: Path) -> int:
    count = 0
    for scan in load_testssl_scans(loot_dir):
        count += import_testssl_scan(conn, workspace_id, scan, replace=False)
    return count


def run_testssl_scan(
    target: str,
    port: str,
    json_out: Path,
    *,
    install_dir: Path | None = None,
    force: bool = False,
) -> int:
    json_out = json_out.resolve()
    log_out = json_out.with_suffix(".log")
    if json_out.is_file() and json_out.stat().st_size > 0 and not force:
        log(f"testssl output exists (use --force to re-run): {json_out}")
        return 0

    testssl_bin = find_testssl_binary(install_dir)
    if not testssl_bin:
        log("testssl.sh not installed: run: sudo bash install.sh force")
        return 1

    json_out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "bash",
        str(testssl_bin),
        "--quiet",
        "--color",
        "0",
        "--warnings",
        "off",
        "--jsonfile-pretty",
        str(json_out),
        "--logfile",
        str(log_out),
        f"{target}:{port}",
    ]
    log(f"running testssl.sh for {target}:{port}")
    proc = subprocess.run(cmd, check=False)
    if json_out.is_file() and json_out.stat().st_size > 0:
        log(f"testssl.sh results → {json_out}")
        return proc.returncode
    log(f"testssl.sh produced no JSON output (exit {proc.returncode})")
    return proc.returncode or 1


def archive_testssl_artifacts(
    conn: Any,
    workspace_id: int,
    loot_dir: Path,
    json_path: Path,
    log_path: Path,
) -> None:
    if artifacts_enabled():
        store_file_from_disk(conn, workspace_id, loot_dir, json_path)
        if log_path.is_file():
            store_file_from_disk(conn, workspace_id, loot_dir, log_path)


def run_workspace_testssl(
    loot_dir: Path,
    workspace: str,
    target: str,
    port: str | None = None,
    *,
    install_dir: Path | None = None,
    force: bool = False,
    update_reports: bool = False,
) -> int:
    loot_dir = loot_dir.resolve()
    host, scan_port = parse_target_port(target, port)
    json_path, log_path = _testssl_paths(loot_dir, host, scan_port)
    loot_dir.joinpath("web").mkdir(parents=True, exist_ok=True)
    loot_dir.joinpath("reports").mkdir(parents=True, exist_ok=True)

    rc = run_testssl_scan(
        host,
        scan_port,
        json_path,
        install_dir=install_dir,
        force=force,
    )
    if not json_path.is_file() or json_path.stat().st_size == 0:
        return rc or 1

    scan = parse_testssl_file(json_path)
    if not scan.get("target"):
        scan["target"] = host
    if not scan.get("port"):
        scan["port"] = scan_port

    with get_connection() as conn:
        workspace_id = ensure_workspace(
            conn, workspace, loot_root=loot_dir.resolve().parent.parent
        )
        archive_testssl_artifacts(conn, workspace_id, loot_dir, json_path, log_path)
        imported = import_testssl_scan(conn, workspace_id, scan, replace=True)
        upsert_host(conn, workspace_id, host, is_live=1)
        insert_notification(
            conn,
            workspace_id,
            f"testssl.sh scan saved for {host}:{scan_port} ({imported} finding(s))",
        )
        log(f"imported {imported} testssl finding(s) into workspace {workspace}")

    write_ssl_html_report(loot_dir, workspace)
    if update_reports:
        from kitelon_loot import generate_reports  # noqa: E402

        generate_reports(loot_dir, workspace)
    return 0


def process_testssl_scans(loot_dir: Path, workspace: str) -> Path | None:
    with get_connection() as conn:
        ws = conn.execute(
            "SELECT id FROM workspaces WHERE alias = %s", (workspace,)
        ).fetchone()
        if not ws:
            return None
        workspace_id = int(ws["id"])
        imported = import_testssl_findings(conn, workspace_id, loot_dir)
        if imported:
            log(f"imported {imported} testssl finding(s)")
    return write_ssl_html_report(loot_dir, workspace)


def list_ssl_scan_summaries(loot_dir: Path) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for scan in load_testssl_scans(loot_dir):
        host = scan.get("target") or "unknown"
        port = str(scan.get("port") or "443")
        rating = extract_ssl_rating(scan)
        summaries.append(
            {
                "hostname": host,
                "port": port,
                "grade": rating.get("grade"),
                "score": rating.get("score"),
                "report_path": ssl_report_rel_path(host, port),
            }
        )
    return summaries


def get_ssl_report_html(
    conn: Any,
    workspace_id: int,
    loot_dir: Path,
    workspace: str,
    *,
    hostname: str | None = None,
    port: str | None = None,
) -> str | None:
    from kitelon_storage import get_artifact_bytes  # noqa: E402

    rel = (
        ssl_report_rel_path(hostname, str(port or "443"))
        if hostname
        else SSL_REPORT_INDEX
    )

    if artifacts_enabled():
        data = get_artifact_bytes(conn, workspace_id, rel)
        if data:
            return data.decode("utf-8", errors="replace")

    path = loot_dir / rel
    if path.is_file():
        return path.read_text(encoding="utf-8", errors="replace")

    generated = write_ssl_html_report(loot_dir, workspace)
    if not generated and not hostname:
        return None
    if hostname:
        path = loot_dir / rel
        if path.is_file():
            return path.read_text(encoding="utf-8", errors="replace")
        scans = load_testssl_scans(loot_dir)
        for scan in scans:
            if scan.get("target") == hostname and str(scan.get("port") or "443") == str(port or "443"):
                return _render_host_ssl_page(scan, workspace)
        return None
    if generated:
        return generated.read_text(encoding="utf-8", errors="replace")
    return None


def get_ssl_report_pdf_bytes(
    conn: Any,
    workspace_id: int,
    loot_dir: Path,
    workspace: str,
    *,
    hostname: str | None = None,
    port: str | None = None,
    force: bool = False,
) -> tuple[bytes, str]:
    from kitelon_storage import get_artifact_bytes  # noqa: WPS433
    from report import export_pdf_bytes  # noqa: WPS433

    pdf_rel = (
        ssl_report_pdf_rel_path(hostname, str(port or "443"))
        if hostname
        else SSL_REPORT_INDEX_PDF
    )
    filename = _ssl_pdf_download_name(workspace, hostname, port)

    if not force and artifacts_enabled():
        cached = get_artifact_bytes(conn, workspace_id, pdf_rel)
        if cached:
            return cached, filename
    pdf_path = loot_dir / pdf_rel
    if not force and pdf_path.is_file():
        return pdf_path.read_bytes(), filename

    html_content = get_ssl_report_html(
        conn,
        workspace_id,
        loot_dir,
        workspace,
        hostname=hostname,
        port=port,
    )
    if not html_content:
        raise FileNotFoundError("SSL/TLS HTML report not found")

    pdf_bytes = export_pdf_bytes(html_content=html_content, force=True)
    _write_ssl_pdf(conn, workspace_id, loot_dir, pdf_rel, html_content)
    return pdf_bytes, filename


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run testssl.sh for a workspace target and archive results as evidence.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Scan one HTTPS target and import into a workspace")
    run_p.add_argument("--workspace", "-w", required=True, help="Workspace alias")
    run_p.add_argument("--target", "-t", required=True, help="Hostname or host:port")
    run_p.add_argument("--port", "-p", default=None, help="TLS port (default: 443)")
    run_p.add_argument("--loot-dir", required=True, help="Workspace loot directory")
    run_p.add_argument(
        "--install-dir",
        default="/usr/share/kitelon",
        help="Kitelon install root (for testssl.sh path)",
    )
    run_p.add_argument(
        "--force",
        action="store_true",
        help="Re-run testssl even when JSON output already exists",
    )
    run_p.add_argument(
        "--reports",
        action="store_true",
        help="Regenerate client and pentest HTML reports after import",
    )

    args = parser.parse_args()
    if args.command == "run":
        rc = run_workspace_testssl(
            Path(args.loot_dir),
            args.workspace,
            args.target,
            args.port,
            install_dir=Path(args.install_dir),
            force=args.force,
            update_reports=args.reports,
        )
        raise SystemExit(rc)


if __name__ == "__main__":
    main()
