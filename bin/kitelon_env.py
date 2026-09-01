#!/usr/bin/env python3
"""Parse recon loot into per-host environment & security-control summaries for reports."""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kitelon_storage import (
    artifact_api_url,
    artifacts_enabled,
    get_artifact_bytes,
    list_artifacts,
    normalize_rel_path,
)


@dataclass
class HostEnvironment:
    hostname: str
    waf: str | None = None
    web_stack: list[str] = field(default_factory=list)
    tls_summary: str | None = None
    testssl_label: str | None = None
    ssl_grade: str | None = None
    ssl_report_rel: str | None = None
    notes: list[str] = field(default_factory=list)


def ssl_report_rel_path(hostname: str, port: str) -> str:
    return f"reports/ssl-report-{hostname}-{port}.html"


def ssl_report_pdf_rel_path(hostname: str, port: str) -> str:
    return f"reports/ssl-report-{hostname}-{port}.pdf"


SSL_REPORT_INDEX_PDF = "reports/ssl-report.pdf"


def extract_ssl_rating(parsed: dict[str, Any]) -> dict[str, Any]:
    grade: str | None = None
    score: str | None = None
    cap_reasons: list[str] = []
    warnings: list[str] = []
    for item in parsed.get("findings") or []:
        fid = str(item.get("id") or "").lower()
        finding = str(item.get("finding") or "").strip()
        if not finding:
            continue
        if fid in ("grade", "overall_grade"):
            grade = finding
        elif fid in ("final_score", "overall_score"):
            score = finding
        elif fid.startswith("grade_cap_reason"):
            cap_reasons.append(finding)
        elif fid.startswith("grade_cap_warning"):
            warnings.append(finding)
        elif "grade_cap" in fid:
            cap_reasons.append(finding)
    return {
        "grade": grade,
        "score": score,
        "cap_reasons": cap_reasons,
        "warnings": warnings,
    }


def grade_from_testssl_log(text: str) -> str | None:
    for line in text.splitlines():
        if "Overall Grade" not in line:
            continue
        # Terminal/log lines look like: " Overall Grade                A+"
        match = re.search(r"Overall Grade\s+([A-F][+-]?|T|M)\s*$", line)
        if match:
            return match.group(1)
        parts = line.split()
        if parts:
            candidate = parts[-1].strip()
            if re.fullmatch(r"[A-F][+-]?|T|M", candidate):
                return candidate
    return None


def read_loot_text(
    loot_dir: Path,
    conn: Any,
    workspace_id: int,
    rel_path: str | Path,
) -> str | None:
    rel = normalize_rel_path(rel_path)
    path = loot_dir / rel
    if path.is_file():
        return path.read_text(encoding="utf-8", errors="replace")
    if conn is not None and workspace_id and artifacts_enabled():
        data = get_artifact_bytes(conn, workspace_id, rel)
        if data:
            return data.decode("utf-8", errors="replace")
    return None


def iter_web_rel_paths(
    loot_dir: Path,
    conn: Any,
    workspace_id: int,
) -> list[str]:
    paths: list[str] = []
    for sub in ("web", "artifacts/web"):
        web_dir = loot_dir / sub
        if not web_dir.is_dir():
            continue
        for path in sorted(web_dir.rglob("*")):
            if path.is_file():
                paths.append(normalize_rel_path(path.relative_to(loot_dir)))
    if conn is not None and workspace_id and artifacts_enabled():
        for row in list_artifacts(conn, workspace_id, prefix="web/", limit=5000):
            rel = row["rel_path"]
            if rel not in paths:
                paths.append(rel)
        for row in list_artifacts(conn, workspace_id, prefix="artifacts/web/", limit=5000):
            rel = row["rel_path"]
            if rel not in paths:
                paths.append(rel)
    return sorted(set(paths))


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1B\[[0-9;]*[a-zA-Z]", "", text)


def _matches_host(rel_path: str, hostname: str) -> bool:
    if not hostname:
        return False
    rel = normalize_rel_path(rel_path)
    name = Path(rel).name
    if not name.startswith(("waf-", "whatweb-", "webtech-", "httpx-", "testssl-", "sslscan-")):
        return False
    # v2 layout: artifacts/web/<hostname>/waf-80.txt
    marker = f"/{hostname}/"
    if marker in f"/{rel}/":
        return True
    # legacy: web/waf-<hostname>-port80.txt
    escaped = re.escape(hostname)
    return bool(
        re.search(
            rf"^(?:waf|whatweb|webtech|httpx|testssl|sslscan)-{escaped}(?:[-.]|$)",
            name,
        )
    )


def _kind_from_name(name: str) -> str | None:
    for prefix in ("waf", "whatweb", "webtech", "httpx", "testssl", "sslscan"):
        if name.startswith(prefix + "-"):
            return prefix
    return None


def parse_waf(text: str) -> str | None:
    plain = _strip_ansi(text)
    for line in plain.splitlines():
        line = line.strip()
        match = re.search(r"is behind (.+?) WAF\.?", line, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        if re.search(r"seems to be behind a WAF", line, re.IGNORECASE):
            detail = "Generic (heuristic detection)"
            reason = re.search(r"Reason:\s*(.+)", plain, re.IGNORECASE)
            if reason:
                detail += f": {reason.group(1).strip()[:120]}"
            return detail
        if "No WAF detected" in line:
            return "None detected"
    return None


def parse_whatweb(text: str) -> list[str]:
    items: list[str] = []
    skip_keys = {"country", "ip", "title"}
    for key, value in re.findall(r"([A-Za-z0-9_-]+)\[([^\]]+)\]", text):
        if key.lower() in skip_keys:
            continue
        label = f"{key}: {value.strip()}"
        if label not in items:
            items.append(label)
    return items[:14]


def parse_webtech(text: str) -> list[str]:
    items: list[str] = []
    for line in text.splitlines():
        line = line.strip().lstrip("-").strip()
        if line and line not in items:
            items.append(line)
    return items[:12]


def parse_httpx(text: str) -> tuple[str | None, list[str]]:
    title: str | None = None
    tech: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        bracket_parts = re.findall(r"\[([^\]]+)\]", line)
        if len(bracket_parts) >= 2 and bracket_parts[0].isdigit():
            title = bracket_parts[1] if not bracket_parts[1].isdigit() else title
        if bracket_parts:
            last = bracket_parts[-1]
            if "," in last and not last.replace(",", "").replace(" ", "").isdigit():
                for part in last.split(","):
                    part = part.strip()
                    if part and part not in tech:
                        tech.append(part)
    return title, tech


def parse_sslscan(text: str) -> str | None:
    bits: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("SSL/TLS Protocols:"):
            bits.append(stripped.replace("SSL/TLS Protocols:", "Protocols:").strip())
        elif stripped.startswith("Supported SSL/TLS protocols:"):
            bits.append(stripped.replace("Supported SSL/TLS protocols:", "Protocols:").strip())
        elif "Preferred" in stripped and "Cipher" in stripped and len(bits) < 3:
            bits.append(stripped[:120])
    return "; ".join(bits) if bits else None


def summarize_testssl(parsed: dict[str, Any]) -> str | None:
    findings = parsed.get("findings") or []
    parts: list[str] = []
    seen: set[str] = set()

    def add(part: str) -> None:
        part = part.strip()
        if part and part not in seen:
            seen.add(part)
            parts.append(part)

    for item in findings:
        finding = str(item.get("finding") or "")
        fid = str(item.get("id") or "").lower()
        lower = finding.lower()

        if fid in ("hsts", "hsts_time") or "hsts" in lower and "not offered" not in lower:
            add("HSTS")
        if "tls 1.3" in lower and "not offered" not in lower and "disabled" not in lower:
            add("TLS 1.3")
        if "tls 1.2" in lower and "not offered" not in lower and "disabled" not in lower:
            add("TLS 1.2")
        if "heartbleed" in lower and "not vulnerable" not in lower and "ok" not in lower:
            add("Heartbleed concern")
        if "expired" in lower or "expires" in lower and "cert" in lower:
            add(finding[:80])
        if fid == "cert_notafter" or "certificate expires" in lower:
            add(finding[:90])

    if not parts and findings:
        for item in findings[:6]:
            sev = str(item.get("severity") or "").upper()
            if sev and sev not in ("OK", "INFO", "DEBUG"):
                add(str(item.get("finding") or "")[:80])

    return "; ".join(parts[:6]) if parts else None


def _merge_stack(*groups: list[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for item in group:
            key = item.lower()
            if key not in seen:
                seen.add(key)
                merged.append(item)
    return merged[:16]


def build_host_environment(
    hostname: str,
    loot_dir: Path,
    conn: Any,
    workspace_id: int,
    web_paths: list[str] | None = None,
) -> HostEnvironment:
    env = HostEnvironment(hostname=hostname)
    paths = web_paths if web_paths is not None else iter_web_rel_paths(loot_dir, conn, workspace_id)
    host_paths = [p for p in paths if _matches_host(p, hostname)]

    waf_values: list[str] = []
    whatweb: list[str] = []
    webtech: list[str] = []
    httpx_title: str | None = None
    httpx_tech: list[str] = []
    tls_bits: list[str] = []

    for rel in host_paths:
        kind = _kind_from_name(Path(rel).name)
        text = read_loot_text(loot_dir, conn, workspace_id, rel)
        if not text or not kind:
            continue

        if kind == "waf":
            value = parse_waf(text)
            if value and value not in waf_values:
                waf_values.append(value)
        elif kind == "whatweb":
            whatweb.extend(parse_whatweb(text))
        elif kind == "webtech":
            webtech.extend(parse_webtech(text))
        elif kind == "httpx":
            title, tech = parse_httpx(text)
            httpx_title = httpx_title or title
            httpx_tech.extend(tech)
        elif kind == "testssl":
            if rel.endswith(".json"):
                parsed = parse_testssl_json_text(text, rel)
                summary = summarize_testssl(parsed)
                if summary:
                    tls_bits.append(summary)
                port = parsed.get("port") or "443"
                env.testssl_label = f"{hostname}:{port}"
                rating = extract_ssl_rating(parsed)
                if not rating.get("grade") and rel.endswith(".json"):
                    log_text = read_loot_text(
                        loot_dir,
                        conn,
                        workspace_id,
                        rel.replace(".json", ".log"),
                    )
                    if log_text:
                        rating["grade"] = grade_from_testssl_log(log_text)
                env.ssl_grade = rating.get("grade")
                env.ssl_report_rel = ssl_report_rel_path(hostname, str(port))
        elif kind == "sslscan":
            summary = parse_sslscan(text)
            if summary:
                tls_bits.append(summary)

    if waf_values:
        env.waf = waf_values[0] if len(waf_values) == 1 else "; ".join(waf_values)
    env.web_stack = _merge_stack(whatweb, webtech, httpx_tech)
    if httpx_title and not any("title" in s.lower() for s in env.web_stack):
        env.web_stack.insert(0, f"Title: {httpx_title}")

    if tls_bits:
        env.tls_summary = "; ".join(dict.fromkeys(tls_bits))

    if env.waf and "none detected" not in env.waf.lower():
        env.notes.append("Edge/WAF detected: some attack payloads may have been blocked during testing.")

    return env


def parse_testssl_json_text(text: str, rel_path: str) -> dict[str, Any]:
    path = Path(rel_path)
    match = re.match(r"testssl-(.+)-(\d+)\.json$", path.name)
    target, port = "", ""
    if match:
        target, port = match.group(1), match.group(2)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"target": target, "port": port, "findings": []}
    if isinstance(data, dict):
        target = str(data.get("targetHost") or data.get("host") or target)
        port = str(data.get("port") or port)
    findings: list[dict[str, str]] = []
    for item in _iter_testssl_findings(data):
        finding = str(item.get("finding") or "").strip()
        if not finding:
            continue
        findings.append(
            {
                "id": str(item.get("id") or ""),
                "severity": str(item.get("severity") or "INFO"),
                "finding": finding,
            }
        )
    return {"target": target, "port": port, "findings": findings}


def _iter_testssl_findings(node: Any):
    if isinstance(node, list):
        for item in node:
            yield from _iter_testssl_findings(item)
    elif isinstance(node, dict):
        if "finding" in node and ("severity" in node or "id" in node):
            yield node
        for value in node.values():
            if isinstance(value, (list, dict)):
                yield from _iter_testssl_findings(value)


def build_environments(
    hostnames: list[str],
    loot_dir: Path,
    conn: Any,
    workspace_id: int,
) -> list[HostEnvironment]:
    web_paths = iter_web_rel_paths(loot_dir, conn, workspace_id)
    profiles = [
        build_host_environment(host, loot_dir, conn, workspace_id, web_paths)
        for host in hostnames
    ]
    return [p for p in profiles if _profile_has_data(p)]


def _profile_has_data(profile: HostEnvironment) -> bool:
    return bool(profile.waf or profile.web_stack or profile.tls_summary or profile.notes)


def _cell(value: str | None, *, muted: str = "-") -> str:
    if not value:
        return f"<span class='muted'>{muted}</span>"
    return html.escape(value)


def _stack_list(items: list[str]) -> str:
    if not items:
        return "<span class='muted'>-</span>"
    return "<ul class='env-tags'>" + "".join(
        f"<li>{html.escape(item)}</li>" for item in items
    ) + "</ul>"


def render_environment_section(
    profiles: list[HostEnvironment],
    workspace: str,
    *,
    for_client: bool = False,
) -> str:
    if not profiles:
        if for_client:
            return (
                "<p class='muted'>No environment or security-control data recorded for this scope yet.</p>"
            )
        return (
            "<p class='muted'>No WAF, technology fingerprint, or TLS recon data imported yet. "
            "Run web/HTTPS modes with WAFWOOF, WHATWEB, WEBTECH, TESTSSL, or HTTPX enabled.</p>"
        )

    cards: list[str] = []
    for profile in profiles:
        tls_cell = _cell(profile.tls_summary)
        if profile.ssl_grade and for_client:
            tls_cell += f" · Grade <strong>{html.escape(profile.ssl_grade)}</strong>"
        elif profile.ssl_report_rel and not for_client:
            href = artifact_api_url(workspace, profile.ssl_report_rel) if artifacts_enabled() else profile.ssl_report_rel
            grade_label = html.escape(profile.ssl_grade or "report")
            tls_cell += (
                f' · <a class="ext-link ssl-grade-link" href="{html.escape(href, quote=True)}" '
                f'target="_blank" rel="noopener">SSL {grade_label} ↗</a>'
            )
        notes_html = ""
        if profile.notes and not for_client:
            notes_html = (
                "<p class='env-note'>"
                + html.escape(" ".join(profile.notes))
                + "</p>"
            )
        elif profile.notes and for_client and profile.waf:
            notes_html = (
                "<p class='env-note'>"
                "Edge or WAF controls were observed; some tests may have been filtered at the perimeter."
                "</p>"
            )
        cards.append(
            f"<article class='env-card'>"
            f"<h3 class='env-host'>{html.escape(profile.hostname)}</h3>"
            f"<dl class='env-grid'>"
            f"<dt>Edge / WAF</dt><dd>{_cell(profile.waf)}</dd>"
            f"<dt>Web stack</dt><dd>{_stack_list(profile.web_stack)}</dd>"
            f"<dt>TLS / SSL</dt><dd>{tls_cell}</dd>"
            f"</dl>"
            f"{notes_html}"
            f"</article>"
        )

    if for_client:
        intro = (
            "<p class='muted env-intro'>Observed environment and security controls identified "
            "during the assessment.</p>"
        )
    else:
        intro = (
            "<p class='muted env-intro'>Observed environment and security controls gathered during "
            "reconnaissance (wafw00f, WhatWeb, webtech, httpx, testssl.sh). "
            "Product names reflect automated fingerprinting, not manual verification.</p>"
        )
    return intro + "".join(cards)


ENV_REPORT_CSS = """
    .env-intro { margin: 0 0 1rem; font-size: .9rem; }
    .env-card {
      background: #11151d;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem 1.1rem;
      margin-bottom: 1rem;
    }
    .env-card:last-child { margin-bottom: 0; }
    .env-host {
      margin: 0 0 .75rem;
      font-size: 1rem;
      color: #fff;
    }
    .env-grid {
      display: grid;
      grid-template-columns: 110px 1fr;
      gap: .45rem .85rem;
      margin: 0;
    }
    .env-grid dt {
      margin: 0;
      color: var(--muted);
      font-size: .78rem;
      text-transform: uppercase;
      letter-spacing: .04em;
    }
    .env-grid dd { margin: 0; font-size: .9rem; }
    .env-tags {
      margin: 0;
      padding: 0;
      list-style: none;
      display: flex;
      flex-wrap: wrap;
      gap: .35rem;
    }
    .env-tags li {
      background: #1e2430;
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: .15rem .55rem;
      font-size: .78rem;
      color: #dce4ef;
    }
    .env-note {
      margin: .75rem 0 0;
      padding-top: .65rem;
      border-top: 1px dashed var(--border);
      color: var(--muted);
      font-size: .82rem;
    }
    .ssl-grade-link { font-weight: 600; white-space: nowrap; }
"""

SSL_REPORT_CSS = """
    .ssl-grade-hero {
      display: flex;
      align-items: center;
      gap: 1.5rem;
      margin: 0 0 1.5rem;
      padding: 1.25rem 1.5rem;
      background: linear-gradient(135deg, #11151d 0%, #1a2030 100%);
      border: 1px solid var(--border);
      border-radius: 12px;
    }
    .ssl-grade-letter {
      flex: 0 0 auto;
      width: 4.5rem;
      height: 4.5rem;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 2.25rem;
      font-weight: 800;
      border-radius: 10px;
      letter-spacing: -.02em;
    }
    .grade-a, .grade-aplus, .grade-aminus { background: #0d3d2a; color: #5ee9a8; border: 2px solid #1f8f5f; }
    .grade-b, .grade-bplus, .grade-bminus { background: #3d320d; color: #f0d060; border: 2px solid #b8941f; }
    .grade-c, .grade-cplus, .grade-cminus { background: #3d280d; color: #f0a050; border: 2px solid #c07020; }
    .grade-d, .grade-e, .grade-f, .grade-t, .grade-m { background: #3d0d0d; color: #f07070; border: 2px solid #c03030; }
    .grade-unknown { background: #1e2430; color: #9aa8b8; border: 2px solid var(--border); }
    .ssl-grade-meta { flex: 1; min-width: 0; }
    .ssl-grade-meta h2 {
      margin: 0 0 .35rem;
      font-size: 1.1rem;
      color: #fff;
    }
    .ssl-grade-meta .score { color: var(--muted); font-size: .9rem; margin: 0 0 .5rem; }
    .ssl-grade-caps {
      margin: 0;
      padding: 0;
      list-style: none;
      font-size: .82rem;
      color: #c8d0dc;
    }
    .ssl-grade-caps li { margin: .2rem 0; }
    .ssl-index-table { width: 100%; }
    .ssl-index-table td, .ssl-index-table th { padding: .45rem .6rem; }
    .table-wrap { overflow-x: auto; max-width: 100%; }
    .ssl-findings-table { table-layout: fixed; width: 100%; }
    .ssl-findings-table td, .ssl-findings-table th {
      overflow-wrap: anywhere;
      word-break: break-word;
      vertical-align: top;
    }
    .ssl-findings-table th:nth-child(1),
    .ssl-findings-table td:nth-child(1) { width: 6rem; }
    .ssl-findings-table th:nth-child(2),
    .ssl-findings-table td:nth-child(2) { width: 24%; }
    .report-toolbar {
      margin: .75rem 0 0;
      display: flex;
      gap: .5rem;
      justify-content: flex-end;
      flex-wrap: wrap;
    }
    .report-pdf-btn {
      font: inherit;
      padding: .45rem .85rem;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: #2a3140;
      color: var(--text);
      cursor: pointer;
      font-weight: 600;
      text-decoration: none;
      display: inline-block;
    }
    .report-pdf-btn:hover { background: #353d4f; }
    .report-pdf-btn[disabled] { opacity: .55; cursor: wait; }
    @media print {
      .no-print { display: none !important; }
      body, .page, header, section, .ssl-grade-hero {
        background: #fff !important;
        color: #1a1a1a !important;
        box-shadow: none !important;
      }
      header { border-bottom: 2px solid #333; }
      .ssl-grade-hero {
        border: 1px solid #ccc;
        break-inside: avoid-page;
      }
      .ssl-grade-letter { border-width: 1px; }
      .table-wrap { overflow: visible; }
      .ssl-findings-table th {
        background: #eee !important;
        color: #333 !important;
      }
      .ssl-findings-table td, .ssl-findings-table th {
        border-color: #ccc !important;
      }
      .badge { border: 1px solid #999; }
      a { color: #0645ad; text-decoration: none; }
    }
"""
