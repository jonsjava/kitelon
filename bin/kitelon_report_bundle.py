#!/usr/bin/env python3
"""Bundle every Kitelon report for a workspace into a single ZIP.

Collects the main scan report, the pentest workbook, the SSL/TLS index, and
each per-host SSL/TLS report, and packs each one into one ZIP archive as a PDF
plus the HTML it was rendered from. A report that is not available (e.g. no
SSL scan data) is skipped rather than failing the whole bundle. If the PDF
toolchain is missing, the HTML is still bundled and MISSING-PDFS.txt lists
what could not be rendered.
"""

from __future__ import annotations

import argparse
import io
import sys
import zipfile
from pathlib import Path
from typing import Any

_BIN_DIR = Path(__file__).resolve().parent
if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))

from kitelon_db import get_connection, log
from kitelon_env import SSL_REPORT_INDEX_PDF
from kitelon_storage import (
    artifacts_enabled,
    get_artifact_bytes,
    store_artifact,
)
from report import (
    ReportError,
    ReportToolError,
    export_pdf_bytes,
)

MAIN_REPORT_HTML = "kitelon-report.html"
MAIN_REPORT_PDF = "reports/kitelon-report.pdf"
PENTEST_REPORT_PDF = "reports/pentest-report.pdf"


def _store_pdf(
    conn: Any,
    workspace_id: int,
    loot_dir: Path,
    pdf_rel: str,
    pdf_bytes: bytes,
) -> None:
    if not artifacts_enabled():
        return
    try:
        store_artifact(
            conn,
            workspace_id,
            loot_dir,
            pdf_rel,
            pdf_bytes,
            content_type="application/pdf",
        )
    except Exception as exc:  # noqa: BLE001 - storage is best-effort for a bundle
        log(f"report bundle: could not cache {pdf_rel} ({exc})")


def _main_report_html(conn: Any, workspace_id: int, loot_dir: Path) -> str | None:
    html_bytes = get_artifact_bytes(conn, workspace_id, MAIN_REPORT_HTML)
    if html_bytes is None:
        html_path = loot_dir / MAIN_REPORT_HTML
        if not html_path.is_file():
            return None
        html_bytes = html_path.read_bytes()
    return html_bytes.decode("utf-8", errors="replace")


def _cached_pdf(conn: Any, workspace_id: int, loot_dir: Path, pdf_rel: str) -> bytes | None:
    if artifacts_enabled():
        cached = get_artifact_bytes(conn, workspace_id, pdf_rel)
        if cached:
            return cached
    pdf_path = loot_dir / pdf_rel
    if pdf_path.is_file():
        return pdf_path.read_bytes()
    return None


def collect_report_files(
    conn: Any,
    workspace_id: int,
    loot_dir: Path,
    workspace: str,
    *,
    force: bool = False,
    regenerate: bool = True,
    include_html: bool = True,
) -> tuple[list[tuple[str, bytes]], list[str]]:
    """Return ``([(arcname, bytes), ...], [tool_error, ...])``.

    Each report contributes its PDF and, when ``include_html`` is set, the HTML
    it was rendered from (same base name, ``.html``). ``tool_error`` entries
    record PDFs that failed because the PDF toolchain was unavailable; their
    HTML is still included.
    """
    loot_dir = loot_dir.resolve()

    if regenerate:
        try:
            from kitelon_loot import generate_reports

            generate_reports(loot_dir, workspace)
        except Exception as exc:  # noqa: BLE001 - bundle collects whatever exists
            log(f"report bundle: report generation step failed ({exc})")

    files: list[tuple[str, bytes]] = []
    tool_errors: list[str] = []

    def add(label: str, base: str, html_producer, pdf_rel: str) -> None:
        try:
            html = html_producer()
        except Exception as exc:  # noqa: BLE001
            log(f"report bundle: {label} skipped ({exc})")
            return
        if not html:
            return
        if include_html:
            files.append((f"{base}.html", html.encode("utf-8")))

        pdf_bytes = None if force else _cached_pdf(conn, workspace_id, loot_dir, pdf_rel)
        if pdf_bytes is None:
            try:
                pdf_bytes = export_pdf_bytes(html_content=html, force=True)
            except ReportToolError as exc:
                tool_errors.append(f"{label}: {exc}")
                log(f"report bundle: {label} PDF skipped ({exc})")
                return
            except ReportError as exc:
                log(f"report bundle: {label} PDF skipped ({exc})")
                return
            _store_pdf(conn, workspace_id, loot_dir, pdf_rel, pdf_bytes)
        files.append((f"{base}.pdf", pdf_bytes))

    add(
        "scan report",
        "kitelon-report",
        lambda: _main_report_html(conn, workspace_id, loot_dir),
        MAIN_REPORT_PDF,
    )

    from kitelon_pentest_report import get_pentest_report_html

    add(
        "pentest workbook",
        "pentest-report",
        lambda: get_pentest_report_html(conn, workspace_id, loot_dir, workspace),
        PENTEST_REPORT_PDF,
    )

    from kitelon_env import ssl_report_pdf_rel_path
    from kitelon_testssl import get_ssl_report_html, list_ssl_scan_summaries

    summaries = list_ssl_scan_summaries(loot_dir)
    if summaries:
        add(
            "ssl index",
            "ssl-report",
            lambda: get_ssl_report_html(conn, workspace_id, loot_dir, workspace),
            SSL_REPORT_INDEX_PDF,
        )
        for summary in summaries:
            host = str(summary.get("hostname") or "unknown")
            port = str(summary.get("port") or "443")
            safe = host.replace("/", "-")
            add(
                f"ssl {host}:{port}",
                f"ssl-{safe}-{port}",
                lambda h=host, p=port: get_ssl_report_html(
                    conn, workspace_id, loot_dir, workspace, hostname=h, port=p
                ),
                ssl_report_pdf_rel_path(host, port),
            )

    return files, tool_errors


# Backwards-compatible name used by earlier callers and tests.
collect_report_pdfs = collect_report_files


def export_reports_zip_bytes(
    conn: Any,
    workspace_id: int,
    loot_dir: Path,
    workspace: str,
    *,
    force: bool = False,
    regenerate: bool = True,
    include_html: bool = True,
) -> tuple[bytes, str]:
    pdfs, tool_errors = collect_report_files(
        conn,
        workspace_id,
        loot_dir,
        workspace,
        force=force,
        regenerate=regenerate,
        include_html=include_html,
    )
    if not pdfs:
        if tool_errors:
            raise ReportToolError("; ".join(tool_errors))
        raise FileNotFoundError(
            "No reports available to export. Import loot and generate reports first."
        )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, data in pdfs:
            zf.writestr(arcname, data)
        if tool_errors:
            note = (
                "Some PDFs could not be rendered; their HTML versions are included.\n"
                "Install pdfkit + wkhtmltopdf (sudo bash install.sh force) and export again.\n\n"
                + "\n".join(tool_errors)
                + "\n"
            )
            zf.writestr("MISSING-PDFS.txt", note)
    return buf.getvalue(), f"kitelon-{workspace}-reports.zip"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bundle all workspace reports into a ZIP (PDF + HTML)"
    )
    parser.add_argument("--loot-dir", required=True, help="Workspace loot directory")
    parser.add_argument("--workspace", required=True, help="Workspace alias")
    parser.add_argument(
        "--output",
        help="Output ZIP path (default: <loot-dir>/reports/kitelon-<alias>-reports.zip)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-render PDFs even if a cached copy exists",
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Bundle PDFs only (leave out the HTML versions)",
    )
    parser.add_argument(
        "--no-regenerate",
        action="store_true",
        help="Do not run report generation first; bundle only what already exists",
    )
    args = parser.parse_args()

    loot_dir = Path(args.loot_dir).resolve()

    with get_connection() as conn:
        ws = conn.execute(
            "SELECT id FROM workspaces WHERE alias = %s", (args.workspace,)
        ).fetchone()
        if not ws:
            print(f"workspace not found: {args.workspace}", file=sys.stderr)
            sys.exit(1)
        try:
            data, default_name = export_reports_zip_bytes(
                conn,
                int(ws["id"]),
                loot_dir,
                args.workspace,
                force=args.force,
                regenerate=not args.no_regenerate,
                include_html=not args.no_html,
            )
        except (ReportError, FileNotFoundError) as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)

    output = Path(args.output) if args.output else loot_dir / "reports" / default_name
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
