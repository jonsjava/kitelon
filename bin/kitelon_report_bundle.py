#!/usr/bin/env python3
"""Bundle every Kitelon report for a workspace into a single ZIP of PDFs.

Collects the main scan report, the pentest workbook, the SSL/TLS index, and
each per-host SSL/TLS report, renders each to PDF, and packs them into one
ZIP archive. A report that is not available (e.g. no SSL scan data) is skipped
rather than failing the whole bundle; only a total lack of a working PDF
toolchain surfaces as an error.
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


def _main_report_pdf(
    conn: Any,
    workspace_id: int,
    loot_dir: Path,
    *,
    force: bool,
) -> bytes | None:
    if not force and artifacts_enabled():
        cached = get_artifact_bytes(conn, workspace_id, MAIN_REPORT_PDF)
        if cached:
            return cached

    html_bytes = get_artifact_bytes(conn, workspace_id, MAIN_REPORT_HTML)
    if html_bytes is None:
        html_path = loot_dir / MAIN_REPORT_HTML
        if not html_path.is_file():
            return None
        html_bytes = html_path.read_bytes()

    pdf_bytes = export_pdf_bytes(
        html_content=html_bytes.decode("utf-8", errors="replace"),
        force=True,
    )
    _store_pdf(conn, workspace_id, loot_dir, MAIN_REPORT_PDF, pdf_bytes)
    return pdf_bytes


def _pentest_report_pdf(
    conn: Any,
    workspace_id: int,
    loot_dir: Path,
    workspace: str,
    *,
    force: bool,
) -> bytes | None:
    from kitelon_pentest_report import get_pentest_report_html

    if not force and artifacts_enabled():
        cached = get_artifact_bytes(conn, workspace_id, PENTEST_REPORT_PDF)
        if cached:
            return cached

    html = get_pentest_report_html(conn, workspace_id, loot_dir, workspace)
    if not html:
        return None
    pdf_bytes = export_pdf_bytes(html_content=html, force=True)
    _store_pdf(conn, workspace_id, loot_dir, PENTEST_REPORT_PDF, pdf_bytes)
    return pdf_bytes


def collect_report_pdfs(
    conn: Any,
    workspace_id: int,
    loot_dir: Path,
    workspace: str,
    *,
    force: bool = False,
    regenerate: bool = True,
) -> tuple[list[tuple[str, bytes]], list[str]]:
    """Return ``([(arcname, pdf_bytes), ...], [tool_error, ...])``.

    ``tool_error`` entries record reports that failed because the PDF
    toolchain was unavailable; callers decide whether an empty bundle with
    tool errors should be a 503.
    """
    loot_dir = loot_dir.resolve()

    if regenerate:
        try:
            from kitelon_loot import generate_reports

            generate_reports(loot_dir, workspace)
        except Exception as exc:  # noqa: BLE001 - bundle collects whatever exists
            log(f"report bundle: report generation step failed ({exc})")

    pdfs: list[tuple[str, bytes]] = []
    tool_errors: list[str] = []

    def add(label: str, arcname: str, producer) -> None:
        try:
            data = producer()
        except ReportToolError as exc:
            tool_errors.append(f"{label}: {exc}")
            log(f"report bundle: {label} skipped ({exc})")
            return
        except ReportError as exc:
            log(f"report bundle: {label} skipped ({exc})")
            return
        except Exception as exc:  # noqa: BLE001
            log(f"report bundle: {label} skipped ({exc})")
            return
        if data:
            pdfs.append((arcname, data))

    add(
        "scan report",
        "kitelon-report.pdf",
        lambda: _main_report_pdf(conn, workspace_id, loot_dir, force=force),
    )
    add(
        "pentest workbook",
        "pentest-report.pdf",
        lambda: _pentest_report_pdf(
            conn, workspace_id, loot_dir, workspace, force=force
        ),
    )

    from kitelon_testssl import (
        get_ssl_report_html,
        get_ssl_report_pdf_bytes,
        list_ssl_scan_summaries,
    )

    summaries = list_ssl_scan_summaries(loot_dir)
    if summaries:
        def _ssl_index() -> bytes | None:
            html = get_ssl_report_html(conn, workspace_id, loot_dir, workspace)
            if not html:
                return None
            pdf_bytes = export_pdf_bytes(html_content=html, force=True)
            _store_pdf(conn, workspace_id, loot_dir, SSL_REPORT_INDEX_PDF, pdf_bytes)
            return pdf_bytes

        add("ssl index", "ssl-report.pdf", _ssl_index)

        for summary in summaries:
            host = str(summary.get("hostname") or "unknown")
            port = str(summary.get("port") or "443")
            safe = host.replace("/", "-")
            add(
                f"ssl {host}:{port}",
                f"ssl-{safe}-{port}.pdf",
                lambda h=host, p=port: get_ssl_report_pdf_bytes(
                    conn,
                    workspace_id,
                    loot_dir,
                    workspace,
                    hostname=h,
                    port=p,
                    force=force,
                )[0],
            )

    return pdfs, tool_errors


def export_reports_zip_bytes(
    conn: Any,
    workspace_id: int,
    loot_dir: Path,
    workspace: str,
    *,
    force: bool = False,
    regenerate: bool = True,
) -> tuple[bytes, str]:
    pdfs, tool_errors = collect_report_pdfs(
        conn,
        workspace_id,
        loot_dir,
        workspace,
        force=force,
        regenerate=regenerate,
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
    return buf.getvalue(), f"kitelon-{workspace}-reports.zip"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bundle all workspace reports into a ZIP of PDFs"
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
