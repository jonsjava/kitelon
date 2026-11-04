"""Tests for the all-reports PDF bundle and the full-audit SSL step."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import kitelon_report_bundle as bundle
from kitelon_engine.context import ScanContext
from kitelon_engine.pipelines import steps
from report import ReportToolError


def test_export_reports_zip_packs_each_pdf():
    pdfs = [
        ("kitelon-report.pdf", b"%PDF-main"),
        ("pentest-report.pdf", b"%PDF-pentest"),
        ("ssl-report.pdf", b"%PDF-ssl"),
        ("ssl-host.example-443.pdf", b"%PDF-ssl-host"),
    ]
    with patch.object(bundle, "collect_report_files", return_value=(pdfs, [])):
        data, filename = bundle.export_reports_zip_bytes(
            conn=None, workspace_id=1, loot_dir=Path("/tmp/x"), workspace="demo"
        )

    assert filename == "kitelon-demo-reports.zip"
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        assert sorted(zf.namelist()) == sorted(name for name, _ in pdfs)
        assert zf.read("ssl-report.pdf") == b"%PDF-ssl"


def test_export_reports_zip_raises_tool_error_when_nothing_rendered():
    with patch.object(
        bundle, "collect_report_files", return_value=([], ["scan report: wkhtmltopdf not found"])
    ):
        with pytest.raises(ReportToolError):
            bundle.export_reports_zip_bytes(
                conn=None, workspace_id=1, loot_dir=Path("/tmp/x"), workspace="demo"
            )


def test_export_reports_zip_raises_not_found_when_no_reports():
    with patch.object(bundle, "collect_report_files", return_value=([], [])):
        with pytest.raises(FileNotFoundError):
            bundle.export_reports_zip_bytes(
                conn=None, workspace_id=1, loot_dir=Path("/tmp/x"), workspace="demo"
            )


def _ctx(install_dir: Path, **options) -> ScanContext:
    return ScanContext(
        install_dir=install_dir,
        target="example.com",
        mode="full-audit",
        workspace="demo",
        options=options,
    )


def test_ssl_stack_runs_testssl_and_tlsx(tmp_path: Path):
    ctx = _ctx(tmp_path, enable_testssl=True, enable_tlsx=True)
    manifest = MagicMock()
    manifest.should_skip.return_value = False
    manifest.ctx = ctx
    manifest.artifact_path.side_effect = lambda *p: ctx.artifacts_dir.joinpath(*p)

    with patch.object(steps.testssl, "run_testssl") as mock_testssl, patch.object(
        steps.tlsx, "probe_tls"
    ) as mock_tlsx:
        steps.ssl_stack(ctx, manifest, "sub.example.com", 443)

    mock_testssl.assert_called_once()
    mock_tlsx.assert_called_once()
    assert mock_testssl.call_args.args[1] == "sub.example.com"
    assert mock_testssl.call_args.args[2] == 443


def test_ssl_stack_skips_testssl_when_disabled(tmp_path: Path):
    ctx = _ctx(tmp_path, enable_testssl=False, enable_tlsx=False)
    manifest = MagicMock()
    manifest.should_skip.return_value = False
    manifest.ctx = ctx
    manifest.artifact_path.side_effect = lambda *p: ctx.artifacts_dir.joinpath(*p)

    with patch.object(steps.testssl, "run_testssl") as mock_testssl, patch.object(
        steps.tlsx, "probe_tls"
    ) as mock_tlsx:
        steps.ssl_stack(ctx, manifest, "sub.example.com", 443)

    mock_testssl.assert_not_called()
    mock_tlsx.assert_not_called()


def _fake_sources(monkeypatch, tmp_path: Path, *, pdf_error: Exception | None = None):
    """Stub every report source so collect_report_files runs without a DB."""
    import kitelon_pentest_report
    import kitelon_testssl

    monkeypatch.setattr(bundle, "artifacts_enabled", lambda: False)
    monkeypatch.setattr(bundle, "_main_report_html", lambda *a: "<html>scan</html>")
    monkeypatch.setattr(
        kitelon_pentest_report, "get_pentest_report_html", lambda *a, **k: "<html>pentest</html>"
    )
    monkeypatch.setattr(
        kitelon_testssl,
        "list_ssl_scan_summaries",
        lambda *a: [{"hostname": "a.example", "port": "443"}],
    )
    monkeypatch.setattr(
        kitelon_testssl,
        "get_ssl_report_html",
        lambda *a, hostname=None, port=None: f"<html>ssl {hostname or 'index'}</html>",
    )

    def fake_pdf(html_content, force=True):
        if pdf_error:
            raise pdf_error
        return b"%PDF-" + html_content.encode()

    monkeypatch.setattr(bundle, "export_pdf_bytes", fake_pdf)


def test_collect_includes_html_next_to_each_pdf(monkeypatch, tmp_path: Path):
    _fake_sources(monkeypatch, tmp_path)
    files, errors = bundle.collect_report_files(
        None, 1, tmp_path, "demo", regenerate=False
    )
    names = sorted(name for name, _ in files)
    assert errors == []
    assert names == sorted(
        [
            "kitelon-report.html", "kitelon-report.pdf",
            "pentest-report.html", "pentest-report.pdf",
            "ssl-report.html", "ssl-report.pdf",
            "ssl-a.example-443.html", "ssl-a.example-443.pdf",
        ]
    )
    assert dict(files)["pentest-report.html"] == b"<html>pentest</html>"


def test_collect_pdf_only_leaves_out_html(monkeypatch, tmp_path: Path):
    _fake_sources(monkeypatch, tmp_path)
    files, _ = bundle.collect_report_files(
        None, 1, tmp_path, "demo", regenerate=False, include_html=False
    )
    assert all(name.endswith(".pdf") for name, _ in files)
    assert len(files) == 4


def test_missing_pdf_toolchain_still_bundles_html(monkeypatch, tmp_path: Path):
    _fake_sources(monkeypatch, tmp_path, pdf_error=ReportToolError("wkhtmltopdf not found"))
    data, _ = bundle.export_reports_zip_bytes(
        None, 1, tmp_path, "demo", regenerate=False
    )
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = zf.namelist()
        assert "kitelon-report.html" in names
        assert not any(n.endswith(".pdf") for n in names)
        assert "wkhtmltopdf not found" in zf.read("MISSING-PDFS.txt").decode()
