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
    with patch.object(bundle, "collect_report_pdfs", return_value=(pdfs, [])):
        data, filename = bundle.export_reports_zip_bytes(
            conn=None, workspace_id=1, loot_dir=Path("/tmp/x"), workspace="demo"
        )

    assert filename == "kitelon-demo-reports.zip"
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        assert sorted(zf.namelist()) == sorted(name for name, _ in pdfs)
        assert zf.read("ssl-report.pdf") == b"%PDF-ssl"


def test_export_reports_zip_raises_tool_error_when_nothing_rendered():
    with patch.object(
        bundle, "collect_report_pdfs", return_value=([], ["scan report: wkhtmltopdf not found"])
    ):
        with pytest.raises(ReportToolError):
            bundle.export_reports_zip_bytes(
                conn=None, workspace_id=1, loot_dir=Path("/tmp/x"), workspace="demo"
            )


def test_export_reports_zip_raises_not_found_when_no_reports():
    with patch.object(bundle, "collect_report_pdfs", return_value=([], [])):
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
