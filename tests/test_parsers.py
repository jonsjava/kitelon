"""Parser and pipeline unit tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kitelon_engine.findings import Finding, FindingWriter, parse_findings_jsonl
from kitelon_engine.tools.ffuf import parse_ffuf_json
from kitelon_engine.tools.webtech import parse_webtech_json
from kitelon_engine.artifacts import Manifest
from kitelon_engine.context import ScanContext


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_parse_ffuf_json():
    rows = parse_ffuf_json(FIXTURES / "ffuf" / "sample.json")
    assert len(rows) == 1
    assert rows[0]["url"] == "https://example.com/admin"
    assert rows[0]["status"] == 200


def test_parse_webtech_json():
    rows = parse_webtech_json(FIXTURES / "webtech" / "sample.json")
    names = {r["name"] for r in rows}
    assert "nginx" in names
    assert "PHP" in names


def test_finding_optional_fields(tmp_path: Path):
    path = tmp_path / "findings.jsonl"
    FindingWriter(path).emit(
        Finding(
            severity="high",
            name="test",
            hostname="example.com",
            source="nuclei",
            cve="CVE-2024-0001",
        )
    )
    rows = parse_findings_jsonl(path)
    assert rows[0]["cve"] == "CVE-2024-0001"
    assert rows[0]["source"] == "nuclei"


def test_manifest_resume_skip(tmp_path: Path):
    install = tmp_path / "kitelon"
    install.mkdir()
    loot = install / "loot" / "workspace" / "demo"
    loot.mkdir(parents=True)
    ctx = ScanContext(
        install_dir=install,
        target="example.com",
        mode="normal",
        workspace="demo",
        options={"resume": True},
    )
    ctx.ensure_dirs()
    manifest = Manifest(ctx)
    artifact = manifest.artifact_path("web", "example.com", "httpx-443.txt")
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("ok", encoding="utf-8")
    manifest.step_done("httpx-example.com-443", str(artifact.relative_to(ctx.loot_root)))
    manifest.save()
    assert manifest.should_skip("httpx-example.com-443", artifact) is True


def test_loot_enrich_services_parser(tmp_path: Path):
    from kitelon_loot_enrich import parse_services_from_nmap

    loot = tmp_path / "loot"
    nmap_dir = loot / "artifacts" / "nmap"
    nmap_dir.mkdir(parents=True)
    (nmap_dir / "example.com.xml").write_text(
        (FIXTURES / "nmap" / "sample.xml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    class FakeConn:
        def __init__(self):
            self.rows = []

        def execute(self, *args, **kwargs):
            return self

        def fetchone(self):
            return None

        def fetchall(self):
            return self.rows

    conn = FakeConn()
    # Monkeypatch insert: import inside test via real function would need DB.
    from kitelon_db import insert_service

    captured: list[tuple] = []

    def _capture(conn, workspace_id, hostname, port, protocol="tcp", **kwargs):
        captured.append((hostname, port, kwargs.get("product")))

    import kitelon_loot_enrich as enrich

    original = enrich.insert_service
    enrich.insert_service = _capture  # type: ignore
    try:
        parse_services_from_nmap(conn, 1, loot)
    finally:
        enrich.insert_service = original  # type: ignore

    assert captured
    assert captured[0][0] == "example.com"
    assert captured[0][1] == 443
    assert captured[0][2] == "nginx"


def test_metasploit_service_modules():
    from kitelon_engine.tools.metasploit import modules_for_service
    from kitelon_engine.tools.nmap_parse import parse_nmap_services

    services = parse_nmap_services(FIXTURES / "nmap" / "sample.xml")
    assert len(services) == 1
    assert services[0].port == 443
    assert services[0].product == "nginx"

    modules = modules_for_service(445, "microsoft-ds")
    assert "auxiliary/scanner/smb/smb_ms17_010" in modules

    https_modules = modules_for_service(443, "https")
    assert "auxiliary/scanner/http/http_version" in https_modules


def test_sanitize_extra_args_blocks_injection():
    from kitelon_scan_config import merge_job_scan_args, sanitize_extra_args

    raw = ["--target", "/etc/passwd", "-rr", "--mode", "normal", "-p", "443"]
    assert sanitize_extra_args(raw) == ["-rr", "-p", "443"]

    merged = merge_job_scan_args(
        {
            "extra_args": ["--target-file", "/etc/passwd", "-rr"],
            "options": {"resume": True, "ffuf": True, "preset": "../../../etc/passwd"},
        }
    )
    assert merged["extra_args"] == ["-rr", "--ffuf"]

    stored = merge_job_scan_args({"extra_args": ["-rr", "--ffuf"]}, trust_extra=True)
    assert stored["extra_args"] == ["-rr", "--ffuf"]

    dropped = merge_job_scan_args({"extra_args": ["-rr", "--ffuf"]})
    assert dropped["extra_args"] == []


def test_format_url_allows_only_http_https():
    from kitelon_loot import format_url

    html = format_url("https://example.com/x")
    assert "href='https://example.com/x'" in html
    js = format_url("javascript:alert(1)")
    assert "href=" not in js
    assert "javascript:alert(1)" in js
    empty = format_url("")
    assert "-" in empty


def test_load_preset_stays_in_presets_dir(tmp_path: Path):
    from kitelon_engine.config import load_preset

    presets = tmp_path / "conf" / "presets"
    presets.mkdir(parents=True)
    (presets / "web.conf").write_text("THREADS=4\n", encoding="utf-8")
    (tmp_path / "kitelon.conf").write_text("INSTALL_DIR=.\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid preset name"):
        load_preset(tmp_path, "../kitelon")
    with pytest.raises(ValueError, match="invalid preset name"):
        load_preset(tmp_path, "web/../../kitelon")
