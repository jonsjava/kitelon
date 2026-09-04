"""Guards: scans always belong to a workspace."""

from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("LOG_DIR", "/tmp/kitelon-test-logs")

import pytest

from kitelon_db import (
    assert_confined_loot_path,
    confined_workspace_loot_path,
    enqueue_job,
    init_workspace_loot_dir,
    is_workspace_loot_dir,
    normalize_workspace_alias,
)
from kitelon_engine.context import ScanContext
from kitelon_scan_config import sanitize_extra_args
from kitelon_worker import build_scan_command


def test_scan_context_requires_workspace(tmp_path: Path):
    with pytest.raises(ValueError, match="workspace required"):
        ScanContext(
            install_dir=tmp_path,
            target="scanme.nmap.org",
            mode="normal",
            workspace="",
        )


def test_scan_context_loot_under_workspace(tmp_path: Path):
    ctx = ScanContext(
        install_dir=tmp_path,
        target="scanme.nmap.org",
        mode="normal",
        workspace="scanme",
    )
    assert ctx.loot_root == tmp_path / "loot" / "workspace" / "scanme"
    assert ctx.workspace == "scanme"


def test_init_loot_dir_is_valid_workspace(tmp_path: Path):
    path = tmp_path / "workspace" / "demo"
    init_workspace_loot_dir(path)
    assert is_workspace_loot_dir(path)


def test_enqueue_scan_requires_workspace():
    with pytest.raises(ValueError, match="workspace required"):
        enqueue_job(object(), job_type="scan", target="scanme.nmap.org")


def test_build_scan_command_requires_workspace():
    with pytest.raises(ValueError, match="workspace"):
        build_scan_command({"id": 1, "target": "scanme.nmap.org", "mode": "normal"})


def test_build_scan_command_includes_workspace():
    cmd = build_scan_command(
        {
            "id": 7,
            "target": "scanme.nmap.org",
            "mode": "normal",
            "workspace_alias": "scanme.nmap.org",
        }
    )
    assert "--workspace" in cmd
    assert "scanme.nmap.org" in cmd
    assert "--target" in cmd


def test_normalize_rejects_dotdot():
    with pytest.raises(ValueError, match="invalid workspace alias"):
        normalize_workspace_alias("..")
    with pytest.raises(ValueError, match="invalid workspace alias"):
        normalize_workspace_alias("../etc")
    with pytest.raises(ValueError):
        ScanContext(
            install_dir=Path("/tmp"),
            target="example.com",
            mode="normal",
            workspace="..",
        )


def test_absolute_alias_stays_under_loot(tmp_path: Path):
    loot = tmp_path / "loot"
    path = confined_workspace_loot_path(loot, "/etc")
    assert path == (loot / "workspace" / "etc").resolve()
    assert str(path).startswith(str((loot / "workspace").resolve()))
    with pytest.raises(ValueError, match="invalid workspace path"):
        assert_confined_loot_path("/etc", "/etc")
    with pytest.raises(ValueError, match="invalid workspace path"):
        assert_confined_loot_path("/etc", "etc")


def test_sanitize_extra_args_rejects_preset_and_port_traversal():
    assert sanitize_extra_args(["--preset", "../kitelon.conf"]) == []
    assert sanitize_extra_args(["--preset", ".hidden"]) == []
    assert sanitize_extra_args(["-p", "notaport"]) == []
    assert sanitize_extra_args(["-p", "99999"]) == []
    assert sanitize_extra_args(["-pr", "web-quick", "-p", "443"]) == [
        "-pr",
        "web-quick",
        "-p",
        "443",
    ]
    assert sanitize_extra_args(["--preset", "web-quick", "-p", "443"]) == [
        "-pr",
        "web-quick",
        "-p",
        "443",
    ]
