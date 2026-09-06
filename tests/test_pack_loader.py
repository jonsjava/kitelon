"""Tests for pack loader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kitelon_engine.pack_loader import PackError, list_packs, load_pack
from kitelon_engine.tools.metasploit import modules_for_service


@pytest.fixture
def install_dir(tmp_path: Path) -> Path:
    src = Path(__file__).resolve().parents[1] / "conf" / "packs" / "metasploit" / "scanners.json"
    dest = tmp_path / "conf" / "packs" / "metasploit"
    dest.mkdir(parents=True)
    dest.joinpath("scanners.json").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return tmp_path


def test_load_msf_scanners_pack(install_dir: Path):
    pack = load_pack(str(install_dir), "metasploit", "scanners")
    assert pack["plugin_id"] == "metasploit"
    assert "445" in pack["port_modules"]


def test_list_packs(install_dir: Path):
    assert list_packs(install_dir, "metasploit") == [("metasploit", "scanners")]


def test_modules_for_service_uses_pack(install_dir: Path):
    from kitelon_engine.context import ScanContext

    ctx = ScanContext(
        install_dir=install_dir,
        target="example.com",
        mode="normal",
        workspace="demo",
        options={},
    )
    custom = install_dir / "conf" / "packs" / "metasploit" / "scanners.json"
    data = json.loads(custom.read_text(encoding="utf-8"))
    data["port_modules"]["9999"] = ["auxiliary/scanner/custom/example"]
    custom.write_text(json.dumps(data), encoding="utf-8")
    load_pack.cache_clear()

    modules = modules_for_service(ctx, 9999, "unknown")
    assert modules == ["auxiliary/scanner/custom/example"]


def test_missing_pack_raises(tmp_path: Path):
    with pytest.raises(PackError, match="not found"):
        load_pack(str(tmp_path), "metasploit", "scanners")
