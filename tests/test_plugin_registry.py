"""Tests for plugin registry manifest."""

from __future__ import annotations

from pathlib import Path

import pytest

from kitelon_engine.context import ScanContext
from kitelon_engine.plugin_registry import RegistryError, get_registry, load_registry


@pytest.fixture
def install_dir(tmp_path: Path) -> Path:
    src = Path(__file__).resolve().parents[1] / "conf" / "plugins" / "registry.json"
    dest_dir = tmp_path / "conf" / "plugins"
    dest_dir.mkdir(parents=True)
    dest_dir.joinpath("registry.json").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return tmp_path


def test_load_registry(install_dir: Path):
    registry = load_registry(install_dir)
    assert registry.get("subfinder") is not None
    assert registry.get("missing") is None


def test_for_pipeline_recon_order(install_dir: Path):
    registry = load_registry(install_dir)
    ctx = ScanContext(
        install_dir=install_dir,
        target="example.com",
        mode="recon",
        workspace="demo",
        options={
            "enable_subfinder": True,
            "enable_dnsx": True,
            "enable_dnsrecon": True,
            "enable_gau": True,
        },
    )
    specs = registry.for_pipeline("recon", ctx)
    assert [s.id for s in specs] == ["subfinder", "dnsx", "dnsrecon", "gau"]


def test_missing_registry_raises(tmp_path: Path):
    with pytest.raises(RegistryError, match="not found"):
        load_registry(tmp_path)


def test_get_registry_cached(install_dir: Path):
    get_registry.cache_clear()
    a = get_registry(str(install_dir))
    b = get_registry(str(install_dir))
    assert a is b
