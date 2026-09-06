"""Tests for registry-driven recon pipeline hooks."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kitelon_engine.context import ScanContext
from kitelon_engine.pipeline_hooks import recon as recon_hooks
from kitelon_engine.plugin_registry import PluginSpec


def _ctx(install_dir: Path, **options: bool) -> ScanContext:
    return ScanContext(
        install_dir=install_dir,
        target="example.com",
        mode="recon",
        workspace="demo",
        options=options,
    )


def _spec(plugin_id: str, config_option: str) -> PluginSpec:
    return PluginSpec(
        id=plugin_id,
        label=plugin_id,
        wrapper=plugin_id,
        config_option=config_option,
    )


@pytest.mark.parametrize(
    ("plugin_id", "config_option", "tool_attr", "tool_name"),
    [
        ("dnsx", "enable_dnsx", "dnsx", "resolve_hosts"),
        ("dnsrecon", "enable_dnsrecon", "dnsrecon", "run_dnsrecon"),
        ("gau", "enable_gau", "gau", "run_gau"),
    ],
)
def test_recon_hook_respects_enable_flag(
    tmp_path: Path,
    plugin_id: str,
    config_option: str,
    tool_attr: str,
    tool_name: str,
):
    ctx = _ctx(tmp_path, **{config_option: False})
    manifest = MagicMock()
    manifest.should_skip.return_value = False
    spec = _spec(plugin_id, config_option)
    tool_module = getattr(recon_hooks, tool_attr)

    with patch.object(tool_module, tool_name) as mock_tool:
        hosts = recon_hooks.run_plugin(ctx, manifest, spec, ["sub.example.com"])
        mock_tool.assert_not_called()
        assert hosts == ["sub.example.com"]


def test_dnsx_does_not_require_subfinder_flag(tmp_path: Path):
    ctx = _ctx(tmp_path, enable_dnsx=True, enable_subfinder=False)
    manifest = MagicMock()
    manifest.should_skip.return_value = False
    dnsx_out = ctx.loot_root / "artifacts" / "recon" / "dnsx.json"
    manifest.artifact_path.return_value = dnsx_out
    spec = _spec("dnsx", "enable_dnsx")

    with patch.object(recon_hooks.dnsx, "resolve_hosts", return_value=["resolved.example.com"]) as mock:
        hosts = recon_hooks.run_plugin(ctx, manifest, spec, ["sub.example.com"])
        mock.assert_called_once()
        assert hosts == ["resolved.example.com"]
