"""Tests for kitelon-cli tab completion helpers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

cmd2 = pytest.importorskip("cmd2")

from kitelon_engine.cli.completers import (  # noqa: E402
    PRESET_DESCRIPTIONS,
    _preset_description,
    mode_choices_provider,
    mode_descriptions,
    port_choices_provider,
    preset_choices_provider,
)
from kitelon_engine.cli.session import SessionContext  # noqa: E402
from kitelon_scan_config import SCAN_MODES, VALID_MODE_IDS  # noqa: E402


def test_mode_descriptions_cover_all_modes():
    desc = mode_descriptions()
    assert set(desc) == set(VALID_MODE_IDS)
    for mode in SCAN_MODES:
        assert desc[mode["id"]] == mode["description"]


def test_preset_descriptions_known_names():
    assert "osint-deep" in PRESET_DESCRIPTIONS
    assert _preset_description("unknown-preset") == "Load conf/presets overrides"


def test_mode_choices_provider_returns_display_meta():
    app = SimpleNamespace(session=SessionContext())
    choices = mode_choices_provider(app)
    items = list(choices)
    assert items
    normal = next(item for item in items if item.value == "normal")
    assert normal.display_meta == mode_descriptions()["normal"]


def test_port_choices_provider_includes_common_ports():
    app = SimpleNamespace(session=SessionContext())
    choices = port_choices_provider(app)
    values = {item.value for item in choices}
    assert {"80", "443"}.issubset(values)
    port_443 = next(item for item in choices if item.value == "443")
    assert "HTTPS" in port_443.display_meta


def test_preset_choices_provider_returns_items(monkeypatch):
    monkeypatch.setattr(
        "kitelon_engine.cli.completers.preset_names",
        lambda: ["osint-deep", "web"],
    )
    app = SimpleNamespace(session=SessionContext())
    choices = preset_choices_provider(app)
    by_value = {item.value: item.display_meta for item in choices}
    assert by_value["osint-deep"] == PRESET_DESCRIPTIONS["osint-deep"]
    assert by_value["web"] == PRESET_DESCRIPTIONS["web"]
