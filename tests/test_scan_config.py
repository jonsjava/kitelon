"""Scan mode catalog tests."""

import re

from kitelon_scan_config import SCAN_MODES, VALID_MODE_IDS, scan_config_payload

_MODE_ID = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def test_scan_config_lists_all_modes():
    payload = scan_config_payload()
    ids = {m["id"] for m in payload["modes"]}
    assert ids == {m["id"] for m in SCAN_MODES}
    assert ids == VALID_MODE_IDS


def test_mode_ids_use_kebab_case():
    for spec in SCAN_MODES:
        assert _MODE_ID.fullmatch(spec["id"]), spec["id"]


def test_each_mode_has_metadata():
    for spec in SCAN_MODES:
        assert spec.get("label")
        assert spec.get("description")


def test_registry_resolves_modes():
    from kitelon_engine.pipelines.registry import get_pipeline

    for mode_id in ("normal", "stealth", "web-deep", "allports", "batch-ports", "full-audit"):
        assert callable(get_pipeline(mode_id))
