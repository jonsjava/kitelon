"""Load plugin content packs from conf/packs/."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


class PackError(ValueError):
    """Invalid or missing pack."""


def packs_root(install_dir: Path) -> Path:
    """Directory containing per-plugin pack folders."""
    return install_dir / "conf" / "packs"


def pack_path(install_dir: Path, plugin_id: str, pack_id: str) -> Path:
    plugin_id = _safe_id(plugin_id)
    pack_id = _safe_id(pack_id)
    for name in (f"{pack_id}.json", f"{pack_id}.yaml", f"{pack_id}.yml"):
        candidate = packs_root(install_dir) / plugin_id / name
        if candidate.is_file():
            return candidate
    return packs_root(install_dir) / plugin_id / f"{pack_id}.json"


def _safe_id(value: str) -> str:
    token = (value or "").strip()
    if not token or "/" in token or ".." in token:
        raise PackError(f"invalid pack id: {value!r}")
    return token


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PackError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PackError(f"pack must be a JSON object: {path}")
    return data


@lru_cache(maxsize=32)
def load_pack(install_dir_str: str, plugin_id: str, pack_id: str) -> dict[str, Any]:
    """Load a pack JSON file. Call clear_pack_cache() after editing pack files."""
    install_dir = Path(install_dir_str)
    path = pack_path(install_dir, plugin_id, pack_id)
    if not path.is_file():
        raise PackError(f"pack not found: {plugin_id}/{pack_id} ({path})")
    return _load_json(path)


def list_packs(install_dir: Path, plugin_id: str | None = None) -> list[tuple[str, str]]:
    root = packs_root(install_dir)
    if not root.is_dir():
        return []
    out: list[tuple[str, str]] = []
    if plugin_id:
        plugin_dirs = [root / _safe_id(plugin_id)]
    else:
        plugin_dirs = sorted(p for p in root.iterdir() if p.is_dir())
    for plugin_dir in plugin_dirs:
        if not plugin_dir.is_dir():
            continue
        pid = plugin_dir.name
        for path in sorted(plugin_dir.glob("*.json")):
            out.append((pid, path.stem))
    return out


def clear_pack_cache() -> None:
    load_pack.cache_clear()
