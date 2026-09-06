"""Plugin registry: manifest-driven enablement and pipeline grouping."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from kitelon_engine.context import ScanContext


class RegistryError(ValueError):
    """Invalid registry manifest."""


@dataclass(frozen=True)
class PluginSpec:
    id: str
    label: str
    wrapper: str
    config_option: str
    pipelines: tuple[str, ...] = ()
    order: int = 100
    addons: tuple[str, ...] = ()
    packs: tuple[str, ...] = ()
    always_on: bool = False


@dataclass
class PluginRegistry:
    plugins: tuple[PluginSpec, ...]

    def get(self, plugin_id: str) -> PluginSpec | None:
        for spec in self.plugins:
            if spec.id == plugin_id:
                return spec
        return None

    def is_enabled(self, ctx: ScanContext, spec: PluginSpec) -> bool:
        if spec.always_on:
            return True
        value = ctx.options.get(spec.config_option)
        if value is None:
            return False
        return bool(value)

    def for_pipeline(self, pipeline: str, ctx: ScanContext) -> list[PluginSpec]:
        name = (pipeline or "").strip().lower()
        enabled = [
            spec
            for spec in self.plugins
            if name in spec.pipelines and self.is_enabled(ctx, spec)
        ]
        return sorted(enabled, key=lambda s: (s.order, s.id))


def registry_path(install_dir: Path) -> Path:
    for name in ("registry.json", "registry.yaml", "registry.yml"):
        path = install_dir / "conf" / "plugins" / name
        if path.is_file():
            return path
    return install_dir / "conf" / "plugins" / "registry.json"


def _parse_plugin(raw: dict[str, Any]) -> PluginSpec:
    plugin_id = str(raw.get("id") or "").strip()
    if not plugin_id:
        raise RegistryError("plugin entry missing id")
    label = str(raw.get("label") or plugin_id).strip()
    wrapper = str(raw.get("wrapper") or plugin_id).strip()
    config_option = str(raw.get("config_option") or "").strip()
    if not config_option and not raw.get("always_on"):
        raise RegistryError(f"plugin {plugin_id!r} missing config_option")
    pipelines = tuple(str(p).strip().lower() for p in (raw.get("pipelines") or []) if str(p).strip())
    order = int(raw.get("order", 100))
    addons = tuple(str(a).strip() for a in (raw.get("addons") or []) if str(a).strip())
    packs = tuple(str(p).strip() for p in (raw.get("packs") or []) if str(p).strip())
    always_on = bool(raw.get("always_on", False))
    return PluginSpec(
        id=plugin_id,
        label=label,
        wrapper=wrapper,
        config_option=config_option,
        pipelines=pipelines,
        order=order,
        addons=addons,
        packs=packs,
        always_on=always_on,
    )


def load_registry(install_dir: Path) -> PluginRegistry:
    path = registry_path(install_dir)
    if not path.is_file():
        raise RegistryError(f"plugin registry not found: {path}")
    if path.suffix.lower() != ".json":
        raise RegistryError(f"unsupported registry format (use JSON): {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RegistryError(f"invalid registry JSON: {exc}") from exc
    raw_plugins = data.get("plugins")
    if not isinstance(raw_plugins, list):
        raise RegistryError("registry must contain a plugins list")
    plugins = tuple(_parse_plugin(entry) for entry in raw_plugins if isinstance(entry, dict))
    return PluginRegistry(plugins=plugins)


@lru_cache(maxsize=8)
def get_registry(install_dir_str: str) -> PluginRegistry:
    """Load registry from disk. Call clear_registry_cache() after editing registry.json."""
    return load_registry(Path(install_dir_str))


def clear_registry_cache() -> None:
    get_registry.cache_clear()
