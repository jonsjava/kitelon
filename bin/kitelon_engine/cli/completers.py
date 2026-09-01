"""Tab completion helpers for kitelon-cli."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Iterable

from cmd2 import CompletionItem, Choices

from kitelon_db import get_connection, list_jobs, list_schedules, list_workspaces
from kitelon_engine.config import list_presets
from kitelon_engine.context import default_install_dir
from kitelon_scan_config import SCAN_MODES, VALID_MODE_IDS

if TYPE_CHECKING:
    from kitelon_engine.cli.session import SessionContext

CRON_EXAMPLES = (
    "0 2 * * *",
    "0 */6 * * *",
    "0 0 * * 0",
    "*/15 * * * *",
)

JOB_STATUSES = ("pending", "running", "completed", "failed", "cancelled")


def _cached(session: SessionContext, key: str, ttl: float, loader):
    now = time.monotonic()
    entry = session._cache.get(key)
    if entry and now - entry["ts"] < ttl:
        return entry["value"]
    value = loader()
    session._cache[key] = {"ts": now, "value": value}
    return value


def workspace_aliases(session: SessionContext) -> list[str]:
    def load() -> list[str]:
        with get_connection() as conn:
            return [ws["alias"] for ws in list_workspaces(conn)]

    return _cached(session, "workspaces", 5.0, load)


def recent_job_ids(session: SessionContext, limit: int = 50) -> list[str]:
    def load() -> list[str]:
        with get_connection() as conn:
            rows = list_jobs(conn, limit=limit)
        return [str(row["id"]) for row in rows]

    return _cached(session, "job_ids", 5.0, load)


def recent_schedule_ids(session: SessionContext, limit: int = 50) -> list[str]:
    def load() -> list[str]:
        with get_connection() as conn:
            rows = list_schedules(conn)
        return [str(row["id"]) for row in rows[:limit]]

    return _cached(session, "schedule_ids", 5.0, load)


def complete_from(items: Iterable[str], text: str, *, sort: bool = True) -> list[CompletionItem]:
    prefix = text or ""
    matches = [item for item in items if item.startswith(prefix)]
    if sort:
        matches.sort()
    return [CompletionItem(s) for s in matches]


def mode_items() -> list[str]:
    return sorted(VALID_MODE_IDS)


def mode_descriptions() -> dict[str, str]:
    return {m["id"]: m["description"] for m in SCAN_MODES}


def preset_names() -> list[str]:
    return list_presets(default_install_dir())


def preset_choices_provider(cmd_app, arg_tokens=None) -> Choices:
    return Choices.from_values(preset_names())


def workspace_choices_provider(cmd_app, arg_tokens=None) -> Choices:
    """Argparse choices_provider for -w / --workspace."""
    return Choices.from_values(workspace_aliases(cmd_app.session))
