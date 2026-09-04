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

PRESET_DESCRIPTIONS: dict[str, str] = {
    "osint-conservative": "Stock OSINT/recon limits; metagoofil off",
    "osint-deep": "Raised caps for lab use; metagoofil on",
    "normal": "Full pipeline; recon options off by default",
    "stealth": "Fewer threads, lighter brute force",
    "web": "Web-focused modules on 80/443",
}

COMMON_PORTS: dict[str, str] = {
    "22": "SSH",
    "25": "SMTP",
    "80": "HTTP",
    "443": "HTTPS",
    "8080": "HTTP alternate",
    "8443": "HTTPS alternate",
    "3306": "MySQL",
    "5432": "PostgreSQL",
}


def _cached(session: SessionContext, key: str, ttl: float, loader):
    now = time.monotonic()
    entry = session._cache.get(key)
    if entry and now - entry["ts"] < ttl:
        return entry["value"]
    value = loader()
    session._cache[key] = {"ts": now, "value": value}
    return value


def _completion_items(items: Iterable[tuple[str, str]], *, sort: bool = True) -> list[CompletionItem]:
    out = [CompletionItem(value, display_meta=meta) for value, meta in items]
    if sort:
        out.sort(key=lambda item: str(item.value))
    return out


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


def _preset_description(name: str) -> str:
    return PRESET_DESCRIPTIONS.get(name, "Load conf/presets overrides")


def _workspace_summary(stats: dict[str, int] | None) -> str:
    if not stats:
        return "workspace"
    hosts = stats.get("hosts", 0)
    services = stats.get("services", 0)
    if hosts or services:
        return f"{hosts} hosts, {services} services"
    return "workspace"


def mode_choices_provider(cmd_app, arg_tokens=None) -> Choices:
    return Choices(_completion_items(mode_descriptions().items()))


def preset_choices_provider(cmd_app, arg_tokens=None) -> Choices:
    items = ((name, _preset_description(name)) for name in preset_names())
    return Choices(_completion_items(items))


def workspace_choices_provider(cmd_app, arg_tokens=None) -> Choices:
    def load() -> list[CompletionItem]:
        with get_connection() as conn:
            rows = list_workspaces(conn)
        return [
            CompletionItem(
                ws["alias"],
                display_meta=_workspace_summary(ws.get("stats")),
            )
            for ws in rows
        ]

    return Choices(_cached(cmd_app.session, "workspace_items", 5.0, load))


def target_choices_provider(cmd_app, arg_tokens=None) -> Choices:
    def load() -> list[CompletionItem]:
        with get_connection() as conn:
            rows = list_jobs(conn, limit=50)
        seen: set[str] = set()
        items: list[CompletionItem] = []
        for row in rows:
            target = str(row.get("target") or "").strip()
            if not target or target in seen:
                continue
            seen.add(target)
            ws = row.get("workspace_alias") or "-"
            mode = row.get("mode") or "normal"
            status = row.get("status") or "?"
            items.append(
                CompletionItem(
                    target,
                    display_meta=f"{ws} · {mode} · job #{row['id']} ({status})",
                )
            )
        return items

    return Choices(_cached(cmd_app.session, "recent_targets", 5.0, load))


def port_choices_provider(cmd_app, arg_tokens=None) -> Choices:
    return Choices(_completion_items(COMMON_PORTS.items(), sort=False))


def job_status_choices_provider(cmd_app, arg_tokens=None) -> Choices:
    labels = {
        "pending": "Queued, not started",
        "running": "Worker is executing",
        "completed": "Finished successfully",
        "failed": "Finished with error",
        "cancelled": "Stopped or removed",
    }
    return Choices(_completion_items((status, labels[status]) for status in JOB_STATUSES))
