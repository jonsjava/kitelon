"""Shared CLI services: workspace resolution, scans, job wait."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from kitelon_db import (
    confined_workspace_loot_path,
    create_schedule,
    enqueue_job,
    ensure_workspace,
    fix_loot_workspace_layout,
    get_connection,
    get_job,
    get_workspace_by_alias,
    migrate,
    normalize_workspace_alias,
    prune_invalid_workspaces,
    test_connection,
    discover_filesystem_workspaces,
)
from kitelon_engine.pipeline import run_scan
from kitelon_loot import generate_reports, import_loot
from kitelon_scan_config import VALID_MODE_IDS, merge_job_scan_args

INSTALL_DIR = Path(os.environ.get("KITELON_INSTALL_DIR", "/usr/share/kitelon"))
LOOT_ROOT = INSTALL_DIR / "loot"

TERMINAL_JOB_STATUSES = frozenset({"completed", "failed", "cancelled"})


class CliError(Exception):
    """User-facing CLI error."""


def resolve_workspace(alias: str | None, *, required: bool = False) -> str | None:
    if not alias:
        if required:
            raise CliError("workspace required (use -w or `use <alias>`)")
        return None
    normalized = normalize_workspace_alias(alias)
    with get_connection() as conn:
        ws = get_workspace_by_alias(conn, normalized)
    if not ws:
        raise CliError(f"workspace not found: {normalized}")
    return normalized


def workspace_loot_dir(alias: str) -> Path:
    return confined_workspace_loot_path(LOOT_ROOT, alias)


def ensure_workspace_id(conn, alias: str) -> int:
    return ensure_workspace(conn, alias, loot_root=LOOT_ROOT)


def build_scan_options(args: Any) -> dict[str, Any]:
    options: dict[str, Any] = {}
    for name in ("resume", "osint", "recon", "fullportscan", "testssl", "ffuf", "port", "preset"):
        if hasattr(args, name):
            value = getattr(args, name)
            if value not in (None, False, ""):
                options[name] = value
    return options


def build_job_args(options: dict[str, Any] | None) -> dict[str, Any]:
    if not options:
        return {}
    return merge_job_scan_args({"options": options})


def enqueue_scan(
    *,
    target: str,
    workspace: str,
    mode: str,
    options: dict[str, Any] | None = None,
    priority: int = 100,
) -> int:
    if not workspace:
        raise CliError("workspace required (use -w or `use <alias>`)")
    if mode not in VALID_MODE_IDS:
        raise CliError(f"invalid mode: {mode}")
    with get_connection() as conn:
        ws_id = ensure_workspace_id(conn, workspace)
        job_id = enqueue_job(
            conn,
            job_type="scan",
            workspace_id=ws_id,
            target=target,
            mode=mode,
            args=build_job_args(options),
            priority=priority,
            created_by="kitelon-cli",
        )
    return job_id


def run_sync_scan(
    *,
    target: str,
    workspace: str,
    mode: str,
    options: dict[str, Any] | None = None,
) -> int:
    if not workspace:
        raise CliError("workspace required (use -w or `use <alias>`)")
    if mode not in VALID_MODE_IDS:
        raise CliError(f"invalid mode: {mode}")
    scan_options = {
        "resume": bool((options or {}).get("resume")),
        "osint": bool((options or {}).get("osint")),
        "recon": bool((options or {}).get("recon")),
        "fullportscan": bool((options or {}).get("fullportscan")),
        "port": (options or {}).get("port"),
        "enable_testssl": bool((options or {}).get("testssl")) or None,
        "enable_ffuf": bool((options or {}).get("ffuf")) or None,
        "preset": (options or {}).get("preset"),
    }
    scan_options = {k: v for k, v in scan_options.items() if v not in (None, False)}
    exit_code = run_scan(
        target=target,
        mode=mode,
        workspace=workspace,
        options=scan_options,
        job_id=None,
    )
    if exit_code == 0 and workspace:
        loot_dir = workspace_loot_dir(workspace)
        import_loot(loot_dir, workspace)
        generate_reports(loot_dir, workspace)
    return exit_code


def wait_for_job(
    job_id: int,
    *,
    poll_sec: float = 2.0,
    timeout: float | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    last_status = None
    while True:
        with get_connection() as conn:
            job = get_job(conn, job_id)
        if not job:
            raise CliError(f"job not found: {job_id}")
        status = job["status"]
        if status != last_status:
            last_status = status
        if status in TERMINAL_JOB_STATUSES:
            return dict(job)
        if timeout is not None and time.monotonic() - started > timeout:
            raise CliError(f"timed out waiting for job #{job_id} (status={status})")
        time.sleep(poll_sec)


def create_scan_schedule(
    *,
    workspace: str,
    cron: str,
    target: str,
    mode: str = "normal",
    options: dict[str, Any] | None = None,
) -> int:
    if mode not in VALID_MODE_IDS:
        raise CliError(f"invalid mode: {mode}")
    with get_connection() as conn:
        ws_id = ensure_workspace_id(conn, workspace)
        sched_id = create_schedule(
            conn,
            ws_id,
            cron,
            target,
            mode,
            build_job_args(options) or None,
        )
    return sched_id


def run_db_import(alias: str, *, action: str = "all") -> str:
    loot_dir = get_workspace_loot_path(alias)
    if not loot_dir.is_dir():
        raise CliError(f"loot directory not found: {loot_dir}")
    if action in ("all", "import"):
        import_loot(loot_dir, alias)
    if action in ("all", "report"):
        generate_reports(loot_dir, alias)
    if action == "import":
        return f"imported loot for workspace {alias}"
    if action == "report":
        return f"regenerated reports for workspace {alias}"
    return f"imported loot and regenerated reports for workspace {alias}"


def run_db_command(cmd: str, *, loot_root: Path | None = None) -> str:
    root = loot_root or LOOT_ROOT
    if cmd == "migrate":
        migrate()
        return "migrations applied"
    if cmd == "test":
        test_connection(verbose=True)
        return "database connection OK"
    if cmd == "prune-workspaces":
        with get_connection() as conn:
            fix_loot_workspace_layout(root)
            for alias, path in discover_filesystem_workspaces(root):
                ensure_workspace(conn, alias, loot_root=root)
            removed = prune_invalid_workspaces(conn, root)
        return f"removed {removed} invalid workspace row(s)"
    if cmd == "fix-loot-layout":
        result = fix_loot_workspace_layout(root)
        moved = result["removed_meta"]
        lines = []
        if result["moved"]:
            lines.append(f"moved {len(result['moved'])} workspace(s): {', '.join(result['moved'])}")
        else:
            lines.append("no workspace directories needed moving")
        if moved:
            lines.append(f"removed nested path(s): {', '.join(moved)}")
        lines.append(f"loot/workspace: {result['workspace_dir']}")
        lines.append("loot/workspaces -> workspace (symlink)")
        return "\n".join(lines)
    raise CliError(f"unknown db command: {cmd}")


def get_workspace_loot_path(alias: str) -> Path:
    with get_connection() as conn:
        ws = get_workspace_by_alias(conn, alias)
    if ws and ws.get("loot_path"):
        return Path(ws["loot_path"])
    return workspace_loot_dir(alias)


def list_workspace_ssl_scans(alias: str) -> list[dict[str, Any]]:
    from kitelon_testssl import list_ssl_scan_summaries

    return list_ssl_scan_summaries(get_workspace_loot_path(alias))


def get_workspace_ssl_scan(
    alias: str,
    hostname: str,
    port: str = "443",
) -> dict[str, Any] | None:
    from kitelon_env import extract_ssl_rating, ssl_report_rel_path
    from kitelon_testssl import load_testssl_scans

    loot = get_workspace_loot_path(alias)
    port = str(port or "443")
    for scan in load_testssl_scans(loot):
        host = scan.get("target") or ""
        scan_port = str(scan.get("port") or "443")
        if host == hostname and scan_port == port:
            rating = extract_ssl_rating(scan)
            rel = ssl_report_rel_path(hostname, scan_port)
            return {
                "scan": scan,
                "hostname": host,
                "port": scan_port,
                "grade": rating.get("grade"),
                "score": rating.get("score"),
                "report_path": loot / rel,
                "index_path": loot / "reports/ssl-report.html",
            }
    return None


def format_ssl_findings_summary(scan: dict[str, Any], *, limit: int = 15) -> list[str]:
    from kitelon_testssl import _map_testssl_severity

    lines: list[str] = []
    findings = scan.get("findings") or []
    notable = [
        f
        for f in findings
        if _map_testssl_severity(str(f.get("severity", ""))) != "INFO"
        or "not ok" in str(f.get("finding", "")).lower()
    ]
    for item in notable[:limit]:
        sev = _map_testssl_severity(str(item.get("severity", "")))
        check = item.get("id") or item.get("check") or "-"
        finding = (item.get("finding") or item.get("result") or "").strip()
        lines.append(f"  [{sev:8}] {check}: {finding}")
    remaining = len(notable) - limit
    if remaining > 0:
        lines.append(f"  ... and {remaining} more notable finding(s)")
    if not notable:
        lines.append("  (no notable issues: see full HTML report for all checks)")
    return lines
