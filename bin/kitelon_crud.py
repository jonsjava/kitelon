#!/usr/bin/env python3
"""Workspace and job CRUD for the `kitelon` driver."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from kitelon_db import (
    ALL_JOB_TYPES,
    POST_JOB_TYPES,
    create_workspace,
    delete_job,
    delete_workspace,
    enqueue_job,
    ensure_workspace,
    get_connection,
    get_job,
    get_workspace_by_alias,
    list_jobs,
    list_workspaces,
    retry_job,
    update_job,
    update_workspace,
    rename_host,
    workspace_stats,
)
from kitelon_scan_config import merge_job_scan_args

INSTALL_DIR = Path(__import__("os").environ.get("KITELON_INSTALL_DIR", "/usr/share/kitelon"))
LOOT_ROOT = INSTALL_DIR / "loot"


def _print_json(data: object) -> None:
    print(json.dumps(data, indent=2, default=str))


def cmd_workspaces(args: argparse.Namespace) -> None:
    if args.ws_cmd == "list":
        with get_connection() as conn:
            rows = list_workspaces(conn)
        if args.json:
            _print_json(rows)
            return
        for ws in rows:
            stats = ws.get("stats") or {}
            print(
                f"{ws['alias']:20} hosts={stats.get('hosts_total', 0):4} "
                f"findings={stats.get('vulnerabilities_total', 0):4} "
                f"{ws.get('loot_path') or ''}"
            )
        return

    if args.ws_cmd == "show":
        with get_connection() as conn:
            ws = get_workspace_by_alias(conn, args.alias)
            if not ws:
                raise SystemExit(f"workspace not found: {args.alias}")
            data = dict(ws)
            data["stats"] = workspace_stats(conn, int(ws["id"]))
        if args.json:
            _print_json(data)
        else:
            for key, val in data.items():
                if key == "stats":
                    print("stats:")
                    for sk, sv in val.items():
                        print(f"  {sk}: {sv}")
                else:
                    print(f"{key}: {val}")
        return

    if args.ws_cmd == "create":
        ws_id, created = create_workspace(LOOT_ROOT, args.alias)
        with get_connection() as conn:
            ws = get_workspace_by_alias(conn, args.alias)
        data = dict(ws) if ws else {"id": ws_id, "alias": args.alias}
        data["created"] = created
        if args.json:
            _print_json(data)
        else:
            print(f"{'Created' if created else 'Updated'} workspace {args.alias} (id={ws_id})")
        return

    if args.ws_cmd == "update":
        with get_connection() as conn:
            ws = update_workspace(
                conn,
                args.alias,
                new_alias=args.rename,
                loot_root=LOOT_ROOT,
            )
        if args.json:
            _print_json(dict(ws))
        else:
            print(f"Updated workspace {ws['alias']}")
        return

    if args.ws_cmd == "rename-host":
        with get_connection() as conn:
            ws = get_workspace_by_alias(conn, args.alias)
            if not ws:
                raise SystemExit(f"workspace not found: {args.alias}")
            row = rename_host(conn, int(ws["id"]), args.hostname, args.new_name)
        if args.json:
            _print_json(dict(row))
        else:
            print(f"Renamed host {args.hostname} → {row['hostname']} in {args.alias}")
        return

    if args.ws_cmd == "delete":
        with get_connection() as conn:
            ws = delete_workspace(conn, args.alias, delete_loot=args.delete_loot)
        if args.json:
            _print_json({"deleted": ws["alias"], "loot_removed": args.delete_loot})
        else:
            msg = f"Deleted workspace {ws['alias']}"
            if args.delete_loot:
                msg += " (loot removed from disk)"
            print(msg)
        return

    if args.ws_cmd == "export":
        from kitelon_workspace_pack import export_workspace_zip  # noqa: E402

        path = export_workspace_zip(
            args.alias,
            args.output,
            loot_root=LOOT_ROOT,
        )
        if args.json:
            _print_json({"alias": args.alias, "path": str(path)})
        else:
            print(path)
        return

    if args.ws_cmd == "import":
        from kitelon_workspace_pack import import_workspace_zip  # noqa: E402

        result = import_workspace_zip(
            args.zip_path,
            alias=args.alias,
            loot_root=LOOT_ROOT,
            replace=args.replace,
        )
        if args.json:
            _print_json(result)
        else:
            print(
                f"Imported {result['alias']}: {result['hosts']} hosts, "
                f"{result['vulnerabilities']} findings, {result['artifacts']} artifacts"
            )
        return


def cmd_jobs(args: argparse.Namespace) -> None:
    if args.job_cmd == "list":
        with get_connection() as conn:
            ws_id = None
            if args.workspace:
                ws = get_workspace_by_alias(conn, args.workspace)
                if not ws:
                    raise SystemExit(f"workspace not found: {args.workspace}")
                ws_id = int(ws["id"])
            rows = list_jobs(conn, status=args.status, workspace_id=ws_id, limit=args.limit)
        if args.json:
            _print_json([dict(r) for r in rows])
            return
        for j in rows:
            ws = j.get("workspace_alias") or "-"
            print(
                f"{j['id']:4} {j['status']:10} {j['job_type']:12} {ws:15} "
                f"{j.get('target') or '-':20} {j.get('mode') or '-'}"
            )
            if j["status"] == "failed" and j.get("error_message"):
                print(f"      error: {j['error_message']}")
        return

    if args.job_cmd == "show":
        with get_connection() as conn:
            j = get_job(conn, args.id)
        if not j:
            raise SystemExit(f"job not found: {args.id}")
        if args.json:
            _print_json(dict(j))
        else:
            for label, key in (
                ("id", "id"),
                ("status", "status"),
                ("type", "job_type"),
                ("workspace", "workspace_alias"),
                ("target", "target"),
                ("mode", "mode"),
                ("priority", "priority"),
                ("exit_code", "exit_code"),
                ("created_by", "created_by"),
                ("scheduled_at", "scheduled_at"),
                ("started_at", "started_at"),
                ("finished_at", "finished_at"),
                ("error", "error_message"),
            ):
                print(f"{label:12} {j.get(key) or '-'}")
        return

    if args.job_cmd == "create":
        if args.type == "scan" and not args.target:
            raise SystemExit("target required for scan jobs")
        if args.type == "scan" and not args.workspace:
            raise SystemExit("workspace required for scan jobs")
        if args.type in POST_JOB_TYPES and not args.workspace:
            raise SystemExit(f"workspace required for {args.type} jobs")
        with get_connection() as conn:
            ws_id = None
            if args.workspace:
                ws_id = ensure_workspace(conn, args.workspace, loot_root=LOOT_ROOT)
            job_args = json.loads(args.args) if args.args else {}
            if not isinstance(job_args, dict):
                raise SystemExit("args must be a JSON object")
            job_id = enqueue_job(
                conn,
                job_type=args.type,
                workspace_id=ws_id,
                target=args.target,
                mode=args.mode,
                args=merge_job_scan_args(job_args, trust_extra=True),
                priority=args.priority,
                created_by=args.created_by,
            )
        if args.json:
            _print_json({"id": job_id, "status": "pending"})
        else:
            print(f"Enqueued job #{job_id}")
        return

    if args.job_cmd == "update":
        fields: dict = {}
        if args.priority is not None:
            fields["priority"] = args.priority
        if args.target is not None:
            fields["target"] = args.target
        if args.mode is not None:
            fields["mode"] = args.mode
        if args.type is not None:
            fields["job_type"] = args.type
        if args.workspace is not None:
            fields["workspace"] = args.workspace
        if args.scheduled_at is not None:
            fields["scheduled_at"] = args.scheduled_at
        if args.args is not None:
            fields["args"] = json.loads(args.args)
        with get_connection() as conn:
            j = update_job(conn, args.id, **fields)
        if args.json:
            _print_json(dict(j))
        else:
            print(f"Updated job #{args.id}")
        return

    if args.job_cmd == "delete":
        with get_connection() as conn:
            j = delete_job(conn, args.id, kill=args.kill)
        if args.json:
            _print_json({"deleted": j["id"], "status": j.get("status")})
        else:
            action = "Cancelled" if j.get("status") == "cancelled" else "Deleted"
            print(f"{action} job #{j['id']}")
        return

    if args.job_cmd == "retry":
        with get_connection() as conn:
            new_id = retry_job(conn, args.id, created_by="cli")
        if args.json:
            _print_json({"id": new_id, "retried_from": args.id})
        else:
            print(f"Re-queued job {args.id} as new job #{new_id}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Kitelon workspace and job CRUD")
    sub = parser.add_subparsers(dest="resource", required=True)

    ws = sub.add_parser("workspaces", help="Workspace CRUD")
    ws_sub = ws.add_subparsers(dest="ws_cmd", required=True)

    p = ws_sub.add_parser("list")
    p.add_argument("--json", action="store_true")

    p = ws_sub.add_parser("show")
    p.add_argument("alias")
    p.add_argument("--json", action="store_true")

    p = ws_sub.add_parser("create")
    p.add_argument("alias")
    p.add_argument("--json", action="store_true")

    p = ws_sub.add_parser("update")
    p.add_argument("alias")
    p.add_argument("--rename", help="New workspace alias")

    p = ws_sub.add_parser("rename-host")
    p.add_argument("alias")
    p.add_argument("hostname", help="Current hostname")
    p.add_argument("new_name", help="New hostname")
    p.add_argument("--json", action="store_true")

    p = ws_sub.add_parser("delete")
    p.add_argument("alias")
    p.add_argument("--delete-loot", action="store_true", help="Remove loot directory")
    p.add_argument("--json", action="store_true")

    p = ws_sub.add_parser("export")
    p.add_argument("alias")
    p.add_argument("--output", "-o", type=Path)
    p.add_argument("--json", action="store_true")

    p = ws_sub.add_parser("import")
    p.add_argument("zip_path", type=Path)
    p.add_argument("--alias", help="Override workspace alias from zip")
    p.add_argument("--replace", action="store_true", help="Replace existing workspace")
    p.add_argument("--json", action="store_true")

    jobs = sub.add_parser("jobs", help="Job CRUD")
    job_sub = jobs.add_subparsers(dest="job_cmd", required=True)

    p = job_sub.add_parser("list")
    p.add_argument("--status")
    p.add_argument("--workspace")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--json", action="store_true")

    p = job_sub.add_parser("show")
    p.add_argument("id", type=int)
    p.add_argument("--json", action="store_true")

    p = job_sub.add_parser("create")
    p.add_argument("--type", default="scan", choices=ALL_JOB_TYPES)
    p.add_argument("--workspace")
    p.add_argument("--target")
    p.add_argument("--mode", default="normal")
    p.add_argument("--priority", type=int, default=100)
    p.add_argument("--args", help="JSON object")
    p.add_argument("--created-by", default="cli")
    p.add_argument("--json", action="store_true")

    p = job_sub.add_parser("update")
    p.add_argument("id", type=int)
    p.add_argument("--priority", type=int)
    p.add_argument("--target")
    p.add_argument("--mode")
    p.add_argument("--type", choices=ALL_JOB_TYPES)
    p.add_argument("--workspace")
    p.add_argument("--scheduled-at")
    p.add_argument("--args", help="JSON object")
    p.add_argument("--json", action="store_true")

    p = job_sub.add_parser("delete")
    p.add_argument("id", type=int)
    p.add_argument("--kill", action="store_true", help="Cancel a running job")
    p.add_argument("--json", action="store_true")

    p = job_sub.add_parser("retry")
    p.add_argument("id", type=int)
    p.add_argument("--json", action="store_true")

    args = parser.parse_args()
    if args.resource == "workspaces":
        cmd_workspaces(args)
    else:
        cmd_jobs(args)


if __name__ == "__main__":
    main()
