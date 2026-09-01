#!/usr/bin/env python3
"""Export and import Kitelon workspaces as ZIP archives."""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_BIN_DIR = Path(__file__).resolve().parent
if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))

from kitelon_db import (  # noqa: E402
    confined_workspace_loot_path,
    create_workspace,
    clear_workspace_data,
    get_connection,
    get_workspace_by_alias,
    insert_domain,
    insert_notification,
    insert_vulnerability,
    list_domains,
    list_hosts,
    list_notifications,
    list_vulns,
    log,
    mark_imported,
    set_stat,
    upsert_host,
    workspace_stats,
)
from kitelon_storage import (  # noqa: E402
    fs_mirror_enabled,
    get_artifact,
    list_artifacts,
    normalize_rel_path,
    put_artifact,
    store_artifact,
)

PACK_FORMAT = "kitelon-workspace-v1"
MANIFEST_NAME = "manifest.json"
DATA_PREFIX = "data/"
ARTIFACTS_PREFIX = "artifacts/"


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"not JSON serializable: {type(value)}")


def _export_data(conn: Any, workspace_id: int) -> dict[str, Any]:
    hosts = [
        {k: v for k, v in dict(row).items() if k not in ("id", "workspace_id")}
        for row in list_hosts(conn, workspace_id, limit=100000)
    ]
    domains = [
        {k: v for k, v in dict(row).items() if k not in ("id", "workspace_id")}
        for row in list_domains(conn, workspace_id, limit=100000)
    ]
    vulns = [
        {k: v for k, v in dict(row).items() if k not in ("id", "workspace_id")}
        for row in list_vulns(conn, workspace_id, limit=100000)
    ]
    notifications = [
        {k: v for k, v in dict(row).items() if k not in ("id", "workspace_id")}
        for row in list_notifications(conn, workspace_id, limit=10000)
    ]
    stats = workspace_stats(conn, workspace_id)
    return {
        "hosts": hosts,
        "domains": domains,
        "vulnerabilities": vulns,
        "notifications": notifications,
        "stats": stats,
    }


def export_workspace_zip(
    alias: str,
    output_path: Path | None = None,
    *,
    loot_root: Path | None = None,
) -> Path:
    install = Path(__import__("os").environ.get("KITELON_INSTALL_DIR", "/usr/share/kitelon"))
    loot_root = loot_root or install / "loot"

    with get_connection() as conn:
        ws = get_workspace_by_alias(conn, alias)
        if not ws:
            raise ValueError(f"workspace not found: {alias}")
        workspace_id = int(ws["id"])
        manifest = {
            "format": PACK_FORMAT,
            "alias": alias,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "source_loot_path": ws["loot_path"],
        }
        data = _export_data(conn, workspace_id)
        artifacts = list_artifacts(conn, workspace_id, limit=100000)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2))
        for key, rows in data.items():
            zf.writestr(
                f"{DATA_PREFIX}{key}.json",
                json.dumps(rows, indent=2, default=_json_default),
            )
        with get_connection() as conn:
            for meta in artifacts:
                row = get_artifact(conn, workspace_id, meta["rel_path"])
                if not row:
                    continue
                content = row["content"]
                if isinstance(content, memoryview):
                    content = content.tobytes()
                rel = normalize_rel_path(meta["rel_path"])
                zf.writestr(f"{ARTIFACTS_PREFIX}{rel}", bytes(content))

    if output_path is None:
        fd, name = tempfile.mkstemp(prefix=f"kitelon-{alias}-", suffix=".zip")
        os.close(fd)
        output_path = Path(name)
    else:
        output_path = Path(output_path)
    output_path.write_bytes(buffer.getvalue())
    log(f"exported workspace {alias} to {output_path}")
    return output_path


def _restore_data(conn: Any, workspace_id: int, data: dict[str, Any]) -> None:
    for host in data.get("hosts") or []:
        upsert_host(
            conn,
            workspace_id,
            host["hostname"],
            host.get("ip"),
            host.get("mac"),
            host.get("os_guess"),
            int(host.get("is_live") or 0),
            float(host.get("risk_score") or 0),
            host.get("open_ports"),
            host.get("web_title"),
        )
    for domain in data.get("domains") or []:
        insert_domain(
            conn,
            workspace_id,
            domain["fqdn"],
            int(domain.get("is_target") or 0),
        )
    for vuln in data.get("vulnerabilities") or []:
        insert_vulnerability(
            conn,
            workspace_id,
            vuln["hostname"],
            vuln["severity"],
            vuln["name"],
            vuln.get("url"),
            vuln.get("evidence"),
            vuln.get("source_file"),
        )
    for note in data.get("notifications") or []:
        insert_notification(conn, workspace_id, note["message"])
    for key, value in (data.get("stats") or {}).items():
        set_stat(conn, workspace_id, key, int(value))


def import_workspace_zip(
    zip_path: Path,
    *,
    alias: str | None = None,
    loot_root: Path | None = None,
    replace: bool = False,
) -> dict[str, Any]:
    install = Path(__import__("os").environ.get("KITELON_INSTALL_DIR", "/usr/share/kitelon"))
    loot_root = loot_root or install / "loot"
    zip_path = zip_path.resolve()
    if not zip_path.is_file():
        raise ValueError(f"zip not found: {zip_path}")

    with zipfile.ZipFile(zip_path, "r") as zf:
        if MANIFEST_NAME not in zf.namelist():
            raise ValueError("invalid workspace zip: missing manifest.json")
        manifest = json.loads(zf.read(MANIFEST_NAME).decode("utf-8"))
        if manifest.get("format") != PACK_FORMAT:
            raise ValueError(f"unsupported pack format: {manifest.get('format')}")

        target_alias = alias or manifest.get("alias")
        if not target_alias:
            raise ValueError("workspace alias required")

        data: dict[str, Any] = {}
        for name in zf.namelist():
            if not name.startswith(DATA_PREFIX) or not name.endswith(".json"):
                continue
            key = name[len(DATA_PREFIX) : -5]
            data[key] = json.loads(zf.read(name).decode("utf-8"))

        artifact_entries = [
            name for name in zf.namelist()
            if name.startswith(ARTIFACTS_PREFIX) and not name.endswith("/")
        ]

        with get_connection() as conn:
            existing = get_workspace_by_alias(conn, target_alias)
            if existing and not replace:
                raise ValueError(
                    f"workspace already exists: {target_alias} (use --replace)"
                )

        ws_id, created = create_workspace(loot_root, target_alias)
        loot_dir = confined_workspace_loot_path(loot_root, target_alias)

        with get_connection() as conn:
            clear_workspace_data(conn, ws_id)
            _restore_data(conn, ws_id, data)

            artifact_count = 0
            mirror = fs_mirror_enabled()
            for entry in artifact_entries:
                rel = normalize_rel_path(entry[len(ARTIFACTS_PREFIX) :])
                content = zf.read(entry)
                store_artifact(conn, ws_id, loot_dir, rel, content, mirror=mirror)
                artifact_count += 1

            imported_at = manifest.get("exported_at")
            if imported_at:
                try:
                    parsed = datetime.fromisoformat(imported_at.replace("Z", "+00:00"))
                    conn.execute(
                        "UPDATE workspaces SET last_imported_at = %s WHERE id = %s",
                        (parsed, ws_id),
                    )
                except ValueError:
                    mark_imported(conn, ws_id)
            else:
                mark_imported(conn, ws_id)

    log(f"imported workspace {target_alias} from {zip_path}")
    return {
        "alias": target_alias,
        "workspace_id": ws_id,
        "created": created,
        "artifacts": artifact_count,
        "hosts": len(data.get("hosts") or []),
        "vulnerabilities": len(data.get("vulnerabilities") or []),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Kitelon workspace ZIP import/export")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_export = sub.add_parser("export", help="Export workspace to ZIP")
    p_export.add_argument("alias")
    p_export.add_argument("--output", "-o", type=Path)
    p_export.add_argument("--loot-root", type=Path)

    p_import = sub.add_parser("import", help="Import workspace from ZIP")
    p_import.add_argument("zip_path", type=Path)
    p_import.add_argument("--alias", help="Override workspace alias")
    p_import.add_argument("--loot-root", type=Path)
    p_import.add_argument(
        "--replace",
        action="store_true",
        help="Replace existing workspace data",
    )
    p_import.add_argument("--json", action="store_true")

    args = parser.parse_args()
    try:
        if args.cmd == "export":
            path = export_workspace_zip(
                args.alias,
                args.output,
                loot_root=args.loot_root,
            )
            print(path)
        else:
            result = import_workspace_zip(
                args.zip_path,
                alias=args.alias,
                loot_root=args.loot_root,
                replace=args.replace,
            )
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(
                    f"Imported workspace {result['alias']} "
                    f"({result['hosts']} hosts, {result['vulnerabilities']} findings, "
                    f"{result['artifacts']} artifacts)"
                )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
