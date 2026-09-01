#!/usr/bin/env python3
"""PostgreSQL-backed storage for workspace loot artifacts and reports."""

from __future__ import annotations

import hashlib
import mimetypes
import os
from pathlib import Path
from typing import Any, Iterator

from kitelon_db import db_enabled, log

MAX_ARTIFACT_BYTES = int(
    os.environ.get("LOOT_ARTIFACT_MAX_BYTES", str(25 * 1024 * 1024))
)

ARCHIVE_GLOBS = (
    "manifest.json",
    "findings.jsonl",
    "scan.log",
    "artifacts/nmap/*.xml",
    "artifacts/ports/*.json",
    "artifacts/web/*",
    "artifacts/web/*/*",
    "artifacts/ssl/*.json",
    "artifacts/recon/*",
    "artifacts/screenshots/*",
    "artifacts/tools/*",
    "artifacts/tools/*/*",
    "reports/*",
    "kitelon-report.html",
)


def artifacts_enabled() -> bool:
    if not db_enabled():
        return False
    flag = os.environ.get("LOOT_ARTIFACTS_DB", "1")
    return flag not in ("0", "false", "False", "")


def fs_mirror_enabled() -> bool:
    flag = os.environ.get("LOOT_FS_MIRROR", "1")
    return flag not in ("0", "false", "False", "")


def fs_prune_enabled() -> bool:
    flag = os.environ.get("LOOT_FS_PRUNE", "0")
    return flag not in ("0", "false", "False", "")


def normalize_rel_path(rel_path: str | Path) -> str:
    rel = str(rel_path).replace("\\", "/").lstrip("/")
    parts = [part for part in rel.split("/") if part and part != "."]
    if any(part == ".." for part in parts):
        raise ValueError(f"invalid artifact path: {rel_path}")
    return "/".join(parts)


def guess_content_type(rel_path: str) -> str:
    suffix = Path(rel_path).suffix.lower()
    if suffix in (".html", ".htm", ".svg"):
        return "application/octet-stream"
    guessed, _ = mimetypes.guess_type(rel_path)
    if guessed:
        return guessed
    if rel_path.endswith(".nessus"):
        return "application/xml"
    if suffix in (".txt", ".csv", ".xml", ".json", ".sh"):
        return "text/plain; charset=utf-8"
    return "application/octet-stream"


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def artifact_api_url(workspace_alias: str, rel_path: str) -> str:
    rel = normalize_rel_path(rel_path)
    return (
        "/api/v1/workspaces/"
        + workspace_alias
        + "/artifacts/"
        + rel
    )


def put_artifact(
    conn: Any,
    workspace_id: int,
    rel_path: str | Path,
    content: bytes | str,
    *,
    content_type: str | None = None,
) -> dict[str, Any]:
    rel = normalize_rel_path(rel_path)
    if isinstance(content, str):
        data = content.encode("utf-8")
    else:
        data = content
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError(
            f"artifact too large ({len(data)} bytes, max {MAX_ARTIFACT_BYTES}): {rel}"
        )
    ctype = content_type or guess_content_type(rel)
    digest = sha256_bytes(data)
    row = conn.execute(
        """
        INSERT INTO loot_artifacts(
            workspace_id, rel_path, content, content_type, size_bytes, sha256, updated_at
        ) VALUES (%s, %s, %s, %s, %s, %s, NOW())
        ON CONFLICT (workspace_id, rel_path) DO UPDATE SET
            content = EXCLUDED.content,
            content_type = EXCLUDED.content_type,
            size_bytes = EXCLUDED.size_bytes,
            sha256 = EXCLUDED.sha256,
            updated_at = NOW()
        RETURNING id, workspace_id, rel_path, content_type, size_bytes, sha256, updated_at
        """,
        (workspace_id, rel, data, ctype, len(data), digest),
    ).fetchone()
    return dict(row)


def get_artifact(conn: Any, workspace_id: int, rel_path: str | Path) -> dict[str, Any] | None:
    rel = normalize_rel_path(rel_path)
    row = conn.execute(
        """
        SELECT id, workspace_id, rel_path, content, content_type, size_bytes, sha256, updated_at
        FROM loot_artifacts
        WHERE workspace_id = %s AND rel_path = %s
        """,
        (workspace_id, rel),
    ).fetchone()
    return dict(row) if row else None


def get_artifact_bytes(conn: Any, workspace_id: int, rel_path: str | Path) -> bytes | None:
    row = get_artifact(conn, workspace_id, rel_path)
    if not row:
        return None
    content = row["content"]
    if isinstance(content, memoryview):
        return content.tobytes()
    return bytes(content)


def list_artifacts(
    conn: Any,
    workspace_id: int,
    *,
    prefix: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> list[dict[str, Any]]:
    if prefix:
        prefix = normalize_rel_path(prefix)
        rows = conn.execute(
            """
            SELECT id, rel_path, content_type, size_bytes, sha256, updated_at
            FROM loot_artifacts
            WHERE workspace_id = %s AND rel_path LIKE %s
            ORDER BY rel_path
            LIMIT %s OFFSET %s
            """,
            (workspace_id, prefix + "%", limit, offset),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT id, rel_path, content_type, size_bytes, sha256, updated_at
            FROM loot_artifacts
            WHERE workspace_id = %s
            ORDER BY rel_path
            LIMIT %s OFFSET %s
            """,
            (workspace_id, limit, offset),
        ).fetchall()
    return [dict(row) for row in rows]


def delete_artifact(conn: Any, workspace_id: int, rel_path: str | Path) -> bool:
    rel = normalize_rel_path(rel_path)
    cur = conn.execute(
        "DELETE FROM loot_artifacts WHERE workspace_id = %s AND rel_path = %s",
        (workspace_id, rel),
    )
    return cur.rowcount > 0


def mirror_to_filesystem(loot_dir: Path, rel_path: str, content: bytes) -> Path:
    dest = loot_dir / rel_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(content)
    return dest


def store_artifact(
    conn: Any,
    workspace_id: int,
    loot_dir: Path,
    rel_path: str | Path,
    content: bytes | str,
    *,
    content_type: str | None = None,
    mirror: bool | None = None,
) -> dict[str, Any]:
    rel = normalize_rel_path(rel_path)
    row = put_artifact(conn, workspace_id, rel, content, content_type=content_type)
    if mirror if mirror is not None else fs_mirror_enabled():
        data = content.encode("utf-8") if isinstance(content, str) else content
        mirror_to_filesystem(loot_dir, rel, data)
    return row


def prune_archived_file(loot_dir: Path, rel_path: str) -> None:
    path = loot_dir / rel_path
    if path.is_file():
        path.unlink()
        log(f"pruned archived file {rel_path}")


def store_file_from_disk(
    conn: Any,
    workspace_id: int,
    loot_dir: Path,
    file_path: Path,
    *,
    rel_path: str | None = None,
    mirror: bool | None = None,
) -> dict[str, Any] | None:
    if not file_path.is_file():
        return None
    try:
        rel = normalize_rel_path(rel_path or file_path.relative_to(loot_dir))
    except ValueError:
        return None
    size = file_path.stat().st_size
    if size > MAX_ARTIFACT_BYTES:
        log(f"skip large artifact ({size} bytes): {rel}")
        return None
    row = store_artifact(
        conn,
        workspace_id,
        loot_dir,
        rel,
        file_path.read_bytes(),
        mirror=mirror,
    )
    if fs_prune_enabled() and not (mirror if mirror is not None else fs_mirror_enabled()):
        prune_archived_file(loot_dir, rel)
    return row


def iter_archive_paths(loot_dir: Path) -> Iterator[Path]:
    seen: set[Path] = set()
    for pattern in ARCHIVE_GLOBS:
        for path in sorted(loot_dir.glob(pattern)):
            if not path.is_file() or path in seen:
                continue
            seen.add(path)
            yield path


def archive_loot_directory(
    conn: Any,
    workspace_id: int,
    loot_dir: Path,
    *,
    mirror: bool | None = None,
) -> int:
    count = 0
    for path in iter_archive_paths(loot_dir):
        if store_file_from_disk(conn, workspace_id, loot_dir, path, mirror=mirror):
            count += 1
    return count


def migrate_workspace_artifacts(
    conn: Any,
    workspace_id: int,
    loot_dir: Path,
    *,
    mirror: bool | None = None,
) -> int:
    if not loot_dir.is_dir():
        return 0
    return archive_loot_directory(conn, workspace_id, loot_dir, mirror=mirror)


def migrate_all_artifacts(loot_root: Path, *, mirror: bool | None = None) -> int:
    from kitelon_db import get_connection, list_workspaces

    total = 0
    with get_connection() as conn:
        for ws in list_workspaces(conn):
            loot_dir = Path(ws["loot_path"])
            if not loot_dir.is_dir():
                continue
            n = migrate_workspace_artifacts(
                conn, int(ws["id"]), loot_dir, mirror=mirror
            )
            log(f"archived {n} artifact(s) for workspace {ws['alias']}")
            total += n
    return total
