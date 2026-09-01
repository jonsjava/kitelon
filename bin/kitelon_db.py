#!/usr/bin/env python3
# PostgreSQL: schema migrations, workspace rows, job queue, loot import hooks.

import json
import os
import re
import shutil
import signal
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None  # type: ignore
    dict_row = None  # type: ignore

try:
    from croniter import croniter
except ImportError:
    croniter = None  # type: ignore

INSTALL_DIR = Path(os.environ.get("KITELON_INSTALL_DIR", "/usr/share/kitelon"))
MIGRATIONS_DIR = INSTALL_DIR / "sql" / "migrations"
SECRETS_FILE = Path("/root/.kitelon_db.conf")
ROOT_CONFIG = Path("/root/.kitelon.conf")
INSTALL_CONFIG = INSTALL_DIR / "kitelon.conf"

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")

RISK_WEIGHTS = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

LEGACY_CRON_MAP = {
    "daily": "0 0 * * *",
    "weekly": "0 0 * * 0",
    "monthly": "0 0 1 * *",
}

CRON_FIELDS_RE = re.compile(r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+$")


def normalize_cron(expr: str) -> str:
    cleaned = " ".join(str(expr).strip().split())
    return LEGACY_CRON_MAP.get(cleaned, cleaned)


def validate_cron(expr: str) -> str:
    cron_expr = normalize_cron(expr)
    if not CRON_FIELDS_RE.match(cron_expr):
        raise ValueError(
            f"invalid cron expression: {expr!r} (expected 5 fields: minute hour dom month dow)"
        )
    if croniter is None:
        raise ValueError("croniter not installed (pip install croniter)")
    try:
        croniter(cron_expr)
    except Exception as exc:
        raise ValueError(f"invalid cron expression: {cron_expr!r}") from exc
    return cron_expr


def cron_next_run(expr: str, base: datetime | None = None) -> datetime:
    cron_expr = validate_cron(expr)
    now = base or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    nxt = croniter(cron_expr, now).get_next(datetime)
    if nxt.tzinfo is None:
        nxt = nxt.replace(tzinfo=timezone.utc)
    return nxt


LOOT_SUBDIR_NAMES = frozenset(
    {
        "domains",
        "ips",
        "screenshots",
        "nmap",
        "reports",
        "output",
        "osint",
        "credentials",
        "web",
        "vulnerabilities",
        "notes",
        "scans",
    }
)


class DatabaseError(RuntimeError):
    pass


def log(msg: str) -> None:
    try:
        from kitelon_log import log_message

        log_message("core", msg)
    except Exception:
        print(f"[kitelon] {msg}", file=sys.stderr)


def load_key_value_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip().strip("\r")
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\r")
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        values[key] = value
    return values


def load_secrets(path: Path = SECRETS_FILE) -> dict[str, str]:
    return load_key_value_file(path)


def db_config() -> dict[str, str]:
    merged: dict[str, str] = {}
    for path in (INSTALL_CONFIG, ROOT_CONFIG, SECRETS_FILE):
        merged.update(load_key_value_file(path))

    for key in ("DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD", "DB_ENABLED"):
        env_val = os.environ.get(key)
        if env_val is not None and env_val != "":
            merged[key] = env_val

    return {
        "host": merged.get("DB_HOST", "127.0.0.1"),
        "port": merged.get("DB_PORT", "5432"),
        "dbname": merged.get("DB_NAME", "kitelon"),
        "user": merged.get("DB_USER", "postgres"),
        "password": merged.get("DB_PASSWORD", ""),
    }


def db_connection_summary(cfg: dict[str, str] | None = None) -> str:
    cfg = cfg or db_config()
    return f"{cfg['user']}@{cfg['host']}:{cfg['port']}/{cfg['dbname']}"


def db_enabled() -> bool:
    flag = os.environ.get("DB_ENABLED", "1")
    return flag not in ("0", "false", "False", "")


def require_psycopg() -> None:
    if psycopg is None:
        raise DatabaseError("psycopg is not installed (pip install 'psycopg[binary]')")


@contextmanager
def get_connection() -> Iterator[Any]:
    require_psycopg()
    cfg = db_config()
    if not cfg["password"]:
        raise DatabaseError(
            "DB password not set.\n"
            f"  Create {SECRETS_FILE} with:\n"
            "    DB_PASSWORD=your_postgres_password\n"
            "  Optional overrides in the same file: DB_USER, DB_HOST, DB_NAME\n"
            f"  Non-secret defaults live in {ROOT_CONFIG} (DB_USER is currently "
            f"{cfg['user']})."
        )
    try:
        conn = psycopg.connect(
            host=cfg["host"],
            port=int(cfg["port"]),
            dbname=cfg["dbname"],
            user=cfg["user"],
            password=cfg["password"],
            row_factory=dict_row,
        )
    except psycopg.OperationalError as exc:
        msg = str(exc).lower()
        hint = (
            f"Check DB_PASSWORD in {SECRETS_FILE} and DB_USER in {ROOT_CONFIG} "
            f"(currently {cfg['user']})."
        )
        if "password authentication failed" in msg:
            hint = (
                f"Wrong password for PostgreSQL user '{cfg['user']}'.\n"
                f"  Update {SECRETS_FILE} with the correct DB_PASSWORD,\n"
                f"  or set DB_USER=postgres (or your local superuser) in "
                f"{ROOT_CONFIG} or {SECRETS_FILE}."
            )
        elif "does not exist" in msg and "database" in msg:
            hint = (
                f"Create the database first:\n"
                f"  psql -U {cfg['user']} -h {cfg['host']} -c "
                f"\"CREATE DATABASE {cfg['dbname']};\""
            )
        raise DatabaseError(
            f"PostgreSQL connection failed ({db_connection_summary(cfg)}).\n"
            f"  {hint}\n"
            f"  Run: kitelon db test"
        ) from exc
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def test_connection(verbose: bool = True) -> None:
    cfg = db_config()
    if verbose:
        print(f"Config file: {SECRETS_FILE} ({'found' if SECRETS_FILE.is_file() else 'missing'})")
        print(f"Target: {db_connection_summary(cfg)}")
        print(f"Password: {'set' if cfg['password'] else 'NOT SET'}")
    if not cfg["password"]:
        raise DatabaseError(f"DB_PASSWORD not set in {SECRETS_FILE}")
    with get_connection() as conn:
        row = conn.execute("SELECT current_user, current_database()").fetchone()
    if verbose:
        print(f"Connected as {row['current_user']} to database {row['current_database']}")


def migrate() -> None:
    require_psycopg()
    if not MIGRATIONS_DIR.is_dir():
        raise DatabaseError(f"migrations directory not found: {MIGRATIONS_DIR}")
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        for sql_file in sorted(MIGRATIONS_DIR.glob("*.sql")):
            version = sql_file.name
            exists = conn.execute(
                "SELECT 1 FROM schema_migrations WHERE version = %s", (version,)
            ).fetchone()
            if exists:
                continue
            log(f"applying migration {version}")
            conn.execute(sql_file.read_text(encoding="utf-8"))
            conn.execute(
                "INSERT INTO schema_migrations(version) VALUES(%s)", (version,)
            )
    log("migrations complete")


def normalize_severity(raw: str) -> str:
    upper = raw.upper()
    for level in SEVERITY_ORDER:
        if level in upper:
            return level
    return "UNKNOWN"


def normalize_workspace_alias(alias: str) -> str:
    alias = re.sub(r"[\s/]+", "-", alias.strip())
    alias = re.sub(r"-+", "-", alias).strip("-")
    if not alias or ".." in alias or alias.startswith("."):
        raise ValueError("invalid workspace alias")
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$", alias):
        raise ValueError(
            "alias must start with a letter or digit and use only letters, "
            "digits, dots, underscores, or hyphens"
        )
    return alias


def confined_workspace_loot_path(loot_root: Path, alias: str) -> Path:
    """Build loot/workspace/<alias> and refuse paths that leave loot_root."""
    alias = normalize_workspace_alias(alias)
    workspace_root = (Path(loot_root) / "workspace").resolve()
    loot_path = (workspace_root / alias).resolve()
    try:
        loot_path.relative_to(workspace_root)
    except ValueError as exc:
        raise ValueError("invalid workspace path") from exc
    if loot_path == workspace_root:
        raise ValueError("invalid workspace path")
    return loot_path


def assert_confined_loot_path(loot_path: str | Path, alias: str) -> Path:
    """Accept a caller path only when it is already .../workspace/<alias>."""
    alias = normalize_workspace_alias(alias)
    path = Path(loot_path).expanduser().resolve()
    if path.name != alias or path.parent.name != "workspace":
        raise ValueError("invalid workspace path")
    inferred_root = path.parent.parent
    canonical = confined_workspace_loot_path(inferred_root, alias)
    if canonical != path:
        raise ValueError("invalid workspace path")
    return path


def resolve_workspace_loot_path(
    alias: str,
    *,
    loot_root: Path | None = None,
    loot_path: str | Path | None = None,
) -> Path:
    """Always derive the on-disk path from a normalized alias."""
    if loot_root is not None:
        return confined_workspace_loot_path(loot_root, alias)
    if loot_path is not None:
        return assert_confined_loot_path(loot_path, alias)
    return confined_workspace_loot_path(INSTALL_DIR / "loot", alias)


def init_workspace_loot_dir(loot_path: Path) -> None:
    """Create v2 workspace loot layout (matches kitelon_init_workspace_dirs in bash)."""
    loot_path.mkdir(parents=True, exist_ok=True)
    os.chmod(loot_path, 0o700)
    subdirs = (
        "artifacts/nmap",
        "artifacts/web",
        "artifacts/ssl",
        "artifacts/recon",
        "artifacts/ports",
        "artifacts/tools",
        "artifacts/screenshots",
        "reports",
        "vulnerabilities",
    )
    for sub in subdirs:
        (loot_path / sub).mkdir(parents=True, exist_ok=True)
        os.chmod(loot_path / sub, 0o700)
    for rel in ("findings.jsonl", "manifest.json", "scan.log"):
        path = loot_path / rel
        path.touch(exist_ok=True)
        os.chmod(path, 0o600)


def create_workspace(loot_root: Path, alias: str) -> tuple[int, bool]:
    """Create loot directory and DB row. Returns (workspace_id, created)."""
    alias = normalize_workspace_alias(alias)
    loot_path = confined_workspace_loot_path(loot_root, alias)

    is_new = not loot_path.is_dir()
    init_workspace_loot_dir(loot_path)

    with get_connection() as conn:
        existing = get_workspace_by_alias(conn, alias)
        ws_id = ensure_workspace(conn, alias, loot_path, loot_root=loot_root)
        created = is_new and existing is None
    return ws_id, created


def ensure_workspace(
    conn: Any,
    alias: str,
    loot_path: str | Path | None = None,
    *,
    loot_root: Path | None = None,
) -> int:
    alias = normalize_workspace_alias(alias)
    path = resolve_workspace_loot_path(
        alias, loot_root=loot_root, loot_path=loot_path
    )
    init_workspace_loot_dir(path)
    stored = str(path)
    row = conn.execute(
        "SELECT id FROM workspaces WHERE alias = %s", (alias,)
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE workspaces SET loot_path = %s WHERE id = %s",
            (stored, row["id"]),
        )
        return int(row["id"])
    row = conn.execute(
        """
        INSERT INTO workspaces(alias, loot_path) VALUES(%s, %s)
        RETURNING id
        """,
        (alias, stored),
    ).fetchone()
    return int(row["id"])


def get_workspace_by_alias(conn: Any, alias: str) -> dict[str, Any] | None:
    try:
        alias = normalize_workspace_alias(alias)
    except ValueError:
        return None
    return conn.execute(
        "SELECT * FROM workspaces WHERE alias = %s", (alias,)
    ).fetchone()


def list_workspaces(conn: Any) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM workspaces ORDER BY alias ASC"
    ).fetchall()
    result = []
    for ws in rows:
        stats = workspace_stats(conn, int(ws["id"]))
        ws = dict(ws)
        ws["stats"] = stats
        result.append(ws)
    return result


def update_workspace(
    conn: Any,
    alias: str,
    *,
    new_alias: str | None = None,
    loot_root: Path | None = None,
) -> dict[str, Any]:
    ws = get_workspace_by_alias(conn, alias)
    if not ws:
        raise ValueError(f"workspace not found: {alias}")

    if new_alias is not None:
        new_alias = normalize_workspace_alias(new_alias)
        if new_alias != alias:
            if get_workspace_by_alias(conn, new_alias):
                raise ValueError(f"workspace already exists: {new_alias}")
            old_path = Path(ws["loot_path"]).resolve()
            root = loot_root or old_path.parent.parent
            new_path = confined_workspace_loot_path(root, new_alias)
            if old_path.is_dir() and old_path != new_path:
                if new_path.exists():
                    raise ValueError(f"loot directory already exists: {new_path}")
                new_path.parent.mkdir(parents=True, exist_ok=True)
                old_path.rename(new_path)
            conn.execute(
                "UPDATE workspaces SET alias = %s, loot_path = %s WHERE id = %s",
                (new_alias, str(new_path), ws["id"]),
            )
            alias = new_alias

    row = get_workspace_by_alias(conn, alias)
    if not row:
        raise ValueError(f"workspace not found after update: {alias}")
    return dict(row)


def delete_workspace(
    conn: Any,
    alias: str,
    *,
    delete_loot: bool = False,
) -> dict[str, Any]:
    ws = get_workspace_by_alias(conn, alias)
    if not ws:
        raise ValueError(f"workspace not found: {alias}")
    ws_id = int(ws["id"])

    running = conn.execute(
        """
        SELECT id FROM jobs
        WHERE workspace_id = %s AND status = 'running'
        """,
        (ws_id,),
    ).fetchall()
    if running:
        raise ValueError(
            f"workspace has {len(running)} running job(s); cancel them first"
        )

    conn.execute("DELETE FROM jobs WHERE workspace_id = %s", (ws_id,))
    conn.execute("DELETE FROM workspaces WHERE id = %s", (ws_id,))

    if delete_loot:
        try:
            loot_path = assert_confined_loot_path(ws["loot_path"], alias)
        except ValueError:
            log(
                f"refusing to delete loot for {alias}: "
                "path is outside loot/workspace"
            )
        else:
            if loot_path.is_dir():
                shutil.rmtree(loot_path)

    return dict(ws)


def clear_workspace_data(conn: Any, workspace_id: int) -> None:
    for table in (
        "services",
        "web_endpoints",
        "discovered_urls",
        "technologies",
        "scan_runs",
        "hosts",
        "domains",
        "vulnerabilities",
        "notifications",
        "workspace_stats",
        "loot_artifacts",
    ):
        conn.execute(
            f"DELETE FROM {table} WHERE workspace_id = %s", (workspace_id,)
        )


def upsert_host(
    conn: Any,
    workspace_id: int,
    hostname: str,
    ip: str | None = None,
    mac: str | None = None,
    os_guess: str | None = None,
    is_live: int = 0,
    risk_score: float = 0,
    open_ports: str | None = None,
    web_title: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO hosts(
            workspace_id, hostname, ip, mac, os_guess, is_live,
            risk_score, open_ports, web_title
        ) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (workspace_id, hostname) DO UPDATE SET
            ip = COALESCE(EXCLUDED.ip, hosts.ip),
            mac = COALESCE(EXCLUDED.mac, hosts.mac),
            os_guess = COALESCE(EXCLUDED.os_guess, hosts.os_guess),
            is_live = GREATEST(hosts.is_live, EXCLUDED.is_live),
            risk_score = CASE
                WHEN EXCLUDED.risk_score > 0 THEN EXCLUDED.risk_score
                ELSE hosts.risk_score
            END,
            open_ports = COALESCE(EXCLUDED.open_ports, hosts.open_ports),
            web_title = COALESCE(EXCLUDED.web_title, hosts.web_title)
        """,
        (
            workspace_id,
            hostname,
            ip,
            mac,
            os_guess,
            is_live,
            risk_score,
            open_ports,
            web_title,
        ),
    )


def insert_domain(conn: Any, workspace_id: int, fqdn: str, is_target: int) -> None:
    conn.execute(
        """
        INSERT INTO domains(workspace_id, fqdn, is_target)
        VALUES(%s, %s, %s)
        ON CONFLICT (workspace_id, fqdn) DO UPDATE SET
            is_target = GREATEST(domains.is_target, EXCLUDED.is_target)
        """,
        (workspace_id, fqdn, is_target),
    )


def insert_vulnerability(
    conn: Any,
    workspace_id: int,
    hostname: str,
    severity: str,
    name: str,
    url: str | None,
    evidence: str | None,
    source_file: str | None,
    *,
    source: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    artifact_path: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO vulnerabilities(
            workspace_id, hostname, severity, name, url, evidence, source_file,
            source, cve, cwe, artifact_path
        ) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            workspace_id,
            hostname,
            severity,
            name,
            url,
            evidence,
            source_file,
            source,
            cve,
            cwe,
            artifact_path,
        ),
    )


def insert_notification(conn: Any, workspace_id: int, message: str) -> None:
    conn.execute(
        """
        INSERT INTO notifications(workspace_id, message)
        VALUES(%s, %s)
        """,
        (workspace_id, message),
    )


def set_stat(conn: Any, workspace_id: int, key: str, value: int) -> None:
    conn.execute(
        """
        INSERT INTO workspace_stats(workspace_id, key, value)
        VALUES(%s, %s, %s)
        ON CONFLICT (workspace_id, key) DO UPDATE SET value = EXCLUDED.value
        """,
        (workspace_id, key, int(value)),
    )


def workspace_stats(conn: Any, workspace_id: int) -> dict[str, int]:
    rows = conn.execute(
        "SELECT key, value FROM workspace_stats WHERE workspace_id = %s",
        (workspace_id,),
    ).fetchall()
    return {row["key"]: int(row["value"]) for row in rows}


def stat_value(conn: Any, workspace_id: int, key: str) -> int:
    row = conn.execute(
        """
        SELECT value FROM workspace_stats
        WHERE workspace_id = %s AND key = %s
        """,
        (workspace_id, key),
    ).fetchone()
    return int(row["value"]) if row else 0


def mark_imported(conn: Any, workspace_id: int) -> None:
    conn.execute(
        """
        UPDATE workspaces SET last_imported_at = NOW() WHERE id = %s
        """,
        (workspace_id,),
    )


def host_vuln_counts(conn: Any, workspace_id: int, hostname: str) -> dict[str, int]:
    counts = {k.lower(): 0 for k in SEVERITY_ORDER if k != "UNKNOWN"}
    rows = conn.execute(
        """
        SELECT severity, COUNT(*) AS c FROM vulnerabilities
        WHERE workspace_id = %s AND hostname = %s
        GROUP BY severity
        """,
        (workspace_id, hostname),
    ).fetchall()
    for row in rows:
        counts[normalize_severity(row["severity"]).lower()] = int(row["c"])
    return counts


def vuln_counts_to_risk_score(counts: dict[str, int]) -> int:
    total = 0
    for level, weight in RISK_WEIGHTS.items():
        total += int(counts.get(level.lower(), 0)) * weight
    return total


def update_host_risk_scores(conn: Any, workspace_id: int) -> None:
    """Set hosts.risk_score from imported vulnerability severities."""
    rows = conn.execute(
        "SELECT hostname FROM hosts WHERE workspace_id = %s",
        (workspace_id,),
    ).fetchall()
    for row in rows:
        hostname = row["hostname"]
        counts = host_vuln_counts(conn, workspace_id, hostname)
        score = vuln_counts_to_risk_score(counts)
        conn.execute(
            """
            UPDATE hosts SET risk_score = %s
            WHERE workspace_id = %s AND hostname = %s
            """,
            (float(score), workspace_id, hostname),
        )


def list_hosts(
    conn: Any, workspace_id: int, limit: int = 500, offset: int = 0
) -> list[dict[str, Any]]:
    return conn.execute(
        """
        SELECT * FROM hosts WHERE workspace_id = %s
        ORDER BY risk_score DESC, hostname ASC
        LIMIT %s OFFSET %s
        """,
        (workspace_id, limit, offset),
    ).fetchall()


def get_host(conn: Any, workspace_id: int, hostname: str) -> dict[str, Any] | None:
    return conn.execute(
        """
        SELECT * FROM hosts WHERE workspace_id = %s AND hostname = %s
        """,
        (workspace_id, hostname),
    ).fetchone()


def rename_host(
    conn: Any, workspace_id: int, old_hostname: str, new_hostname: str
) -> dict[str, Any]:
    old_hostname = old_hostname.strip()
    new_hostname = new_hostname.strip()
    if not new_hostname:
        raise ValueError("hostname required")
    if new_hostname == old_hostname:
        row = get_host(conn, workspace_id, old_hostname)
        if not row:
            raise ValueError(f"host not found: {old_hostname}")
        return dict(row)
    if get_host(conn, workspace_id, new_hostname):
        raise ValueError(f"host already exists: {new_hostname}")
    if not get_host(conn, workspace_id, old_hostname):
        raise ValueError(f"host not found: {old_hostname}")

    conn.execute(
        "UPDATE hosts SET hostname = %s WHERE workspace_id = %s AND hostname = %s",
        (new_hostname, workspace_id, old_hostname),
    )
    conn.execute(
        """
        UPDATE vulnerabilities SET hostname = %s
        WHERE workspace_id = %s AND hostname = %s
        """,
        (new_hostname, workspace_id, old_hostname),
    )
    conn.execute(
        """
        UPDATE domains SET fqdn = %s
        WHERE workspace_id = %s AND fqdn = %s
        """,
        (new_hostname, workspace_id, old_hostname),
    )
    row = get_host(conn, workspace_id, new_hostname)
    if not row:
        raise ValueError("host rename failed")
    return dict(row)


def list_vulns_for_hosts(
    conn: Any,
    workspace_id: int,
    hostnames: list[str],
    limit: int = 5000,
) -> list[dict[str, Any]]:
    if not hostnames:
        return []
    placeholders = ", ".join(["%s"] * len(hostnames))
    return conn.execute(
        f"""
        SELECT * FROM vulnerabilities
        WHERE workspace_id = %s AND hostname IN ({placeholders})
        ORDER BY severity, hostname, name
        LIMIT %s
        """,
        [workspace_id, *hostnames, limit],
    ).fetchall()


def list_hosts_by_names(
    conn: Any, workspace_id: int, hostnames: list[str]
) -> list[dict[str, Any]]:
    if not hostnames:
        return []
    placeholders = ", ".join(["%s"] * len(hostnames))
    return conn.execute(
        f"""
        SELECT * FROM hosts
        WHERE workspace_id = %s AND hostname IN ({placeholders})
        ORDER BY risk_score DESC, hostname ASC
        """,
        [workspace_id, *hostnames],
    ).fetchall()


def list_vulns(
    conn: Any,
    workspace_id: int,
    severity: str | None = None,
    hostname: str | None = None,
    q: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> list[dict[str, Any]]:
    query = "SELECT * FROM vulnerabilities WHERE workspace_id = %s"
    params: list[Any] = [workspace_id]
    if severity:
        query += " AND severity = %s"
        params.append(normalize_severity(severity))
    if hostname:
        query += " AND hostname = %s"
        params.append(hostname)
    if q:
        like = f"%{q.strip()}%"
        query += (
            " AND (name ILIKE %s OR hostname ILIKE %s OR COALESCE(url, '') ILIKE %s"
            " OR COALESCE(evidence, '') ILIKE %s)"
        )
        params.extend([like, like, like, like])
    query += " ORDER BY severity, hostname, name LIMIT %s OFFSET %s"
    params.extend([limit, offset])
    return conn.execute(query, params).fetchall()


    return conn.execute(query, params).fetchall()


def insert_service(
    conn: Any,
    workspace_id: int,
    hostname: str,
    port: int,
    protocol: str = "tcp",
    product: str | None = None,
    version: str | None = None,
    cpe: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO services(
            workspace_id, hostname, port, protocol, product, version, cpe
        ) VALUES(%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (workspace_id, hostname, port, protocol) DO UPDATE SET
            product = COALESCE(EXCLUDED.product, services.product),
            version = COALESCE(EXCLUDED.version, services.version),
            cpe = COALESCE(EXCLUDED.cpe, services.cpe)
        """,
        (workspace_id, hostname, port, protocol, product, version, cpe),
    )


def insert_web_endpoint(
    conn: Any,
    workspace_id: int,
    hostname: str,
    url: str,
    *,
    port: int | None = None,
    status_code: int | None = None,
    title: str | None = None,
    screenshot_path: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO web_endpoints(
            workspace_id, hostname, port, url, status_code, title, screenshot_path
        ) VALUES(%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (workspace_id, url) DO UPDATE SET
            status_code = COALESCE(EXCLUDED.status_code, web_endpoints.status_code),
            title = COALESCE(EXCLUDED.title, web_endpoints.title),
            screenshot_path = COALESCE(EXCLUDED.screenshot_path, web_endpoints.screenshot_path)
        """,
        (workspace_id, hostname, port, url, status_code, title, screenshot_path),
    )


def insert_discovered_url(
    conn: Any,
    workspace_id: int,
    hostname: str,
    url: str,
    source: str,
    status_code: int | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO discovered_urls(
            workspace_id, hostname, url, source, status_code
        ) VALUES(%s, %s, %s, %s, %s)
        ON CONFLICT (workspace_id, url, source) DO UPDATE SET
            status_code = COALESCE(EXCLUDED.status_code, discovered_urls.status_code)
        """,
        (workspace_id, hostname, url, source, status_code),
    )


def insert_technology(
    conn: Any,
    workspace_id: int,
    hostname: str,
    name: str,
    *,
    port: int | None = None,
    version: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO technologies(
            workspace_id, hostname, port, name, version
        ) VALUES(%s, %s, %s, %s, %s)
        ON CONFLICT (workspace_id, hostname, port, name) DO UPDATE SET
            version = COALESCE(EXCLUDED.version, technologies.version)
        """,
        (workspace_id, hostname, port, name, version),
    )


def insert_scan_run(
    conn: Any,
    workspace_id: int,
    *,
    scan_id: str | None = None,
    mode: str | None = None,
    target: str | None = None,
    options_json: dict | None = None,
    steps_json: list | None = None,
    started_at: str | None = None,
    finished_at: str | None = None,
) -> None:
    import json

    conn.execute(
        """
        INSERT INTO scan_runs(
            workspace_id, scan_id, mode, target, options_json, steps_json, started_at, finished_at
        ) VALUES(%s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s)
        """,
        (
            workspace_id,
            scan_id,
            mode,
            target,
            json.dumps(options_json or {}),
            json.dumps(steps_json or []),
            started_at,
            finished_at,
        ),
    )


def list_services(
    conn: Any, workspace_id: int, hostname: str | None = None, limit: int = 500
) -> list[dict[str, Any]]:
    query = "SELECT * FROM services WHERE workspace_id = %s"
    params: list[Any] = [workspace_id]
    if hostname:
        query += " AND hostname = %s"
        params.append(hostname)
    query += " ORDER BY hostname, port LIMIT %s"
    params.append(limit)
    return conn.execute(query, params).fetchall()


def list_technologies(
    conn: Any, workspace_id: int, hostname: str | None = None, limit: int = 500
) -> list[dict[str, Any]]:
    query = "SELECT * FROM technologies WHERE workspace_id = %s"
    params: list[Any] = [workspace_id]
    if hostname:
        query += " AND hostname = %s"
        params.append(hostname)
    query += " ORDER BY hostname, name LIMIT %s"
    params.append(limit)
    return conn.execute(query, params).fetchall()


def list_discovered_urls(
    conn: Any,
    workspace_id: int,
    hostname: str | None = None,
    source: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    query = "SELECT * FROM discovered_urls WHERE workspace_id = %s"
    params: list[Any] = [workspace_id]
    if hostname:
        query += " AND hostname = %s"
        params.append(hostname)
    if source:
        query += " AND source = %s"
        params.append(source)
    query += " ORDER BY hostname, url LIMIT %s"
    params.append(limit)
    return conn.execute(query, params).fetchall()


def list_scan_runs(conn: Any, workspace_id: int, limit: int = 50) -> list[dict[str, Any]]:
    return conn.execute(
        """
        SELECT * FROM scan_runs
        WHERE workspace_id = %s
        ORDER BY id DESC
        LIMIT %s
        """,
        (workspace_id, limit),
    ).fetchall()


def list_domains(conn: Any, workspace_id: int, limit: int = 500) -> list[dict[str, Any]]:
    return conn.execute(
        """
        SELECT fqdn, is_target FROM domains
        WHERE workspace_id = %s
        ORDER BY is_target DESC, fqdn ASC LIMIT %s
        """,
        (workspace_id, limit),
    ).fetchall()


def list_notifications(conn: Any, workspace_id: int, limit: int = 100) -> list[dict[str, Any]]:
    return conn.execute(
        """
        SELECT message, created_at FROM notifications
        WHERE workspace_id = %s ORDER BY id DESC LIMIT %s
        """,
        (workspace_id, limit),
    ).fetchall()


# --- Jobs ---

SCAN_JOB_TYPES = ("scan",)
POST_JOB_TYPES = ("reimport", "loot_process", "report")
ALL_JOB_TYPES = SCAN_JOB_TYPES + POST_JOB_TYPES


def get_running_scan_workspace_ids(conn: Any) -> set[int]:
    rows = conn.execute(
        """
        SELECT DISTINCT workspace_id FROM jobs
        WHERE job_type = 'scan' AND status = 'running' AND workspace_id IS NOT NULL
        """
    ).fetchall()
    return {int(row["workspace_id"]) for row in rows}


def enqueue_job(
    conn: Any,
    job_type: str,
    workspace_id: int | None = None,
    target: str | None = None,
    mode: str | None = None,
    args: dict[str, Any] | None = None,
    priority: int = 100,
    scheduled_at: datetime | None = None,
    created_by: str = "cli",
) -> int:
    if job_type == "scan":
        if not workspace_id:
            raise ValueError("workspace required for scan jobs")
        if not target:
            raise ValueError("target required for scan jobs")
    elif job_type in POST_JOB_TYPES and not workspace_id:
        raise ValueError(f"workspace required for {job_type} jobs")
    row = conn.execute(
        """
        INSERT INTO jobs(
            workspace_id, job_type, target, mode, args_json, priority,
            scheduled_at, created_by
        ) VALUES(%s, %s, %s, %s, %s::jsonb, %s, %s, %s)
        RETURNING id
        """,
        (
            workspace_id,
            job_type,
            target,
            mode,
            json.dumps(args or {}),
            priority,
            scheduled_at or datetime.now(timezone.utc),
            created_by,
        ),
    ).fetchone()
    return int(row["id"])


def claim_next_job(
    conn: Any,
    role: str = "any",
    *,
    skip_scan_types: bool = False,
    exclude_workspace_ids: set[int] | None = None,
) -> dict[str, Any] | None:
    type_filter = ""
    if role == "scan":
        type_filter = " AND j.job_type = 'scan'"
    elif role == "post":
        type_filter = " AND j.job_type IN ('reimport', 'loot_process', 'report')"
    elif skip_scan_types:
        type_filter = " AND j.job_type NOT IN ('scan', 'loot_process')"

    exclude_filter = ""
    params: list[Any] = []
    if exclude_workspace_ids:
        exclude_filter = " AND (j.workspace_id IS NULL OR j.workspace_id != ALL(%s::int[]))"
        params.append(list(exclude_workspace_ids))

    query = f"""
        SELECT j.*, w.alias AS workspace_alias
        FROM jobs j
        LEFT JOIN workspaces w ON w.id = j.workspace_id
        WHERE j.status = 'pending'
          AND j.scheduled_at <= NOW()
          {type_filter}
          {exclude_filter}
        ORDER BY j.priority ASC, j.scheduled_at ASC, j.id ASC
        FOR UPDATE OF j SKIP LOCKED
        LIMIT 1
        """
    if params:
        row = conn.execute(query, params).fetchone()
    else:
        row = conn.execute(query).fetchone()
    if not row:
        return None
    if role == "scan" and row.get("workspace_id"):
        conn.execute(
            "SELECT pg_advisory_xact_lock(%s)",
            (1_000_000 + int(row["workspace_id"]),),
        )
        busy = conn.execute(
            """
            SELECT 1 FROM jobs
            WHERE workspace_id = %s AND job_type = 'scan'
              AND status = 'running' AND id != %s
            LIMIT 1
            """,
            (row["workspace_id"], row["id"]),
        ).fetchone()
        if busy:
            return None
    conn.execute(
        """
        UPDATE jobs SET status = 'running', started_at = NOW(), pid = NULL
        WHERE id = %s
        """,
        (row["id"],),
    )
    return dict(row)


def complete_job(conn: Any, job_id: int, exit_code: int = 0, error: str | None = None) -> None:
    status = "completed" if exit_code == 0 else "failed"
    conn.execute(
        """
        UPDATE jobs SET status = %s, finished_at = NOW(), exit_code = %s,
            error_message = %s, pid = NULL
        WHERE id = %s
        """,
        (status, exit_code, error, job_id),
    )


def set_job_pid(conn: Any, job_id: int, pid: int) -> None:
    conn.execute("UPDATE jobs SET pid = %s WHERE id = %s", (pid, job_id))


def list_jobs(
    conn: Any,
    status: str | None = None,
    workspace_id: int | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    query = """
        SELECT j.*, w.alias AS workspace_alias
        FROM jobs j
        LEFT JOIN workspaces w ON w.id = j.workspace_id
        WHERE 1=1
    """
    params: list[Any] = []
    if status:
        query += " AND j.status = %s"
        params.append(status)
    if workspace_id:
        query += " AND j.workspace_id = %s"
        params.append(workspace_id)
    query += " ORDER BY j.id DESC LIMIT %s"
    params.append(limit)
    return conn.execute(query, params).fetchall()


def get_job(conn: Any, job_id: int) -> dict[str, Any] | None:
    return conn.execute(
        """
        SELECT j.*, w.alias AS workspace_alias
        FROM jobs j
        LEFT JOIN workspaces w ON w.id = j.workspace_id
        WHERE j.id = %s
        """,
        (job_id,),
    ).fetchone()


def retry_job(conn: Any, job_id: int, created_by: str = "retry") -> int:
    job = get_job(conn, job_id)
    if not job:
        raise ValueError(f"job not found: {job_id}")
    if job["status"] in ("pending", "running"):
        raise ValueError(f"cannot retry job {job_id} while status is {job['status']}")

    args = job.get("args_json") or {}
    if isinstance(args, str):
        args = json.loads(args)

    workspace_id = job.get("workspace_id")
    if job["job_type"] in ("reimport", "loot_process", "report") and not workspace_id:
        raise ValueError(f"job {job_id} has no workspace")

    return enqueue_job(
        conn,
        job_type=job["job_type"],
        workspace_id=int(workspace_id) if workspace_id else None,
        target=job.get("target"),
        mode=job.get("mode"),
        args=args if isinstance(args, dict) else {},
        priority=int(job.get("priority") or 100),
        created_by=f"{created_by}:from-{job_id}",
    )


def update_job(conn: Any, job_id: int, **fields: Any) -> dict[str, Any]:
    job = get_job(conn, job_id)
    if not job:
        raise ValueError(f"job not found: {job_id}")
    if job["status"] != "pending":
        raise ValueError(
            f"can only update pending jobs (job {job_id} is {job['status']})"
        )

    sets: list[str] = []
    params: list[Any] = []

    if "priority" in fields and fields["priority"] is not None:
        sets.append("priority = %s")
        params.append(int(fields["priority"]))
    if "scheduled_at" in fields and fields["scheduled_at"] is not None:
        raw = fields["scheduled_at"]
        if isinstance(raw, str):
            raw = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        sets.append("scheduled_at = %s")
        params.append(raw)
    if "target" in fields:
        sets.append("target = %s")
        params.append(fields["target"])
    if "mode" in fields:
        sets.append("mode = %s")
        params.append(fields["mode"])
    if "job_type" in fields and fields["job_type"] is not None:
        job_type = str(fields["job_type"])
        if job_type not in ALL_JOB_TYPES:
            raise ValueError(f"invalid job_type: {job_type}")
        sets.append("job_type = %s")
        params.append(job_type)
    if "args" in fields and fields["args"] is not None:
        sets.append("args_json = %s::jsonb")
        params.append(json.dumps(fields["args"]))
    if "workspace" in fields:
        alias = fields["workspace"]
        if alias is None:
            if job.get("job_type") in ALL_JOB_TYPES:
                raise ValueError("workspace cannot be cleared on scan or post jobs")
            sets.append("workspace_id = NULL")
        else:
            ws = get_workspace_by_alias(conn, normalize_workspace_alias(str(alias)))
            if not ws:
                raise ValueError(f"workspace not found: {alias}")
            sets.append("workspace_id = %s")
            params.append(int(ws["id"]))

    if not sets:
        raise ValueError("no fields to update")

    params.append(job_id)
    conn.execute(f"UPDATE jobs SET {', '.join(sets)} WHERE id = %s", params)
    row = get_job(conn, job_id)
    if not row:
        raise ValueError(f"job not found after update: {job_id}")
    return dict(row)


def delete_job(conn: Any, job_id: int, *, kill: bool = False) -> dict[str, Any]:
    job = get_job(conn, job_id)
    if not job:
        raise ValueError(f"job not found: {job_id}")

    if job["status"] == "running":
        if not kill:
            raise ValueError(
                f"job {job_id} is running; use kill=true to cancel"
            )
        pid = job.get("pid")
        if pid:
            try:
                os.kill(int(pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError, TypeError):
                pass
        conn.execute(
            """
            UPDATE jobs SET status = 'cancelled', finished_at = NOW(), pid = NULL,
                error_message = 'cancelled by user'
            WHERE id = %s
            """,
            (job_id,),
        )
        row = get_job(conn, job_id)
        return dict(row) if row else dict(job)

    conn.execute("DELETE FROM jobs WHERE id = %s", (job_id,))
    return dict(job)


def recover_stuck_jobs(conn: Any, max_age_minutes: int = 180) -> int:
    result = conn.execute(
        """
        SELECT id, pid FROM jobs
        WHERE status = 'running'
          AND started_at < NOW() - (%s || ' minutes')::interval
        """,
        (str(max_age_minutes),),
    ).fetchall()
    recovered = 0
    for row in result:
        pid = row.get("pid")
        if pid:
            try:
                os.kill(int(pid), 0)
            except ProcessLookupError:
                pid = None
            except (PermissionError, TypeError, ValueError):
                pid = None
            else:
                try:
                    os.killpg(int(pid), signal.SIGTERM)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        os.kill(int(pid), signal.SIGTERM)
                    except (ProcessLookupError, PermissionError, OSError):
                        pass
                continue
        conn.execute(
            """
            UPDATE jobs SET status = 'failed', finished_at = NOW(),
                error_message = 'recovered: exceeded max runtime', pid = NULL
            WHERE id = %s AND status = 'running'
            """,
            (row["id"],),
        )
        recovered += 1
    return recovered


def promote_schedules(conn: Any) -> int:
    due = conn.execute(
        """
        SELECT s.*, w.alias FROM job_schedules s
        JOIN workspaces w ON w.id = s.workspace_id
        WHERE s.enabled = TRUE AND s.next_run_at <= NOW()
        FOR UPDATE OF s SKIP LOCKED
        """
    ).fetchall()
    count = 0
    for sched in due:
        enqueue_job(
            conn,
            job_type="scan",
            workspace_id=int(sched["workspace_id"]),
            target=sched["target"],
            mode=sched["mode"],
            args=dict(sched["args_json"] or {}),
            created_by=f"schedule:{sched['cron']}",
        )
        next_at = cron_next_run(sched["cron"])
        conn.execute(
            "UPDATE job_schedules SET next_run_at = %s WHERE id = %s",
            (next_at, sched["id"]),
        )
        count += 1
    return count


def create_schedule(
    conn: Any,
    workspace_id: int,
    cron: str,
    target: str,
    mode: str = "normal",
    args: dict[str, Any] | None = None,
) -> int:
    cron_expr = validate_cron(cron)
    next_run = cron_next_run(cron_expr)
    row = conn.execute(
        """
        INSERT INTO job_schedules(
            workspace_id, cron, target, mode, args_json, next_run_at
        ) VALUES(%s, %s, %s, %s, %s::jsonb, %s)
        RETURNING id
        """,
        (workspace_id, cron_expr, target, mode, json.dumps(args or {}), next_run),
    ).fetchone()
    return int(row["id"])


def list_schedules(conn: Any, workspace_id: int | None = None) -> list[dict[str, Any]]:
    if workspace_id:
        return conn.execute(
            """
            SELECT s.*, w.alias AS workspace_alias FROM job_schedules s
            JOIN workspaces w ON w.id = s.workspace_id
            WHERE s.workspace_id = %s ORDER BY s.id DESC
            """,
            (workspace_id,),
        ).fetchall()
    return conn.execute(
        """
        SELECT s.*, w.alias AS workspace_alias FROM job_schedules s
        JOIN workspaces w ON w.id = s.workspace_id
        ORDER BY s.id DESC
        """
    ).fetchall()


def get_schedule(conn: Any, schedule_id: int) -> dict[str, Any] | None:
    return conn.execute(
        """
        SELECT s.*, w.alias AS workspace_alias FROM job_schedules s
        JOIN workspaces w ON w.id = s.workspace_id
        WHERE s.id = %s
        """,
        (schedule_id,),
    ).fetchone()


def update_schedule(conn: Any, schedule_id: int, **fields: Any) -> dict[str, Any]:
    row = get_schedule(conn, schedule_id)
    if not row:
        raise ValueError(f"schedule not found: {schedule_id}")

    sets: list[str] = []
    params: list[Any] = []

    if "cron" in fields and fields["cron"] is not None:
        cron_expr = validate_cron(str(fields["cron"]))
        sets.append("cron = %s")
        params.append(cron_expr)
        sets.append("next_run_at = %s")
        params.append(cron_next_run(cron_expr))
    if "target" in fields:
        sets.append("target = %s")
        params.append(fields["target"])
    if "mode" in fields:
        sets.append("mode = %s")
        params.append(fields["mode"])
    if "enabled" in fields and fields["enabled"] is not None:
        sets.append("enabled = %s")
        params.append(bool(fields["enabled"]))
    if "args" in fields and fields["args"] is not None:
        sets.append("args_json = %s::jsonb")
        params.append(json.dumps(fields["args"]))
    if "next_run_at" in fields and fields["next_run_at"] is not None:
        raw = fields["next_run_at"]
        if isinstance(raw, str):
            raw = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        sets.append("next_run_at = %s")
        params.append(raw)
    if "workspace" in fields:
        alias = fields["workspace"]
        ws = get_workspace_by_alias(conn, normalize_workspace_alias(str(alias)))
        if not ws:
            raise ValueError(f"workspace not found: {alias}")
        sets.append("workspace_id = %s")
        params.append(int(ws["id"]))

    if not sets:
        raise ValueError("no fields to update")

    params.append(schedule_id)
    conn.execute(f"UPDATE job_schedules SET {', '.join(sets)} WHERE id = %s", params)
    updated = get_schedule(conn, schedule_id)
    if not updated:
        raise ValueError(f"schedule not found after update: {schedule_id}")
    return dict(updated)


def delete_schedule(conn: Any, schedule_id: int) -> dict[str, Any]:
    row = get_schedule(conn, schedule_id)
    if not row:
        raise ValueError(f"schedule not found: {schedule_id}")
    conn.execute("DELETE FROM job_schedules WHERE id = %s", (schedule_id,))
    return dict(row)


def touch_heartbeat(conn: Any, job_id: int | None = None, message: str | None = None) -> None:
    conn.execute(
        """
        UPDATE worker_heartbeat SET last_tick_at = NOW(), last_job_id = %s, message = %s
        WHERE id = 1
        """,
        (job_id, message),
    )


def get_heartbeat(conn: Any) -> dict[str, Any] | None:
    return conn.execute("SELECT * FROM worker_heartbeat WHERE id = 1").fetchone()


def migrate_sqlite_workspace(sqlite_path: Path, alias: str) -> None:
    """One-time import from legacy per-workspace kitelon.db."""
    if not sqlite_path.is_file():
        return
    loot_path = sqlite_path.parent
    sconn = sqlite3.connect(sqlite_path)
    sconn.row_factory = sqlite3.Row
    with get_connection() as conn:
        ws_id = ensure_workspace(conn, alias, loot_path)
        clear_workspace_data(conn, ws_id)
        for row in sconn.execute("SELECT * FROM hosts"):
            upsert_host(
                conn,
                ws_id,
                row["hostname"],
                row["ip"],
                row["mac"],
                row["os_guess"],
                row["is_live"],
                row["risk_score"],
                row["open_ports"],
                row["web_title"],
            )
        for row in sconn.execute("SELECT * FROM domains"):
            insert_domain(conn, ws_id, row["fqdn"], row["is_target"])
        for row in sconn.execute("SELECT * FROM vulnerabilities"):
            insert_vulnerability(
                conn,
                ws_id,
                row["hostname"],
                row["severity"],
                row["name"],
                row["url"],
                row["evidence"],
                row["source_file"],
            )
        for row in sconn.execute("SELECT * FROM notifications"):
            insert_notification(conn, ws_id, row["message"])
        for row in sconn.execute("SELECT key, value FROM workspace_stats"):
            set_stat(conn, ws_id, row["key"], row["value"])
        mark_imported(conn, ws_id)
    sconn.close()
    log(f"migrated SQLite workspace {alias} from {sqlite_path}")


def migrate_all_sqlite(loot_root: Path) -> int:
    count = 0
    workspace_root = loot_root / "workspace"
    if not workspace_root.is_dir():
        return 0
    for entry in sorted(workspace_root.iterdir()):
        if not entry.is_dir():
            continue
        db = entry / "kitelon.db"
        if db.is_file():
            migrate_sqlite_workspace(db, entry.name)
            count += 1
    return count


def is_workspace_loot_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    if path.name.startswith(".") or path.name in LOOT_SUBDIR_NAMES:
        return False
    try:
        normalize_workspace_alias(path.name)
    except ValueError:
        return False
    # v2 layout (Python scan engine)
    if (path / "artifacts").is_dir():
        return True
    if (path / "manifest.json").is_file():
        return True
    if (path / "findings.jsonl").is_file() or (path / "scan.log").is_file():
        return True
    # v1 legacy layout
    return (path / "scans").is_dir() and (path / "domains").is_dir()


def canonical_workspace_loot_path(loot_root: Path, alias: str) -> Path:
    return confined_workspace_loot_path(loot_root, alias)


def _workspace_has_data(conn: Any, workspace_id: int) -> bool:
    for table in (
        "hosts",
        "vulnerabilities",
        "loot_artifacts",
        "jobs",
        "domains",
        "scan_runs",
    ):
        row = conn.execute(
            f"SELECT 1 FROM {table} WHERE workspace_id = %s LIMIT 1",
            (workspace_id,),
        ).fetchone()
        if row:
            return True
    return False


def prune_invalid_workspaces(
    conn: Any, loot_root: Path | None = None, *, force: bool = False
) -> int:
    loot_root = (loot_root or INSTALL_DIR / "loot").resolve()
    removed = 0
    rows = conn.execute("SELECT id, alias, loot_path FROM workspaces").fetchall()
    for row in rows:
        alias = row["alias"]
        loot_path = Path(row["loot_path"]) if row.get("loot_path") else None
        drop = False
        try:
            normalize_workspace_alias(alias)
        except ValueError:
            drop = True
        if alias in LOOT_SUBDIR_NAMES:
            drop = True
        if not drop and loot_path and not is_workspace_loot_dir(loot_path):
            try:
                canonical = canonical_workspace_loot_path(loot_root, alias)
            except ValueError:
                drop = True
                canonical = None
            if canonical is not None and canonical != loot_path.resolve() and is_workspace_loot_dir(canonical):
                conn.execute(
                    "UPDATE workspaces SET loot_path = %s WHERE id = %s",
                    (str(canonical), row["id"]),
                )
                log(f"repaired loot_path for workspace {alias}")
                continue
            active = conn.execute(
                """
                SELECT 1 FROM jobs
                WHERE workspace_id = %s AND status IN ('pending', 'running')
                LIMIT 1
                """,
                (row["id"],),
            ).fetchone()
            if canonical is not None and active:
                init_workspace_loot_dir(canonical)
                conn.execute(
                    "UPDATE workspaces SET loot_path = %s WHERE id = %s",
                    (str(canonical), row["id"]),
                )
                log(f"restored loot dir for workspace {alias} (has active jobs)")
                continue
            drop = True
        if drop:
            if not force and _workspace_has_data(conn, int(row["id"])):
                log(
                    f"skip prune workspace {alias}: has stored data "
                    "(pass --force to delete)"
                )
                continue
            conn.execute("DELETE FROM workspaces WHERE id = %s", (row["id"],))
            removed += 1
    return removed


def discover_filesystem_workspaces(loot_root: Path) -> list[tuple[str, Path]]:
    workspace_root = loot_root / "workspace"
    if not workspace_root.is_dir():
        return []
    result: list[tuple[str, Path]] = []
    for p in sorted(workspace_root.iterdir()):
        if not is_workspace_loot_dir(p):
            continue
        try:
            alias = normalize_workspace_alias(p.name)
        except ValueError:
            continue
        result.append((alias, p.resolve()))
    return result


def sync_workspaces_from_disk(
    conn: Any, loot_root: Path, *, prune: bool = False
) -> None:
    loot_root = loot_root.resolve()
    fix_loot_workspace_layout(loot_root)
    for alias, path in discover_filesystem_workspaces(loot_root):
        ensure_workspace(conn, alias, path)
    if prune:
        prune_invalid_workspaces(conn, loot_root)


def fix_loot_workspace_layout(loot_root: Path) -> dict[str, Any]:
    """Ensure loot/workspace is canonical and loot/workspaces symlinks to it.

    Older installs could replace the symlink with a real directory (install.sh
    copied the tree after creating the link), producing nested workspace/workspaces
    paths and hiding scan data from the API.
    """
    loot_root = loot_root.resolve()
    workspace_dir = loot_root / "workspace"
    workspaces_link = loot_root / "workspaces"
    workspace_dir.mkdir(parents=True, exist_ok=True)

    moved: list[str] = []
    removed_meta: list[str] = []

    def remove_meta_path(path: Path) -> None:
        rel = str(path.relative_to(loot_root))
        if path.is_symlink():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
        removed_meta.append(rel)

    def migrate_from(directory: Path) -> None:
        if not directory.is_dir():
            return
        for child in sorted(directory.iterdir()):
            if child.name in ("workspace", "workspaces"):
                migrate_from(child)
                remove_meta_path(child)
                continue
            if not is_workspace_loot_dir(child):
                continue
            dest = workspace_dir / child.name
            if dest.exists():
                log(f"skip move {child.name}: already exists in workspace/")
                continue
            shutil.move(str(child), str(dest))
            moved.append(child.name)
            log(f"moved workspace {child.name} -> workspace/")

    if workspaces_link.exists() and not workspaces_link.is_symlink():
        log("repairing loot/workspaces (expected symlink to workspace/)")
        migrate_from(workspaces_link)
        shutil.rmtree(workspaces_link)
        removed_meta.append("workspaces")

    for meta in ("workspace", "workspaces"):
        nested = workspace_dir / meta
        if nested.exists():
            migrate_from(nested)
            remove_meta_path(nested)

    if workspaces_link.is_symlink():
        if workspaces_link.resolve() != workspace_dir.resolve():
            workspaces_link.unlink()
            workspaces_link.symlink_to(workspace_dir)
    elif workspaces_link.exists():
        shutil.rmtree(workspaces_link)
        workspaces_link.symlink_to(workspace_dir)
    else:
        workspaces_link.symlink_to(workspace_dir)

    return {
        "moved": moved,
        "removed_meta": removed_meta,
        "workspace_dir": str(workspace_dir),
        "workspaces_link": str(workspaces_link),
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Kitelon database utilities")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("migrate", help="Apply SQL migrations")
    sub.add_parser("test", help="Test PostgreSQL connectivity")
    p_prune = sub.add_parser(
        "prune-workspaces",
        help="Remove bogus workspace rows and re-sync from disk",
    )
    p_prune.add_argument(
        "--loot-root",
        default=str(INSTALL_DIR / "loot"),
        help="Loot root directory",
    )
    p_prune.add_argument(
        "--force",
        action="store_true",
        help="Delete workspace rows even when they still have hosts, findings, or jobs",
    )
    p_fix_loot = sub.add_parser(
        "fix-loot-layout",
        help="Repair loot/workspace vs loot/workspaces symlink layout",
    )
    p_fix_loot.add_argument(
        "--loot-root",
        default=str(INSTALL_DIR / "loot"),
        help="Loot root directory",
    )
    p_migrate_loot = sub.add_parser("migrate-loot", help="Import legacy SQLite files")
    p_migrate_loot.add_argument(
        "--loot-root",
        default=str(INSTALL_DIR / "loot"),
        help="Loot root directory",
    )
    p_migrate_artifacts = sub.add_parser(
        "migrate-artifacts",
        help="Archive workspace loot files into PostgreSQL",
    )
    p_migrate_artifacts.add_argument(
        "--loot-root",
        default=str(INSTALL_DIR / "loot"),
        help="Loot root directory",
    )
    p_migrate_artifacts.add_argument(
        "--no-mirror",
        action="store_true",
        help="Do not write files back to the loot directory",
    )
    p_schedule = sub.add_parser("schedule", help="Create recurring scan schedule (cron)")
    p_schedule.add_argument("--workspace", required=True)
    p_schedule.add_argument(
        "--cron",
        required=True,
        help='5-field cron expression (e.g. "0 2 * * *" for daily at 02:00)',
    )
    p_schedule.add_argument("--target", required=True)
    p_schedule.add_argument("--mode", default="normal")
    p_schedule.add_argument(
        "--loot-root",
        default=str(INSTALL_DIR / "loot"),
        help="Loot root directory",
    )

    args = parser.parse_args()
    if args.cmd == "migrate":
        migrate()
    elif args.cmd == "test":
        test_connection()
    elif args.cmd == "prune-workspaces":
        loot = Path(args.loot_root)
        with get_connection() as conn:
            fix_loot_workspace_layout(loot)
            for alias, path in discover_filesystem_workspaces(loot):
                ensure_workspace(conn, alias, path)
            removed = prune_invalid_workspaces(conn, loot, force=args.force)
        print(f"removed {removed} invalid workspace row(s)")
    elif args.cmd == "fix-loot-layout":
        result = fix_loot_workspace_layout(Path(args.loot_root))
        moved = result["moved"]
        if moved:
            print(f"moved {len(moved)} workspace(s): {', '.join(moved)}")
        else:
            print("no workspace directories needed moving")
        if result["removed_meta"]:
            print(f"removed nested path(s): {', '.join(result['removed_meta'])}")
        print(f"loot/workspace: {result['workspace_dir']}")
        print(f"loot/workspaces -> workspace (symlink)")
    elif args.cmd == "migrate-loot":
        n = migrate_all_sqlite(Path(args.loot_root))
        print(f"migrated {n} workspace(s)")
    elif args.cmd == "migrate-artifacts":
        from kitelon_storage import migrate_all_artifacts  # noqa: E402

        loot = Path(args.loot_root)
        mirror = not args.no_mirror
        with get_connection() as conn:
            sync_workspaces_from_disk(conn, loot)
        n = migrate_all_artifacts(loot, mirror=mirror)
        print(f"archived {n} artifact(s)")
    elif args.cmd == "schedule":
        loot = Path(args.loot_root)
        with get_connection() as conn:
            ws_id = ensure_workspace(conn, args.workspace, loot_root=loot)
            sched_id = create_schedule(
                conn, ws_id, args.cron, args.target, args.mode
            )
            print(sched_id)
