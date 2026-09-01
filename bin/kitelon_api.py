#!/usr/bin/env python3
"""
REST + static file server for the Web UI.

Workspaces, jobs, schedules, loot download, and report endpoints live here.
Requires WEB_API_KEY on every bind.
"""

import hmac
import json
import os
import secrets
import subprocess
import sys
import time
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from kitelon_db import (
    create_schedule,
    create_workspace,
    db_config,
    delete_job,
    delete_schedule,
    delete_workspace,
    enqueue_job,
    confined_workspace_loot_path,
    ensure_workspace,
    get_connection,
    get_heartbeat,
    get_host,
    get_job,
    get_schedule,
    get_workspace_by_alias,
    list_discovered_urls,
    list_domains,
    list_hosts,
    list_jobs,
    list_scan_runs,
    list_schedules,
    list_services,
    list_technologies,
    list_vulns,
    list_workspaces,
    rename_host,
    retry_job,
    sync_workspaces_from_disk,
    is_workspace_loot_dir,
    update_job,
    update_schedule,
    update_workspace,
    workspace_stats,
)
from kitelon_scan_config import (
    VALID_MODE_IDS,
    merge_job_scan_args,
    scan_config_payload,
)

MAX_IMPORT_BYTES = 50 * 1024 * 1024
MAX_PACK_BYTES = 100 * 1024 * 1024

_BIN_DIR = Path(__file__).resolve().parent
INSTALL_DIR = Path(os.environ.get("KITELON_INSTALL_DIR", "/usr/share/kitelon"))
WEB_ROOT = Path(os.environ.get("KITELON_WEB_ROOT", INSTALL_DIR / "web"))
LOOT_ROOT = Path(os.environ.get("KITELON_LOOT_ROOT", INSTALL_DIR / "loot"))
KITELON_BIN = Path(os.environ.get("KITELON_BIN", INSTALL_DIR / "kitelon"))
WEB_BIND = os.environ.get("WEB_BIND", "127.0.0.1")
WEB_PORT = int(os.environ.get("WEB_PORT", "8080"))
API_KEY = os.environ.get("WEB_API_KEY", os.environ.get("KITELON_API_KEY", ""))
API_KEYS_FILE = Path("/root/.kitelon_api_keys.conf")


def _package_version() -> str:
    for candidate in (_BIN_DIR.parent / "VERSION", INSTALL_DIR / "VERSION"):
        try:
            text = candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text:
            return text
    return "0.0.0"

try:
    from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
    from fastapi.responses import FileResponse, JSONResponse, Response
    from fastapi.staticfiles import StaticFiles
    import uvicorn
except ImportError:
    FastAPI = None  # type: ignore
    UploadFile = None  # type: ignore


def _serialize(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, val in row.items():
        if isinstance(val, datetime):
            out[key] = val.isoformat()
        else:
            out[key] = val
    return out


def _read_api_key_file() -> str:
    try:
        text = API_KEYS_FILE.read_text(encoding="utf-8")
    except OSError:
        return ""
    for line in text.splitlines():
        if line.startswith("WEB_API_KEY="):
            value = line.split("=", 1)[1].strip().strip('"').strip("'")
            if value:
                return value
    return ""


def _persist_api_key(key: str) -> None:
    try:
        API_KEYS_FILE.write_text(f"WEB_API_KEY={key}\n", encoding="utf-8")
        API_KEYS_FILE.chmod(0o600)
    except OSError as exc:
        print(f"could not write {API_KEYS_FILE}: {exc}", file=sys.stderr)


def ensure_api_key() -> str:
    global API_KEY
    if API_KEY:
        return API_KEY
    stored = _read_api_key_file()
    if stored:
        API_KEY = stored
        os.environ["WEB_API_KEY"] = stored
        return API_KEY
    API_KEY = secrets.token_hex(16)
    os.environ["WEB_API_KEY"] = API_KEY
    _persist_api_key(API_KEY)
    print(
        f"generated WEB_API_KEY (stored in {API_KEYS_FILE}; send as X-API-Key)",
        file=sys.stderr,
    )
    return API_KEY


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    expected = API_KEY or ensure_api_key()
    provided = x_api_key or ""
    if not expected or len(provided) != len(expected) or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


def _workspace_loot_path(alias: str) -> Path:
    try:
        return confined_workspace_loot_path(LOOT_ROOT, alias)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


def _workspace_or_404(alias: str, conn=None) -> dict[str, Any]:
    def lookup(c) -> dict[str, Any]:
        ws = get_workspace_by_alias(c, alias)
        if not ws:
            loot_path = _workspace_loot_path(alias)
            if is_workspace_loot_dir(loot_path):
                ensure_workspace(c, alias, loot_root=LOOT_ROOT)
                ws = get_workspace_by_alias(c, alias)
        if not ws:
            raise HTTPException(404, "workspace not found")
        return dict(ws)

    if conn is not None:
        return lookup(conn)
    with get_connection() as c:
        return lookup(c)


def verify_api_startup() -> None:
    ensure_api_key()
    if not API_KEY:
        print(
            f"refusing to bind API to {WEB_BIND}:{WEB_PORT} without WEB_API_KEY",
            file=sys.stderr,
        )
        sys.exit(1)


def _normalized_job_args(payload: dict[str, Any]) -> dict[str, Any]:
    args = merge_job_scan_args(payload.get("args") or {})
    if payload.get("options"):
        args = merge_job_scan_args({**args, "options": payload["options"]})
    return args


def kitelon_is_running() -> bool:
    try:
        r = subprocess.run(
            [str(KITELON_BIN), "--is-running"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return r.stdout.strip() == "true"
    except (subprocess.SubprocessError, OSError):
        return False


def _parse_hosts_list(hosts: list[str] | None) -> list[str] | None:
    if not hosts:
        return None
    result: list[str] = []
    for item in hosts:
        result.extend(part.strip() for part in item.split(",") if part.strip())
    return result or None


def _report_rel_paths(loot_path: Path, host_filter: list[str] | None) -> tuple[str, str]:
    from kitelon_loot import subset_report_paths  # noqa: E402
    from kitelon_storage import normalize_rel_path  # noqa: E402

    if host_filter:
        html_path, pdf_path = subset_report_paths(loot_path, host_filter)
        return (
            normalize_rel_path(html_path.relative_to(loot_path)),
            normalize_rel_path(pdf_path.relative_to(loot_path)),
        )
    return "kitelon-report.html", "reports/kitelon-report.pdf"


def _pdf_download_filename(alias: str, host_filter: list[str] | None) -> str:
    if host_filter:
        slug = "-".join(h[:20] for h in host_filter[:3]).replace("/", "-") or "subset"
        return f"kitelon-{alias}-{slug}.pdf"
    return f"kitelon-{alias}-report.pdf"


def _pdf_response(pdf_bytes: bytes, filename: str) -> Response:
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def create_app() -> FastAPI:
    if FastAPI is None:
        raise RuntimeError("fastapi is not installed")

    app = FastAPI(title="Kitelon API", version=_package_version())

    from kitelon_log import get_logger  # noqa: E402

    api_logger = get_logger("api")

    @app.middleware("http")
    async def log_http_requests(request, call_next):  # type: ignore[no-untyped-def]
        started = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - started) * 1000
        if not request.url.path.startswith("/static/"):
            api_logger.info(
                "%s %s -> %s (%.0fms)",
                request.method,
                request.url.path,
                response.status_code,
                elapsed_ms,
            )
        return response

    @app.get("/api/v1/")
    def api_root(_: None = Depends(require_api_key)) -> dict[str, Any]:
        return {
            "name": "Kitelon",
            "version": _package_version(),
            "endpoints": [
                "/api/v1/workspaces",
                "/api/v1/workspaces/{alias}",
                "/api/v1/workspaces/{alias}/import",
                "/api/v1/workspaces/{alias}/import/nessus",
                "/api/v1/workspaces/{alias}/import/burp",
                "/api/v1/jobs",
                "/api/v1/jobs/{id}",
                "/api/v1/schedules",
                "/api/v1/schedules/{id}",
                "/api/v1/scan-config",
                "/api/v1/status",
            ],
        }

    @app.get("/api/v1/status")
    def status(_: None = Depends(require_api_key)) -> dict[str, Any]:
        with get_connection() as conn:
            hb = get_heartbeat(conn)
        return {
            "scan_running": kitelon_is_running(),
            "heartbeat": _serialize(hb) if hb else None,
            "database": db_config()["dbname"],
        }

    @app.get("/api/v1/workspaces")
    def workspaces(_: None = Depends(require_api_key)) -> list[dict[str, Any]]:
        with get_connection() as conn:
            sync_workspaces_from_disk(conn, LOOT_ROOT)
            rows = list_workspaces(conn)
        return [_serialize(r) for r in rows]

    @app.post("/api/v1/workspaces")
    async def create_workspace_endpoint(
        payload: dict[str, Any], _: None = Depends(require_api_key)
    ) -> dict[str, Any]:
        alias = payload.get("alias")
        if not alias:
            raise HTTPException(400, "alias required")
        try:
            ws_id, created = create_workspace(LOOT_ROOT, str(alias))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        with get_connection() as conn:
            ws = conn.execute(
                "SELECT * FROM workspaces WHERE id = %s", (ws_id,)
            ).fetchone()
            data = _serialize(ws)
            data["stats"] = workspace_stats(conn, ws_id)
            data["created"] = created
        return data

    @app.get("/api/v1/workspaces/{alias}")
    def workspace_detail(alias: str, _: None = Depends(require_api_key)) -> dict[str, Any]:
        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)
            data = _serialize(ws)
            data["stats"] = workspace_stats(conn, int(ws["id"]))
        return data

    @app.patch("/api/v1/workspaces/{alias}")
    async def update_workspace_endpoint(
        alias: str, payload: dict[str, Any], _: None = Depends(require_api_key)
    ) -> dict[str, Any]:
        new_alias = payload.get("alias")
        try:
            with get_connection() as conn:
                ws = update_workspace(
                    conn, alias, new_alias=new_alias, loot_root=LOOT_ROOT
                )
                data = _serialize(ws)
                data["stats"] = workspace_stats(conn, int(ws["id"]))
        except ValueError as exc:
            msg = str(exc)
            if "not found" in msg:
                raise HTTPException(404, msg) from exc
            raise HTTPException(400, msg) from exc
        return data

    @app.delete("/api/v1/workspaces/{alias}")
    def delete_workspace_endpoint(
        alias: str,
        delete_loot: bool = Query(False),
        _: None = Depends(require_api_key),
    ) -> dict[str, Any]:
        try:
            with get_connection() as conn:
                ws = delete_workspace(conn, alias, delete_loot=delete_loot)
        except ValueError as exc:
            msg = str(exc)
            if "not found" in msg:
                raise HTTPException(404, msg) from exc
            raise HTTPException(409, msg) from exc
        return {
            "deleted": _serialize(ws),
            "loot_removed": delete_loot,
        }

    @app.get("/api/v1/workspaces/{alias}/export.zip")
    def workspace_export_zip(
        alias: str,
        _: None = Depends(require_api_key),
    ) -> Response:
        from kitelon_workspace_pack import export_workspace_zip  # noqa: E402

        try:
            out = export_workspace_zip(alias, loot_root=LOOT_ROOT)
            data = out.read_bytes()
            out.unlink(missing_ok=True)
        except ValueError as exc:
            msg = str(exc)
            if "not found" in msg:
                raise HTTPException(404, msg) from exc
            raise HTTPException(400, msg) from exc
        filename = f"kitelon-{alias}.zip"
        return Response(
            content=data,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.post("/api/v1/workspaces/import-zip")
    async def workspace_import_zip(
        file: UploadFile = File(...),
        alias: str | None = Query(None),
        replace: bool = Query(False),
        _: None = Depends(require_api_key),
    ) -> dict[str, Any]:
        from kitelon_workspace_pack import import_workspace_zip  # noqa: E402

        content = await file.read()
        if len(content) > MAX_PACK_BYTES:
            raise HTTPException(413, "workspace zip too large (max 100MB)")
        if not content:
            raise HTTPException(400, "empty upload")
        tmp = LOOT_ROOT / "tmp" / f"import-{uuid.uuid4().hex}.zip"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(content)
        try:
            result = import_workspace_zip(
                tmp,
                alias=alias,
                loot_root=LOOT_ROOT,
                replace=replace,
            )
        except (ValueError, json.JSONDecodeError, zipfile.BadZipFile, KeyError) as exc:
            msg = str(exc)
            code = 409 if "already exists" in msg else 400
            raise HTTPException(code, msg) from exc
        finally:
            tmp.unlink(missing_ok=True)
        return result

    @app.post("/api/v1/workspaces/{alias}/import")
    def import_workspace(alias: str, _: None = Depends(require_api_key)) -> dict[str, Any]:
        loot_path = _workspace_loot_path(alias)
        if not is_workspace_loot_dir(loot_path):
            raise HTTPException(404, "workspace loot directory not found")
        try:
            with get_connection() as conn:
                ws_id = ensure_workspace(conn, alias, loot_root=LOOT_ROOT)
                job_id = enqueue_job(
                    conn,
                    job_type="loot_process",
                    workspace_id=ws_id,
                    priority=50,
                    created_by="web-ui",
                )
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"id": job_id, "status": "pending", "job_type": "loot_process"}

    async def _import_scanner_file(
        alias: str, scanner: str, file: UploadFile
    ) -> dict[str, Any]:
        from kitelon_import import import_scanner_file  # noqa: E402

        ws = _workspace_or_404(alias)
        content = await file.read()
        if len(content) > MAX_IMPORT_BYTES:
            raise HTTPException(413, "upload too large (max 50MB)")
        if not content:
            raise HTTPException(400, "empty upload")
        filename = file.filename or f"{scanner}-import.xml"
        loot_path = Path(ws["loot_path"])
        try:
            result = import_scanner_file(
                int(ws["id"]), loot_path, scanner, filename, content
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        with get_connection() as conn:
            job_id = enqueue_job(
                conn,
                job_type="report",
                workspace_id=int(ws["id"]),
                priority=40,
                created_by=f"api:import-{scanner}",
            )
        result["report_job_id"] = job_id
        return result

    @app.post("/api/v1/workspaces/{alias}/import/nessus")
    async def import_nessus(
        alias: str,
        file: UploadFile = File(...),
        _: None = Depends(require_api_key),
    ) -> dict[str, Any]:
        return await _import_scanner_file(alias, "nessus", file)

    @app.post("/api/v1/workspaces/{alias}/import/burp")
    async def import_burp(
        alias: str,
        file: UploadFile = File(...),
        _: None = Depends(require_api_key),
    ) -> dict[str, Any]:
        return await _import_scanner_file(alias, "burp", file)

    @app.get("/api/v1/workspaces/{alias}/report.pdf")
    def workspace_report_pdf(
        alias: str,
        force: bool = Query(False),
        hosts: list[str] | None = Query(None),
        _: None = Depends(require_api_key),
    ) -> Response:
        from kitelon_loot import generate_reports  # noqa: E402
        from kitelon_storage import (  # noqa: E402
            artifacts_enabled,
            fs_mirror_enabled,
            get_artifact_bytes,
            store_artifact,
        )
        from report import (  # noqa: E402
            ReportError,
            ReportNotFoundError,
            ReportToolError,
            export_pdf_bytes,
        )

        host_filter = _parse_hosts_list(hosts)

        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)

            loot_path = Path(ws["loot_path"])
            workspace_id = int(ws["id"])
            html_rel, pdf_rel = _report_rel_paths(loot_path, host_filter)
            filename = _pdf_download_filename(alias, host_filter)

            if not force and artifacts_enabled():
                cached = get_artifact_bytes(conn, workspace_id, pdf_rel)
                if cached:
                    return _pdf_response(cached, filename)

            if host_filter:
                generate_reports(loot_path, alias, hostnames=host_filter)
            else:
                html_ready = bool(get_artifact_bytes(conn, workspace_id, html_rel))
                if not html_ready and not (loot_path / html_rel).is_file():
                    job_id = enqueue_job(
                        conn,
                        job_type="report",
                        workspace_id=workspace_id,
                        priority=30,
                        created_by="api:report.pdf",
                    )
                    raise HTTPException(
                        409,
                        f"Report not ready: queued job #{job_id}. Retry download in a moment.",
                    )
                if not html_ready:
                    generate_reports(loot_path, alias)

            html_bytes = get_artifact_bytes(conn, workspace_id, html_rel)
            if html_bytes is None:
                html_path = loot_path / html_rel
                if not html_path.is_file():
                    raise HTTPException(404, "HTML report not found")
                html_bytes = html_path.read_bytes()

            try:
                pdf_bytes = export_pdf_bytes(
                    html_content=html_bytes.decode("utf-8", errors="replace"),
                    force=force or bool(host_filter),
                )
            except ReportNotFoundError as exc:
                raise HTTPException(404, str(exc)) from exc
            except ReportToolError as exc:
                raise HTTPException(503, str(exc)) from exc
            except ReportError as exc:
                raise HTTPException(500, str(exc)) from exc

            if artifacts_enabled():
                store_artifact(
                    conn,
                    workspace_id,
                    loot_path,
                    pdf_rel,
                    pdf_bytes,
                    content_type="application/pdf",
                )
            elif fs_mirror_enabled():
                pdf_path = loot_path / pdf_rel
                pdf_path.parent.mkdir(parents=True, exist_ok=True)
                pdf_path.write_bytes(pdf_bytes)

            return _pdf_response(pdf_bytes, filename)

    @app.post("/api/v1/workspaces/{alias}/report")
    async def workspace_report_generate(
        alias: str,
        payload: dict[str, Any],
        _: None = Depends(require_api_key),
    ) -> dict[str, Any]:
        from kitelon_loot import generate_reports  # noqa: E402
        from kitelon_storage import artifacts_enabled, get_artifact_bytes, store_artifact  # noqa: E402
        from report import export_pdf_bytes  # noqa: E402

        host_filter = payload.get("hosts") or []
        if not isinstance(host_filter, list) or not host_filter:
            raise HTTPException(400, "hosts array required")
        host_filter = [str(h).strip() for h in host_filter if str(h).strip()]
        if not host_filter:
            raise HTTPException(400, "hosts array required")
        fmt = str(payload.get("format", "pdf")).lower()

        try:
            with get_connection() as conn:
                ws = _workspace_or_404(alias, conn)

                loot_path = Path(ws["loot_path"])
                workspace_id = int(ws["id"])
                generate_reports(loot_path, alias, hostnames=host_filter)
                html_rel, pdf_rel = _report_rel_paths(loot_path, host_filter)
                result: dict[str, Any] = {
                    "hosts": host_filter,
                    "html_path": html_rel,
                }
                if fmt == "pdf":
                    html_bytes = get_artifact_bytes(conn, workspace_id, html_rel)
                    if html_bytes is None:
                        html_path = loot_path / html_rel
                        if not html_path.is_file():
                            raise FileNotFoundError("HTML report not found")
                        html_bytes = html_path.read_bytes()
                    pdf_bytes = export_pdf_bytes(
                        html_content=html_bytes.decode("utf-8", errors="replace"),
                        force=True,
                    )
                    if artifacts_enabled():
                        store_artifact(
                            conn,
                            workspace_id,
                            loot_path,
                            pdf_rel,
                            pdf_bytes,
                            content_type="application/pdf",
                        )
                    result["pdf_path"] = pdf_rel
                return result
        except FileNotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except Exception as exc:
            from report import ReportError  # noqa: E402

            if isinstance(exc, ReportError):
                raise HTTPException(503, str(exc)) from exc
            raise

    @app.get("/api/v1/workspaces/{alias}/ssl-scans")
    def workspace_ssl_scans(
        alias: str,
        _: None = Depends(require_api_key),
    ) -> list[dict[str, Any]]:
        from kitelon_testssl import list_ssl_scan_summaries  # noqa: E402

        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)
            loot_path = Path(ws["loot_path"])
            rows = list_ssl_scan_summaries(loot_path)
            for row in rows:
                row["report_url"] = (
                    f"/api/v1/workspaces/{alias}/hosts/"
                    f"{row['hostname']}/ssl-report.html?port={row['port']}"
                )
                row["pdf_url"] = (
                    f"/api/v1/workspaces/{alias}/hosts/"
                    f"{row['hostname']}/ssl-report.pdf?port={row['port']}"
                )
            return rows

    @app.get("/api/v1/workspaces/{alias}/ssl-report.html")
    def workspace_ssl_report(
        alias: str,
        _: None = Depends(require_api_key),
    ) -> Response:
        from kitelon_testssl import get_ssl_report_html  # noqa: E402

        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)
            html = get_ssl_report_html(
                conn, int(ws["id"]), Path(ws["loot_path"]), alias
            )
        if not html:
            raise HTTPException(
                404,
                "No SSL/TLS scan data: run testssl with TESTSSL=1 or --testssl-only.",
            )
        return Response(content=html, media_type="text/html; charset=utf-8")

    @app.get("/api/v1/workspaces/{alias}/hosts/{hostname}/ssl-report.html")
    def host_ssl_report(
        alias: str,
        hostname: str,
        port: int = Query(443, ge=1, le=65535),
        _: None = Depends(require_api_key),
    ) -> Response:
        from kitelon_testssl import get_ssl_report_html  # noqa: E402

        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)
            html = get_ssl_report_html(
                conn,
                int(ws["id"]),
                Path(ws["loot_path"]),
                alias,
                hostname=hostname,
                port=str(port),
            )
        if not html:
            raise HTTPException(
                404,
                f"No SSL/TLS report for {hostname}:{port}.",
            )
        return Response(content=html, media_type="text/html; charset=utf-8")

    @app.get("/api/v1/workspaces/{alias}/ssl-report.pdf")
    def workspace_ssl_report_pdf(
        alias: str,
        force: bool = Query(False),
        _: None = Depends(require_api_key),
    ) -> Response:
        from kitelon_testssl import get_ssl_report_pdf_bytes  # noqa: E402
        from report import ReportError, ReportNotFoundError, ReportToolError  # noqa: E402

        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)
            try:
                pdf_bytes, filename = get_ssl_report_pdf_bytes(
                    conn,
                    int(ws["id"]),
                    Path(ws["loot_path"]),
                    alias,
                    force=force,
                )
            except FileNotFoundError as exc:
                raise HTTPException(404, str(exc)) from exc
            except ReportNotFoundError as exc:
                raise HTTPException(404, str(exc)) from exc
            except ReportToolError as exc:
                raise HTTPException(503, str(exc)) from exc
            except ReportError as exc:
                raise HTTPException(500, str(exc)) from exc
        return _pdf_response(pdf_bytes, filename)

    @app.get("/api/v1/workspaces/{alias}/hosts/{hostname}/ssl-report.pdf")
    def host_ssl_report_pdf(
        alias: str,
        hostname: str,
        port: int = Query(443, ge=1, le=65535),
        force: bool = Query(False),
        _: None = Depends(require_api_key),
    ) -> Response:
        from kitelon_testssl import get_ssl_report_pdf_bytes  # noqa: E402
        from report import ReportError, ReportNotFoundError, ReportToolError  # noqa: E402

        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)
            try:
                pdf_bytes, filename = get_ssl_report_pdf_bytes(
                    conn,
                    int(ws["id"]),
                    Path(ws["loot_path"]),
                    alias,
                    hostname=hostname,
                    port=str(port),
                    force=force,
                )
            except FileNotFoundError as exc:
                raise HTTPException(404, str(exc)) from exc
            except ReportNotFoundError as exc:
                raise HTTPException(404, str(exc)) from exc
            except ReportToolError as exc:
                raise HTTPException(503, str(exc)) from exc
            except ReportError as exc:
                raise HTTPException(500, str(exc)) from exc
        return _pdf_response(pdf_bytes, filename)

    @app.get("/api/v1/workspaces/{alias}/pentest-report.html")
    def workspace_pentest_report(
        alias: str,
        _: None = Depends(require_api_key),
    ) -> Response:
        from kitelon_pentest_report import get_pentest_report_html  # noqa: E402

        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)
            html = get_pentest_report_html(conn, int(ws["id"]), Path(ws["loot_path"]), alias)
        if not html:
            raise HTTPException(
                404,
                "Pentest workbook not available: import loot or run report generation.",
            )
        return Response(content=html, media_type="text/html; charset=utf-8")

    @app.get("/api/v1/workspaces/{alias}/artifacts")
    def workspace_artifacts(
        alias: str,
        prefix: str | None = Query(None),
        limit: int = Query(200, ge=1, le=5000),
        offset: int = Query(0, ge=0),
        _: None = Depends(require_api_key),
    ) -> list[dict[str, Any]]:
        from kitelon_storage import list_artifacts  # noqa: E402

        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)
            rows = list_artifacts(
                conn, int(ws["id"]), prefix=prefix, limit=limit, offset=offset
            )
        return [_serialize(r) for r in rows]

    @app.get("/api/v1/workspaces/{alias}/artifacts/{rel_path:path}")
    def workspace_artifact_download(
        alias: str,
        rel_path: str,
        _: None = Depends(require_api_key),
    ) -> Response:
        from kitelon_storage import get_artifact, normalize_rel_path  # noqa: E402

        try:
            rel = normalize_rel_path(rel_path)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)
            row = get_artifact(conn, int(ws["id"]), rel)
        if not row:
            raise HTTPException(404, "artifact not found")

        content = row["content"]
        if isinstance(content, memoryview):
            content = content.tobytes()
        else:
            content = bytes(content)
        filename = Path(rel).name or "artifact"
        media = str(row.get("content_type") or "application/octet-stream")
        lower_name = filename.lower()
        if "html" in media.lower() or lower_name.endswith((".html", ".htm", ".svg")):
            media = "application/octet-stream"
        safe_name = filename.replace('"', "").replace("\r", "").replace("\n", "")
        return Response(
            content=content,
            media_type=media,
            headers={
                "Content-Disposition": f'attachment; filename="{safe_name}"',
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.get("/api/v1/workspaces/{alias}/hosts")
    def workspace_hosts(
        alias: str,
        limit: int = Query(100, ge=1, le=5000),
        offset: int = Query(0, ge=0),
        _: None = Depends(require_api_key),
    ) -> list[dict[str, Any]]:
        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)
            rows = list_hosts(conn, int(ws["id"]), limit=limit, offset=offset)
        return [_serialize(r) for r in rows]

    @app.patch("/api/v1/workspaces/{alias}/hosts/{hostname}")
    async def update_host_endpoint(
        alias: str,
        hostname: str,
        payload: dict[str, Any],
        _: None = Depends(require_api_key),
    ) -> dict[str, Any]:
        new_hostname = payload.get("hostname")
        if not new_hostname:
            raise HTTPException(400, "hostname required")
        try:
            with get_connection() as conn:
                ws = _workspace_or_404(alias, conn)
                row = rename_host(conn, int(ws["id"]), hostname, str(new_hostname))
        except ValueError as exc:
            msg = str(exc)
            if "not found" in msg:
                raise HTTPException(404, msg) from exc
            raise HTTPException(400, msg) from exc
        return _serialize(row)

    @app.get("/api/v1/workspaces/{alias}/vulns")
    def workspace_vulns(
        alias: str,
        severity: str | None = None,
        hostname: str | None = None,
        q: str | None = Query(None, min_length=1),
        limit: int = Query(100, ge=1, le=5000),
        offset: int = Query(0, ge=0),
        _: None = Depends(require_api_key),
    ) -> list[dict[str, Any]]:
        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)
            rows = list_vulns(
                conn,
                int(ws["id"]),
                severity=severity,
                hostname=hostname,
                q=q,
                limit=limit,
                offset=offset,
            )
        return [_serialize(r) for r in rows]

    @app.get("/api/v1/workspaces/{alias}/domains")
    def workspace_domains(
        alias: str,
        limit: int = Query(500, ge=1, le=5000),
        _: None = Depends(require_api_key),
    ) -> list[dict[str, Any]]:
        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)
            rows = list_domains(conn, int(ws["id"]), limit=limit)
        return [_serialize(r) for r in rows]

    @app.get("/api/v1/workspaces/{alias}/services")
    def workspace_services(
        alias: str,
        hostname: str | None = None,
        limit: int = Query(500, ge=1, le=5000),
        _: None = Depends(require_api_key),
    ) -> list[dict[str, Any]]:
        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)
            rows = list_services(conn, int(ws["id"]), hostname=hostname, limit=limit)
        return [_serialize(r) for r in rows]

    @app.get("/api/v1/workspaces/{alias}/technologies")
    def workspace_technologies(
        alias: str,
        hostname: str | None = None,
        limit: int = Query(500, ge=1, le=5000),
        _: None = Depends(require_api_key),
    ) -> list[dict[str, Any]]:
        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)
            rows = list_technologies(conn, int(ws["id"]), hostname=hostname, limit=limit)
        return [_serialize(r) for r in rows]

    @app.get("/api/v1/workspaces/{alias}/urls")
    def workspace_urls(
        alias: str,
        hostname: str | None = None,
        source: str | None = None,
        limit: int = Query(500, ge=1, le=5000),
        _: None = Depends(require_api_key),
    ) -> list[dict[str, Any]]:
        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)
            rows = list_discovered_urls(
                conn, int(ws["id"]), hostname=hostname, source=source, limit=limit
            )
        return [_serialize(r) for r in rows]

    @app.get("/api/v1/workspaces/{alias}/scan-runs")
    def workspace_scan_runs(
        alias: str,
        limit: int = Query(50, ge=1, le=500),
        _: None = Depends(require_api_key),
    ) -> list[dict[str, Any]]:
        with get_connection() as conn:
            ws = _workspace_or_404(alias, conn)
            rows = list_scan_runs(conn, int(ws["id"]), limit=limit)
        return [_serialize(r) for r in rows]

    @app.get("/api/v1/jobs")
    def jobs(
        status: str | None = None,
        workspace: str | None = None,
        limit: int = Query(100, ge=1, le=500),
        _: None = Depends(require_api_key),
    ) -> list[dict[str, Any]]:
        with get_connection() as conn:
            ws_id = None
            if workspace:
                ws = _workspace_or_404(workspace, conn)
                ws_id = int(ws["id"])
            rows = list_jobs(conn, status=status, workspace_id=ws_id, limit=limit)
        return [_serialize(r) for r in rows]

    @app.get("/api/v1/jobs/{job_id}")
    def job_detail(job_id: int, _: None = Depends(require_api_key)) -> dict[str, Any]:
        with get_connection() as conn:
            row = get_job(conn, job_id)
        if not row:
            raise HTTPException(404, "job not found")
        return _serialize(row)

    @app.post("/api/v1/jobs/{job_id}/retry")
    def retry_job_endpoint(job_id: int, _: None = Depends(require_api_key)) -> dict[str, Any]:
        try:
            with get_connection() as conn:
                new_id = retry_job(conn, job_id, created_by="web-ui")
        except ValueError as exc:
            msg = str(exc)
            if "not found" in msg:
                raise HTTPException(404, msg) from exc
            raise HTTPException(400, msg) from exc
        return {"id": new_id, "status": "pending", "retried_from": job_id}

    @app.patch("/api/v1/jobs/{job_id}")
    async def update_job_endpoint(
        job_id: int, payload: dict[str, Any], _: None = Depends(require_api_key)
    ) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        for key in ("priority", "target", "mode", "scheduled_at"):
            if key in payload:
                fields[key] = payload[key]
        if "args" in payload or "options" in payload:
            fields["args"] = _normalized_job_args(payload)
        if "job_type" in payload:
            fields["job_type"] = payload["job_type"]
        if "workspace" in payload:
            fields["workspace"] = payload["workspace"]
        try:
            with get_connection() as conn:
                row = update_job(conn, job_id, **fields)
        except ValueError as exc:
            msg = str(exc)
            if "not found" in msg:
                raise HTTPException(404, msg) from exc
            raise HTTPException(400, msg) from exc
        return _serialize(row)

    @app.delete("/api/v1/jobs/{job_id}")
    def delete_job_endpoint(
        job_id: int,
        kill: bool = Query(False),
        _: None = Depends(require_api_key),
    ) -> dict[str, Any]:
        try:
            with get_connection() as conn:
                row = delete_job(conn, job_id, kill=kill)
        except ValueError as exc:
            msg = str(exc)
            if "not found" in msg:
                raise HTTPException(404, msg) from exc
            raise HTTPException(409, msg) from exc
        return {"deleted": _serialize(row), "cancelled": row.get("status") == "cancelled"}

    @app.post("/api/v1/jobs")
    async def create_job(payload: dict[str, Any], _: None = Depends(require_api_key)) -> dict[str, Any]:
        job_type = payload.get("job_type", "scan")
        workspace = payload.get("workspace")
        target = payload.get("target")
        mode = payload.get("mode", "normal")
        args = _normalized_job_args(payload)
        priority = int(payload.get("priority", 100))
        created_by = payload.get("created_by", "api")

        if job_type in ("reimport", "loot_process", "report"):
            if not workspace:
                raise HTTPException(400, "workspace required for import/report jobs")
            target = None
            mode = None
        elif job_type == "scan":
            if not target:
                raise HTTPException(400, "target required for scan")
            if not workspace:
                raise HTTPException(400, "workspace required for scan")
            if mode not in VALID_MODE_IDS:
                raise HTTPException(400, f"invalid mode: {mode}")

        try:
            with get_connection() as conn:
                ws_id = None
                if workspace:
                    ws_id = ensure_workspace(conn, workspace, loot_root=LOOT_ROOT)
                job_id = enqueue_job(
                    conn,
                    job_type=job_type,
                    workspace_id=ws_id,
                    target=target,
                    mode=mode,
                    args=args,
                    priority=priority,
                    created_by=created_by,
                )
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"id": job_id, "status": "pending"}

    @app.get("/api/v1/scan-config")
    def scan_config(_: None = Depends(require_api_key)) -> dict[str, Any]:
        return scan_config_payload()

    @app.get("/api/v1/schedules")
    def schedules(
        workspace: str | None = None,
        _: None = Depends(require_api_key),
    ) -> list[dict[str, Any]]:
        with get_connection() as conn:
            ws_id = None
            if workspace:
                ws = _workspace_or_404(workspace, conn)
                ws_id = int(ws["id"])
            rows = list_schedules(conn, workspace_id=ws_id)
        return [_serialize(r) for r in rows]

    @app.post("/api/v1/schedules")
    async def create_sched(payload: dict[str, Any], _: None = Depends(require_api_key)) -> dict[str, Any]:
        workspace = payload.get("workspace")
        cron = payload.get("cron") or payload.get("cadence")
        target = payload.get("target")
        mode = payload.get("mode", "normal")
        args = _normalized_job_args(payload)
        if not workspace or not cron or not target:
            raise HTTPException(400, "workspace, cron, and target required")
        if mode not in VALID_MODE_IDS:
            raise HTTPException(400, f"invalid mode: {mode}")
        try:
            from kitelon_db import validate_cron

            cron = validate_cron(str(cron))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        try:
            with get_connection() as conn:
                ws_id = ensure_workspace(conn, workspace, loot_root=LOOT_ROOT)
                sched_id = create_schedule(conn, ws_id, cron, target, mode, args)
                row = get_schedule(conn, sched_id)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return _serialize(row) if row else {"id": sched_id}

    @app.get("/api/v1/schedules/{schedule_id}")
    def schedule_detail(schedule_id: int, _: None = Depends(require_api_key)) -> dict[str, Any]:
        with get_connection() as conn:
            row = get_schedule(conn, schedule_id)
        if not row:
            raise HTTPException(404, "schedule not found")
        return _serialize(row)

    @app.patch("/api/v1/schedules/{schedule_id}")
    async def update_sched_endpoint(
        schedule_id: int, payload: dict[str, Any], _: None = Depends(require_api_key)
    ) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        for key in ("cron", "target", "mode", "enabled", "next_run_at", "workspace"):
            if key in payload:
                fields[key] = payload[key]
        if "args" in payload or "options" in payload:
            fields["args"] = _normalized_job_args(payload)
        if "mode" in fields and fields["mode"] not in VALID_MODE_IDS:
            raise HTTPException(400, f"invalid mode: {fields['mode']}")
        try:
            with get_connection() as conn:
                row = update_schedule(conn, schedule_id, **fields)
        except ValueError as exc:
            msg = str(exc)
            if "not found" in msg:
                raise HTTPException(404, msg) from exc
            raise HTTPException(400, msg) from exc
        return _serialize(row)

    @app.delete("/api/v1/schedules/{schedule_id}")
    def delete_sched_endpoint(
        schedule_id: int, _: None = Depends(require_api_key)
    ) -> dict[str, Any]:
        try:
            with get_connection() as conn:
                row = delete_schedule(conn, schedule_id)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc
        return {"deleted": _serialize(row)}

    static_dir = WEB_ROOT / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(WEB_ROOT / "index.html")

    @app.get("/workspace.html")
    def workspace_page() -> FileResponse:
        return FileResponse(WEB_ROOT / "workspace.html")

    @app.get("/jobs.html")
    def jobs_page() -> FileResponse:
        return FileResponse(WEB_ROOT / "jobs.html")

    @app.get("/schedules.html")
    def schedules_page() -> FileResponse:
        return FileResponse(WEB_ROOT / "schedules.html")

    return app


def main() -> None:
    if FastAPI is None:
        print("fastapi/uvicorn not installed", file=sys.stderr)
        sys.exit(1)
    verify_api_startup()
    from kitelon_log import get_logger  # noqa: E402

    get_logger("api").info("starting web UI bind=%s port=%s", WEB_BIND, WEB_PORT)
    app = create_app()
    uvicorn.run(app, host=WEB_BIND, port=WEB_PORT, log_level="info")


if __name__ == "__main__":
    main()
