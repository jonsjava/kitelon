#!/usr/bin/env python3
# Polls PostgreSQL for pending jobs; runs kitelon_scan / loot import subprocesses.

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

_BIN_DIR = Path(__file__).resolve().parent
if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))

from kitelon_db import (  # noqa: E402
    claim_next_job,
    complete_job,
    enqueue_job,
    get_connection,
    get_running_scan_workspace_ids,
    get_workspace_by_alias,
    log,
    normalize_workspace_alias,
    promote_schedules,
    recover_stuck_jobs,
    set_job_pid,
    touch_heartbeat,
)
from kitelon_log import get_logger  # noqa: E402

INSTALL_DIR = Path(os.environ.get("KITELON_INSTALL_DIR", "/usr/share/kitelon"))
SCAN_SCRIPT = Path(os.environ.get("KITELON_SCAN_SCRIPT", INSTALL_DIR / "bin" / "kitelon_scan.py"))
POLL_SEC = int(os.environ.get("WORKER_POLL_SEC", "10"))
STUCK_MINUTES = int(os.environ.get("WORKER_STUCK_MINUTES", "180"))
POST_CONCURRENCY = max(1, int(os.environ.get("WORKER_POST_CONCURRENCY", "2")))
WORKER_ROLE = os.environ.get("WORKER_ROLE", "both").lower()

_worker_logger = get_logger("worker")

_stop = threading.Event()


def build_scan_command(job: dict) -> list[str]:
    alias = job.get("workspace_alias")
    if not alias:
        raise ValueError("scan job missing workspace")
    cmd = ["python3", str(SCAN_SCRIPT)]
    if job.get("target"):
        cmd.extend(["--target", job["target"]])
    mode = job.get("mode") or "normal"
    cmd.extend(["--mode", mode])
    cmd.extend(["--workspace", normalize_workspace_alias(alias)])
    cmd.extend(["--job-id", str(job["id"])])
    args = job.get("args_json") or {}
    if isinstance(args, str):
        args = json.loads(args)
    from kitelon_scan_config import merge_job_scan_args

    args = merge_job_scan_args(args, trust_extra=True)
    extra = args.get("extra_args", [])
    if isinstance(extra, str):
        extra = extra.split()
    cmd.extend(extra)
    return cmd


def loot_action_for_job(job: dict) -> str:
    args = job.get("args_json") or {}
    if isinstance(args, str):
        args = json.loads(args)
    if job["job_type"] == "report":
        return str(args.get("action", "report"))
    if job["job_type"] == "loot_process":
        return str(args.get("action", "all"))
    return str(args.get("action", "all"))


def run_loot_job(job: dict) -> tuple[int, str]:
    alias = job.get("workspace_alias")
    if not alias:
        return 1, f"{job['job_type']} job missing workspace"
    alias = normalize_workspace_alias(alias)
    with get_connection() as conn:
        ws = get_workspace_by_alias(conn, alias)
    if not ws:
        return 1, f"workspace not found: {alias}"

    action = loot_action_for_job(job)
    proc = subprocess.run(
        [
            "python3",
            str(INSTALL_DIR / "bin" / "kitelon_loot.py"),
            "--loot-dir",
            ws["loot_path"],
            "--workspace",
            alias,
            "--action",
            action,
        ],
        capture_output=True,
        text=True,
    )
    err = proc.stderr.strip() or proc.stdout.strip()
    return proc.returncode, err


def run_job(job: dict) -> tuple[int, str]:
    job_type = job["job_type"]
    job_id = int(job["id"])

    if job_type in ("reimport", "loot_process", "report"):
        return run_loot_job(job)

    if job_type == "scan":
        if not job.get("workspace_alias"):
            return 1, "scan job missing workspace"
        cmd = build_scan_command(job)
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        with get_connection() as conn:
            set_job_pid(conn, job_id, proc.pid)
        _stdout, stderr = proc.communicate()
        err = (stderr or "").strip()
        if len(err) > 8000:
            err = err[:8000] + "…"
        if proc.returncode == 0 and job.get("workspace_alias"):
            with get_connection() as conn:
                ws = get_workspace_by_alias(conn, job["workspace_alias"])
                if ws:
                    enqueue_job(
                        conn,
                        job_type="loot_process",
                        workspace_id=int(ws["id"]),
                        created_by=f"worker:after-scan:{job_id}",
                        priority=50,
                    )
        return proc.returncode, err

    return 1, f"unknown job_type: {job_type}"


def execute_one(role: str) -> bool:
    with get_connection() as conn:
        exclude = get_running_scan_workspace_ids(conn) or None
        job = claim_next_job(conn, role=role, exclude_workspace_ids=exclude)
    if not job:
        return False

    job_id = int(job["id"])
    log(f"[{role}] running job {job_id} type={job['job_type']} target={job.get('target')}")
    try:
        code, err = run_job(job)
    except Exception as exc:
        code, err = 1, str(exc)

    with get_connection() as conn:
        complete_job(conn, job_id, exit_code=code, error=err if code != 0 else None)
        touch_heartbeat(conn, job_id, f"{role}: {'ok' if code == 0 else err[:180]}")

    if code != 0:
        log(f"[{role}] job {job_id} failed ({code}): {err[:300]}")
    else:
        log(f"[{role}] job {job_id} completed")
    return True


def post_worker_loop(worker_id: int) -> None:
    name = f"post-{worker_id}"
    log(f"{name} started")
    while not _stop.is_set():
        try:
            if execute_one("post"):
                continue
            with get_connection() as conn:
                touch_heartbeat(conn, None, f"{name} idle")
        except Exception as exc:
            log(f"{name} error: {exc}")
        _stop.wait(POLL_SEC)


def scan_worker_loop() -> None:
    log("scan pool started")
    while not _stop.is_set():
        try:
            if execute_one("scan"):
                continue
            with get_connection() as conn:
                touch_heartbeat(conn, None, "scan pool idle")
        except Exception as exc:
            log(f"scan pool error: {exc}")
        _stop.wait(POLL_SEC)


def recover() -> None:
    with get_connection() as conn:
        stuck = recover_stuck_jobs(conn, STUCK_MINUTES)
        promoted = promote_schedules(conn)
        touch_heartbeat(conn, None, f"recover stuck={stuck} promoted={promoted}")
    log(f"recover: stuck={stuck} schedules_promoted={promoted}")


def run_daemon() -> None:
    log(
        f"worker started role={WORKER_ROLE} poll={POLL_SEC}s "
        f"post_concurrency={POST_CONCURRENCY} scan={SCAN_SCRIPT}"
    )
    threads: list[threading.Thread] = []

    if WORKER_ROLE in ("both", "post"):
        for idx in range(POST_CONCURRENCY):
            thread = threading.Thread(
                target=post_worker_loop,
                args=(idx + 1,),
                name=f"kitelon-post-{idx + 1}",
                daemon=True,
            )
            thread.start()
            threads.append(thread)

    if WORKER_ROLE in ("both", "scan"):
        scan_thread = threading.Thread(
            target=scan_worker_loop,
            name="kitelon-scan",
            daemon=True,
        )
        scan_thread.start()
        threads.append(scan_thread)

    if not threads:
        raise SystemExit(f"invalid WORKER_ROLE={WORKER_ROLE!r} (use both, scan, or post)")

    try:
        while True:
            _stop.wait(3600)
    except KeyboardInterrupt:
        _stop.set()


def run_once() -> None:
    recover()
    if WORKER_ROLE in ("both", "post") and execute_one("post"):
        return
    if WORKER_ROLE in ("both", "scan"):
        execute_one("scan")


def main() -> None:
    parser = argparse.ArgumentParser(description="Kitelon job worker")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run", help="Daemon loop (scan + post pools)")
    sub.add_parser("run-once", help="Single tick (cron)")
    sub.add_parser("recover", help="Reset stuck jobs and promote schedules")
    args = parser.parse_args()

    if args.cmd == "run":
        _worker_logger.info(
            "worker started role=%s poll=%ss post_concurrency=%s",
            WORKER_ROLE,
            POLL_SEC,
            POST_CONCURRENCY,
        )
        run_daemon()
    elif args.cmd == "run-once":
        run_once()
    elif args.cmd == "recover":
        recover()


if __name__ == "__main__":
    main()
