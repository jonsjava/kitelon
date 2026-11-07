#!/usr/bin/env python3
# Polls PostgreSQL for pending jobs; runs kitelon_scan / loot import subprocesses.

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
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
    queue_paused,
    recover_stuck_jobs,
    requeue_job,
    set_job_pid,
    touch_heartbeat,
    touch_job_heartbeat,
)
from kitelon_log import get_logger  # noqa: E402

INSTALL_DIR = Path(os.environ.get("KITELON_INSTALL_DIR", "/usr/share/kitelon"))
SCAN_SCRIPT = Path(os.environ.get("KITELON_SCAN_SCRIPT", INSTALL_DIR / "bin" / "kitelon_scan.py"))
POLL_SEC = int(os.environ.get("WORKER_POLL_SEC", "10"))
# A running job whose heartbeat is older than this is treated as orphaned and
# requeued. Workers touch the heartbeat every HEARTBEAT_SEC, so keep this well
# above it. (Replaces the old 180-minute WORKER_STUCK_MINUTES cutoff.)
STALE_MINUTES = int(os.environ.get("WORKER_STALE_MINUTES", "10"))
# Must stay below recover's 2-minute dead-process grace: in Docker the recover
# sidecar can't see the worker's PIDs, so a fresh heartbeat is what keeps it
# from requeueing a scan that is still running.
HEARTBEAT_SEC = max(1, int(os.environ.get("WORKER_HEARTBEAT_SEC", "30")))
# How long a stopping worker waits for running jobs to exit before requeueing
# them anyway. Keep below systemd's TimeoutStopSec / Docker's stop_grace_period.
SHUTDOWN_GRACE_SEC = int(os.environ.get("WORKER_SHUTDOWN_GRACE_SEC", "60"))
POST_CONCURRENCY = max(1, int(os.environ.get("WORKER_POST_CONCURRENCY", "2")))
WORKER_ROLE = os.environ.get("WORKER_ROLE", "both").lower()

_worker_logger = get_logger("worker")

_stop = threading.Event()

# job_id -> subprocess currently running for it, so shutdown can stop them.
_active: dict[int, subprocess.Popen] = {}
_active_lock = threading.RLock()  # re-entrant: the signal handler takes it too


def _run_job_process(
    job_id: int, cmd: list[str], *, capture_stdout: bool = True
) -> tuple[int, str, str]:
    """Run a job's subprocess in its own session, tracked for shutdown."""
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    with _active_lock:
        _active[job_id] = proc
    try:
        if _stop.is_set():
            # Shutdown began between claim and start: don't run the job.
            _terminate(proc)
        with get_connection() as conn:
            set_job_pid(conn, job_id, proc.pid)
        stdout, stderr = proc.communicate()
    finally:
        with _active_lock:
            _active.pop(job_id, None)
    return proc.returncode, stdout or "", stderr or ""


def _terminate(proc: subprocess.Popen, sig: int = signal.SIGTERM) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.send_signal(sig)
        except (ProcessLookupError, OSError):
            pass


@contextmanager
def job_heartbeat(job_id: int, interval: float = HEARTBEAT_SEC):
    """Touch ``jobs.heartbeat_at`` every ``interval`` seconds while the job runs."""
    done = threading.Event()

    def beat() -> None:
        while not done.wait(interval):
            try:
                with get_connection() as conn:
                    touch_job_heartbeat(conn, job_id)
            except Exception as exc:
                log(f"job {job_id} heartbeat failed: {exc}")

    thread = threading.Thread(target=beat, name=f"kitelon-beat-{job_id}", daemon=True)
    thread.start()
    try:
        yield
    finally:
        done.set()
        thread.join(timeout=5)


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
    code, stdout, stderr = _run_job_process(
        int(job["id"]),
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
    )
    err = stderr.strip() or stdout.strip()
    return code, err


def run_job(job: dict) -> tuple[int, str]:
    job_type = job["job_type"]
    job_id = int(job["id"])

    if job_type in ("reimport", "loot_process", "report"):
        return run_loot_job(job)

    if job_type == "scan":
        if not job.get("workspace_alias"):
            return 1, "scan job missing workspace"
        cmd = build_scan_command(job)
        code, _stdout, stderr = _run_job_process(job_id, cmd, capture_stdout=False)
        err = stderr.strip()
        if len(err) > 8000:
            err = err[:8000] + "…"
        if code == 0 and job.get("workspace_alias"):
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
        return code, err

    return 1, f"unknown job_type: {job_type}"


def execute_one(role: str) -> bool:
    if _stop.is_set():
        return False
    with get_connection() as conn:
        if queue_paused(conn):
            return False
        exclude = get_running_scan_workspace_ids(conn) or None
        job = claim_next_job(conn, role=role, exclude_workspace_ids=exclude)
    if not job:
        return False

    job_id = int(job["id"])
    log(f"[{role}] running job {job_id} type={job['job_type']} target={job.get('target')}")
    with job_heartbeat(job_id):
        try:
            code, err = run_job(job)
        except Exception as exc:
            code, err = 1, str(exc)

    if code != 0 and _stop.is_set():
        # Interrupted by worker shutdown: put it back instead of failing it.
        with get_connection() as conn:
            outcome = requeue_job(conn, job_id, reason="worker shut down")
            touch_heartbeat(conn, job_id, f"{role}: {outcome} on shutdown")
        log(f"[{role}] job {job_id} interrupted by shutdown: {outcome}")
        return True

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
        stuck = recover_stuck_jobs(conn, STALE_MINUTES)
        promoted = promote_schedules(conn)
        touch_heartbeat(conn, None, f"recover stuck={stuck} promoted={promoted}")
    log(f"recover: stuck={stuck} schedules_promoted={promoted}")


def _request_stop(signum: int, _frame: object) -> None:
    """SIGTERM/SIGINT: stop claiming and stop the running jobs' processes."""
    if not _stop.is_set():
        log(f"worker received signal {signum}; stopping running jobs to requeue them")
    _stop.set()
    with _active_lock:
        procs = list(_active.values())
    for proc in procs:
        _terminate(proc)


def shutdown(threads: list[threading.Thread], grace: float = SHUTDOWN_GRACE_SEC) -> None:
    """Wait for worker threads to requeue their jobs; force it after ``grace``."""
    _stop.set()
    deadline = time.monotonic() + grace
    for thread in threads:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
    with _active_lock:
        leftover = dict(_active)
    if not leftover:
        log("worker stopped")
        return
    for proc in leftover.values():
        _terminate(proc, signal.SIGKILL)
    with get_connection() as conn:
        for job_id in leftover:
            outcome = requeue_job(conn, job_id, reason="worker shut down (forced)")
            log(f"job {job_id} did not stop within {grace:.0f}s: {outcome}")


def run_daemon() -> None:
    log(
        f"worker started role={WORKER_ROLE} poll={POLL_SEC}s "
        f"post_concurrency={POST_CONCURRENCY} scan={SCAN_SCRIPT}"
    )
    if WORKER_ROLE not in ("both", "scan", "post"):
        raise SystemExit(f"invalid WORKER_ROLE={WORKER_ROLE!r} (use both, scan, or post)")
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)

    # Requeue jobs orphaned by a previous worker (crash, kill, reboot) now
    # instead of waiting for the next recover run.
    try:
        recover()
    except Exception as exc:
        log(f"startup recover failed: {exc}")

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

    while not _stop.wait(3600):
        pass
    shutdown(threads)


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
