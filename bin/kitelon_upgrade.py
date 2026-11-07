#!/usr/bin/env python3
"""Pause the job queue and drain running work so Kitelon can be upgraded safely.

Pause storage follows DB_ENABLED: a PostgreSQL setting when the database is
enabled (pending jobs move to 'held' so no worker, old or new, claims them),
otherwise a flag file (KITELON_PAUSE_FILE, default /var/lib/kitelon/paused).

Commands:
  status            Show pause state and running work
  pause             Pause the queue (running work continues)
  resume            Resume the queue (held jobs become pending again)
  drain             Pause, then wait until no scan or job is running
  is-paused         Exit 0 if paused, 1 if not (for scripts)

drain exit codes: 0 drained, 2 timed out (still paused), 3 queue unavailable.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_BIN_DIR = Path(__file__).resolve().parent
if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))

import kitelon_db  # noqa: E402

EXIT_OK = 0
EXIT_NOT_PAUSED = 1
EXIT_TIMEOUT = 2
EXIT_UNAVAILABLE = 3

SCAN_PROCESS_MARKER = "kitelon_scan.py"


def uses_db() -> bool:
    """Resolve DB_ENABLED the way kitelon_db.db_config merges config sources."""
    value = os.environ.get("DB_ENABLED")
    if value is None:
        merged: dict[str, str] = {}
        for path in (kitelon_db.INSTALL_CONFIG, kitelon_db.ROOT_CONFIG):
            try:
                merged.update(kitelon_db.load_key_value_file(path))
            except OSError:
                continue
        value = merged.get("DB_ENABLED", "1")
    return str(value).strip().strip('"').strip("'") not in ("0", "false", "False", "")


def pause_file() -> Path:
    return kitelon_db.PAUSE_FILE


def local_scan_processes() -> list[dict[str, Any]]:
    """Kitelon scan processes on this host (direct CLI scans and worker scans)."""
    procs: list[dict[str, Any]] = []
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return procs
    own = os.getpid()
    for entry in proc_root.iterdir():
        if not entry.name.isdigit() or int(entry.name) == own:
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if not raw:
            continue
        argv = [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]
        if any(a.endswith(SCAN_PROCESS_MARKER) for a in argv):
            procs.append({"pid": int(entry.name), "cmd": " ".join(argv)[:160]})
    return procs


def _age(started: Any) -> str:
    if not isinstance(started, datetime):
        return "?"
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    minutes = int((datetime.now(timezone.utc) - started).total_seconds() // 60)
    return f"{minutes // 60}h{minutes % 60:02d}m" if minutes >= 60 else f"{minutes}m"


class Queue:
    """Pause/resume/running-work operations for the configured backend."""

    def __init__(self) -> None:
        self.db = uses_db()

    # -- pause flag -------------------------------------------------------
    def is_paused(self) -> bool:
        if pause_file().exists():
            return True
        if not self.db:
            return False
        with kitelon_db.get_connection() as conn:
            return kitelon_db.queue_paused(conn)

    def pause(self, *, hold_pending: bool = True) -> int:
        if not self.db:
            path = pause_file()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(datetime.now(timezone.utc).isoformat() + "\n")
            return 0
        with kitelon_db.get_connection() as conn:
            return kitelon_db.set_queue_paused(conn, True, hold_pending=hold_pending)

    def resume(self) -> int:
        released = 0
        if self.db:
            with kitelon_db.get_connection() as conn:
                released = kitelon_db.set_queue_paused(conn, False)
        try:
            pause_file().unlink()
        except FileNotFoundError:
            pass
        return released

    # -- running work -----------------------------------------------------
    def running_jobs(self) -> list[dict[str, Any]]:
        if not self.db:
            return []
        with kitelon_db.get_connection() as conn:
            return kitelon_db.list_running_jobs(conn)

    def held_count(self) -> int:
        if not self.db:
            return 0
        with kitelon_db.get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM jobs WHERE status = 'held'"
            ).fetchone()
            return int(row["n"]) if row else 0


def _describe_jobs(jobs: list[dict[str, Any]]) -> list[str]:
    lines = []
    for job in jobs:
        what = job.get("job_type") or "job"
        if job.get("mode"):
            what += f" {job['mode']}"
        target = job.get("target") or job.get("workspace_alias") or ""
        lines.append(
            f"  #{job['id']} {what} {target} (running {_age(job.get('started_at'))})".rstrip()
        )
    return lines


def cmd_status(queue: Queue) -> int:
    paused = queue.is_paused()
    print(f"queue: {'PAUSED' if paused else 'running'} (backend: {'database' if queue.db else 'file'})")
    jobs = queue.running_jobs()
    procs = local_scan_processes()
    if queue.db:
        print(f"held jobs: {queue.held_count()}")
    print(f"running jobs: {len(jobs)}")
    for line in _describe_jobs(jobs):
        print(line)
    print(f"local scan processes: {len(procs)}")
    for proc in procs:
        print(f"  pid {proc['pid']}: {proc['cmd']}")
    return EXIT_OK


def drain(
    queue: Queue,
    *,
    timeout: float = 0,
    interval: float = 15,
    sleep=time.sleep,
    clock=time.monotonic,
) -> int:
    """Pause the queue and wait until nothing is running.

    Returns EXIT_OK when drained, EXIT_TIMEOUT when ``timeout`` (seconds, 0 =
    wait forever) runs out. The queue stays paused either way; the caller
    resumes it.
    """
    held = queue.pause()
    note = f", {held} queued job(s) held" if held else ""
    print(f"queue paused{note}; waiting for running work to finish", flush=True)
    start = clock()
    while True:
        jobs = queue.running_jobs()
        procs = local_scan_processes()
        if not jobs and not procs:
            print("drained: nothing is running", flush=True)
            return EXIT_OK
        elapsed = clock() - start
        parts = []
        if jobs:
            parts.append(f"{len(jobs)} job(s)")
        if procs:
            parts.append(f"{len(procs)} scan process(es)")
        print(f"waiting on {' and '.join(parts)} [{int(elapsed)}s]", flush=True)
        for line in _describe_jobs(jobs):
            print(line, flush=True)
        if timeout and elapsed >= timeout:
            print(f"timed out after {int(timeout)}s; queue is still paused", flush=True)
            return EXIT_TIMEOUT
        wait = interval if not timeout else max(0.0, min(interval, timeout - elapsed))
        sleep(wait)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kitelon upgrade",
        description="Pause the job queue and drain running work for a safe upgrade",
    )
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("status", help="Show pause state and running work")
    p_pause = sub.add_parser("pause", help="Pause the queue")
    p_pause.add_argument(
        "--no-hold",
        action="store_true",
        help="Set the flag only; leave queued jobs as pending",
    )
    sub.add_parser("resume", help="Resume the queue")
    p_drain = sub.add_parser("drain", help="Pause and wait until nothing is running")
    p_drain.add_argument("--timeout", type=float, default=0, help="Seconds to wait (0 = forever)")
    p_drain.add_argument("--interval", type=float, default=15, help="Seconds between checks")
    p_drain.add_argument(
        "--resume-on-timeout",
        action="store_true",
        help="Resume the queue if the timeout runs out",
    )
    sub.add_parser("is-paused", help="Exit 0 if paused, 1 if not")
    args = parser.parse_args(argv)
    cmd = args.cmd or "status"

    queue = Queue()
    try:
        if cmd == "status":
            return cmd_status(queue)
        if cmd == "is-paused":
            return EXIT_OK if queue.is_paused() else EXIT_NOT_PAUSED
        if cmd == "pause":
            held = queue.pause(hold_pending=not args.no_hold)
            print(f"queue paused{f'; {held} queued job(s) held' if held else ''}")
            return EXIT_OK
        if cmd == "resume":
            released = queue.resume()
            print(f"queue resumed{f'; {released} held job(s) released' if released else ''}")
            return EXIT_OK
        if cmd == "drain":
            try:
                rc = drain(queue, timeout=args.timeout, interval=args.interval)
            except KeyboardInterrupt:
                queue.resume()
                print("\ninterrupted; queue resumed", file=sys.stderr)
                return 130
            if rc == EXIT_TIMEOUT and args.resume_on_timeout:
                queue.resume()
                print("queue resumed")
            return rc
    except kitelon_db.DatabaseError as exc:
        print(f"job queue unavailable: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE
    except Exception as exc:  # noqa: BLE001 - psycopg connection errors etc.
        if cmd == "is-paused":
            return EXIT_NOT_PAUSED
        print(f"job queue unavailable: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
