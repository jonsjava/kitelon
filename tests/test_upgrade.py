"""Tests for safe-upgrade support: queue pause/drain and job requeue/recover."""

from __future__ import annotations

import json

import pytest

import kitelon_db
import kitelon_upgrade


# --- fakes -------------------------------------------------------------------


class FakeResult:
    def __init__(self, rows=None, rowcount=0):
        self._rows = rows or []
        self.rowcount = rowcount

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class FakeConn:
    """Answers the handful of queries requeue/recover issue; records writes."""

    def __init__(self, jobs=None, running=None, paused=False):
        self.jobs = {j["id"]: dict(j) for j in (jobs or [])}
        self.running = running or []
        self.paused = paused
        self.updates: list[tuple[str, tuple]] = []

    def execute(self, sql, params=()):
        q = " ".join(sql.split())
        if q.startswith("SELECT to_regclass"):
            return FakeResult([{"t": "kitelon_settings"}])
        if q.startswith("SELECT value FROM kitelon_settings"):
            return FakeResult([{"value": "1" if self.paused else "0"}])
        if q.startswith("SELECT id, job_type, args_json"):
            job = self.jobs.get(params[0])
            return FakeResult([job] if job and job.get("status") == "running" else [])
        if q.startswith("SELECT id, pid,"):
            return FakeResult(self.running)
        if q.startswith("UPDATE jobs"):
            self.updates.append((q, params))
            return FakeResult(rowcount=1)
        raise AssertionError(f"unexpected query: {q}")


@pytest.fixture(autouse=True)
def _no_pause_file(tmp_path, monkeypatch):
    monkeypatch.setattr(kitelon_db, "PAUSE_FILE", tmp_path / "paused")


# --- requeue -----------------------------------------------------------------


def _scan_job(**kw):
    job = {
        "id": 7,
        "status": "running",
        "job_type": "scan",
        "args_json": {"extra_args": ["-o"]},
        "attempts": 1,
    }
    job.update(kw)
    return job


def test_requeue_scan_adds_resume_flag_and_goes_pending():
    conn = FakeConn(jobs=[_scan_job()])
    assert kitelon_db.requeue_job(conn, 7, reason="worker stopped") == "requeued"
    sql, params = conn.updates[-1]
    assert "status = %s" in sql
    status, args_json = params[0], json.loads(params[1])
    assert status == "pending"
    assert args_json["extra_args"] == ["-o", "-rr"]
    assert "attempt 1 of 3" in params[2]


def test_requeue_keeps_existing_resume_flag_and_holds_when_paused():
    conn = FakeConn(jobs=[_scan_job(args_json={"extra_args": "-rr -o"})], paused=True)
    kitelon_db.requeue_job(conn, 7, reason="x")
    _, params = conn.updates[-1]
    assert params[0] == "held"
    assert json.loads(params[1])["extra_args"] == ["-rr", "-o"]


def test_requeue_post_job_does_not_add_resume_flag():
    conn = FakeConn(jobs=[_scan_job(job_type="loot_process", args_json={})])
    kitelon_db.requeue_job(conn, 7, reason="x")
    _, params = conn.updates[-1]
    assert json.loads(params[1]) == {}


def test_requeue_gives_up_at_retry_cap():
    conn = FakeConn(jobs=[_scan_job(attempts=3)])
    assert kitelon_db.requeue_job(conn, 7, reason="worker stopped", max_attempts=3) == "failed"
    sql, params = conn.updates[-1]
    assert "status = 'failed'" in sql
    assert "gave up after 3 attempt(s)" in params[0]


def test_requeue_skips_jobs_that_are_no_longer_running():
    conn = FakeConn(jobs=[_scan_job(status="completed")])
    assert kitelon_db.requeue_job(conn, 7, reason="x") == "skipped"
    assert conn.updates == []


# --- recover -----------------------------------------------------------------


def _recover(monkeypatch, running, alive_pids=(), jobs=None):
    terminated = []
    monkeypatch.setattr(kitelon_db, "_pid_alive", lambda pid: pid in alive_pids)
    monkeypatch.setattr(kitelon_db, "_terminate_process_group", terminated.append)
    conn = FakeConn(jobs=jobs or [_scan_job(id=r["id"]) for r in running], running=running)
    count = kitelon_db.recover_stuck_jobs(conn, 10)
    return count, terminated, conn


def test_recover_leaves_fresh_jobs_alone_even_with_live_process(monkeypatch):
    running = [{"id": 1, "pid": 100, "stale": False, "past_grace": True}]
    count, terminated, conn = _recover(monkeypatch, running, alive_pids={100})
    assert count == 0 and terminated == [] and conn.updates == []


def test_recover_requeues_dead_process_after_grace(monkeypatch):
    running = [{"id": 1, "pid": 100, "stale": False, "past_grace": True}]
    count, terminated, conn = _recover(monkeypatch, running)
    assert count == 1 and terminated == []
    assert "worker process exited" in conn.updates[-1][1][2]


def test_recover_waits_out_grace_for_just_exited_process(monkeypatch):
    running = [{"id": 1, "pid": 100, "stale": False, "past_grace": False}]
    count, _, conn = _recover(monkeypatch, running)
    assert count == 0 and conn.updates == []


def test_recover_stops_and_requeues_unwatched_stale_process(monkeypatch):
    running = [{"id": 1, "pid": 100, "stale": True, "past_grace": True}]
    count, terminated, conn = _recover(monkeypatch, running, alive_pids={100})
    assert count == 1 and terminated == [100]
    assert "stopped heartbeating" in conn.updates[-1][1][2]


# --- pause / drain -----------------------------------------------------------


def test_file_mode_pause_and_resume(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_ENABLED", "0")
    queue = kitelon_upgrade.Queue()
    assert not queue.db and not queue.is_paused()
    queue.pause()
    assert kitelon_db.PAUSE_FILE.exists() and queue.is_paused()
    queue.resume()
    assert not queue.is_paused()


@pytest.mark.parametrize(
    ("value", "expected"),
    [("1", True), ('"1"', True), ("0", False), ("false", False), ("", False)],
)
def test_uses_db_reads_env(monkeypatch, value, expected):
    monkeypatch.setenv("DB_ENABLED", value)
    assert kitelon_upgrade.uses_db() is expected


class FakeQueue:
    def __init__(self, running_sequence):
        self.seq = list(running_sequence)
        self.paused = False

    def pause(self, hold_pending=True):
        self.paused = True
        return 2

    def running_jobs(self):
        return self.seq.pop(0) if len(self.seq) > 1 else self.seq[0]


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _job(i):
    return {"id": i, "job_type": "scan", "mode": "normal", "target": "example.com"}


def test_drain_returns_when_work_finishes(monkeypatch):
    monkeypatch.setattr(kitelon_upgrade, "local_scan_processes", lambda: [])
    queue = FakeQueue([[_job(1)], [_job(1)], []])
    clock = FakeClock()
    rc = kitelon_upgrade.drain(queue, interval=15, sleep=clock.sleep, clock=clock)
    assert rc == kitelon_upgrade.EXIT_OK
    assert queue.paused and clock.now == 30


def test_drain_times_out_and_stays_paused(monkeypatch):
    monkeypatch.setattr(kitelon_upgrade, "local_scan_processes", lambda: [])
    queue = FakeQueue([[_job(1)]])
    clock = FakeClock()
    rc = kitelon_upgrade.drain(queue, timeout=40, interval=15, sleep=clock.sleep, clock=clock)
    assert rc == kitelon_upgrade.EXIT_TIMEOUT
    assert queue.paused and clock.now == 40


def test_drain_waits_on_direct_cli_scans(monkeypatch):
    procs = [[{"pid": 5, "cmd": "python3 kitelon_scan.py"}], []]
    monkeypatch.setattr(kitelon_upgrade, "local_scan_processes", lambda: procs.pop(0))
    queue = FakeQueue([[]])
    clock = FakeClock()
    assert kitelon_upgrade.drain(queue, interval=5, sleep=clock.sleep, clock=clock) == 0
    assert clock.now == 5
