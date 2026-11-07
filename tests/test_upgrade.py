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
        self.locks: list[tuple[str, tuple]] = []

    def execute(self, sql, params=()):
        q = " ".join(sql.split())
        if q.startswith("SELECT to_regclass"):
            return FakeResult([{"t": "kitelon_settings"}])
        if q.startswith("SELECT value FROM kitelon_settings"):
            return FakeResult([{"value": "1" if self.paused else "0"}])
        if q.startswith("SELECT pg_advisory"):
            self.locks.append((q, params))
            return FakeResult([{}])
        if q.startswith("SELECT id, job_type, args_json"):
            job = self.jobs.get(params[0])
            if not job or job.get("status") != "running":
                return FakeResult([])
            if len(params) > 1 and job.get("started_at") != params[1]:
                return FakeResult([])  # owner filter: a different run owns it
            return FakeResult([job])
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


def _requeue_update(conn):
    """(status, attempts, delay, args, message) from requeue_job's UPDATE."""
    sql, params = conn.updates[-1]
    assert "status = %s" in sql
    return params[0], params[1], params[2], json.loads(params[3]), params[4]


def test_requeue_scan_marks_resume_and_goes_pending():
    conn = FakeConn(jobs=[_scan_job()])
    assert kitelon_db.requeue_job(conn, 7, reason="worker stopped") == "requeued"
    status, attempts, delay, args, msg = _requeue_update(conn)
    assert status == "pending" and attempts == 1 and delay == 0
    # Resume is a separate key, not -rr in extra_args, so a later retry starts
    # fresh and jobs whose args carry "options" still resume.
    assert args["extra_args"] == ["-o"]
    assert args[kitelon_db.RESUME_ARG_KEY] is True
    assert "attempt 1 of 3" in msg
    assert conn.locks, "requeue must take the pause lock before reading the flag"


def test_requeue_holds_when_paused():
    conn = FakeConn(jobs=[_scan_job()], paused=True)
    kitelon_db.requeue_job(conn, 7, reason="x")
    assert _requeue_update(conn)[0] == "held"


def test_requeue_post_job_does_not_mark_resume():
    conn = FakeConn(jobs=[_scan_job(job_type="loot_process", args_json={})])
    kitelon_db.requeue_job(conn, 7, reason="x")
    assert _requeue_update(conn)[3] == {}


def test_requeue_gives_up_at_retry_cap():
    conn = FakeConn(jobs=[_scan_job(attempts=3)])
    assert kitelon_db.requeue_job(conn, 7, reason="worker stopped", max_attempts=3) == "failed"
    sql, params = conn.updates[-1]
    assert "status = 'failed'" in sql
    assert "gave up after 3 attempt(s)" in params[0]


def test_uncounted_requeue_gives_the_attempt_back_and_ignores_the_cap():
    conn = FakeConn(jobs=[_scan_job(attempts=3)])
    outcome = kitelon_db.requeue_job(
        conn, 7, reason="worker shut down", max_attempts=3, count_attempt=False
    )
    assert outcome == "requeued"
    status, attempts, _delay, _args, msg = _requeue_update(conn)
    assert status == "pending" and attempts == 2
    assert "not counted" in msg


def test_requeue_with_claim_skips_a_job_another_run_owns():
    conn = FakeConn(jobs=[_scan_job(started_at="run-2")])
    assert kitelon_db.requeue_job(conn, 7, reason="x", claim="run-1") == "skipped"
    assert conn.updates == []
    assert kitelon_db.requeue_job(conn, 7, reason="x", claim="run-2") == "requeued"


def test_requeue_skips_jobs_that_are_no_longer_running():
    conn = FakeConn(jobs=[_scan_job(status="completed")])
    assert kitelon_db.requeue_job(conn, 7, reason="x") == "skipped"
    assert conn.updates == []


def test_retry_starts_fresh_instead_of_resuming(monkeypatch):
    job = {
        "id": 7,
        "status": "failed",
        "job_type": "scan",
        "workspace_id": 1,
        "target": "example.com",
        "mode": "normal",
        "priority": 100,
        "args_json": {"extra_args": ["-rr"], kitelon_db.RESUME_ARG_KEY: True},
    }
    captured = {}
    monkeypatch.setattr(kitelon_db, "get_job", lambda conn, job_id: job)
    monkeypatch.setattr(
        kitelon_db, "enqueue_job", lambda conn, **kw: captured.update(kw) or 8
    )
    assert kitelon_db.retry_job(object(), 7) == 8
    # The user's own -rr stays; the requeue's resume marker does not.
    assert captured["args"] == {"extra_args": ["-rr"]}


# --- ownership -----------------------------------------------------------------


class OwnerConn:
    def __init__(self, rowcount):
        self.rowcount = rowcount
        self.calls = []

    def execute(self, sql, params=()):
        self.calls.append((" ".join(sql.split()), params))
        return FakeResult(rowcount=self.rowcount)


@pytest.mark.parametrize(
    "call",
    [
        lambda c: kitelon_db.complete_job(c, 7, exit_code=0, claim="run-1"),
        lambda c: kitelon_db.touch_job_heartbeat(c, 7, "run-1"),
        lambda c: kitelon_db.set_job_pid(c, 7, 99, claim="run-1"),
    ],
)
def test_owner_writes_are_scoped_to_the_claiming_run(call):
    conn = OwnerConn(rowcount=1)
    assert call(conn) is True
    sql, params = conn.calls[-1]
    assert "status = 'running' AND started_at = %s" in sql
    assert params[-1] == "run-1"
    # A run that lost the job gets False and changes nothing.
    assert call(OwnerConn(rowcount=0)) is False


def test_complete_without_claim_keeps_old_unconditional_update():
    conn = OwnerConn(rowcount=1)
    kitelon_db.complete_job(conn, 7, exit_code=1, error="x")
    assert "started_at" not in conn.calls[-1][0]


# --- recover -----------------------------------------------------------------


HERE = kitelon_db.WORKER_HOST


def _recover(monkeypatch, running, alive_pids=(), jobs=None):
    terminated = []
    monkeypatch.setattr(
        kitelon_db, "_job_process_alive", lambda pid, job_id: pid in alive_pids
    )
    monkeypatch.setattr(kitelon_db, "_terminate_process_group", terminated.append)
    conn = FakeConn(jobs=jobs or [_scan_job(id=r["id"]) for r in running], running=running)
    count = kitelon_db.recover_stuck_jobs(conn, 10)
    return count, terminated, conn


def _row(**kw):
    row = {"id": 1, "pid": 100, "worker_host": HERE, "stale": False, "past_grace": True}
    row.update(kw)
    return row


def test_recover_leaves_fresh_jobs_alone_even_with_live_process(monkeypatch):
    count, terminated, conn = _recover(monkeypatch, [_row()], alive_pids={100})
    assert count == 0 and terminated == [] and conn.updates == []


def test_recover_requeues_local_dead_process_after_grace(monkeypatch):
    count, terminated, conn = _recover(monkeypatch, [_row()])
    assert count == 1 and terminated == []
    status, _attempts, delay, _args, msg = _requeue_update(conn)
    assert "worker process exited" in msg and delay == 0


def test_recover_does_not_trust_pids_from_another_host(monkeypatch):
    # e.g. the Docker recover sidecar looking at a worker container's job: the
    # PID isn't visible here, which doesn't mean the scan is dead.
    count, terminated, conn = _recover(monkeypatch, [_row(worker_host="other-container")])
    assert count == 0 and terminated == [] and conn.updates == []


def test_recover_waits_out_grace_for_just_exited_process(monkeypatch):
    count, _, conn = _recover(monkeypatch, [_row(past_grace=False)])
    assert count == 0 and conn.updates == []


def test_recover_stops_and_requeues_unwatched_stale_process(monkeypatch):
    count, terminated, conn = _recover(
        monkeypatch, [_row(stale=True)], alive_pids={100}
    )
    assert count == 1 and terminated == [100]
    assert "stopped heartbeating" in _requeue_update(conn)[4]


def test_recover_never_signals_a_pid_it_cannot_verify(monkeypatch):
    # Stale job from another host whose PID number happens to exist locally.
    count, terminated, conn = _recover(
        monkeypatch, [_row(stale=True, worker_host="other-host")]
    )
    assert count == 1 and terminated == []
    # Its run may still be stopping elsewhere, so the requeue is delayed.
    assert _requeue_update(conn)[2] == kitelon_db.ORPHAN_REQUEUE_DELAY_SEC


def test_job_process_alive_rejects_unrelated_and_other_job_processes(monkeypatch, tmp_path):
    import os
    import subprocess
    import sys

    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    script = tmp_path / "kitelon_scan.py"
    script.write_text("import time; time.sleep(30)\n")
    scan = subprocess.Popen([sys.executable, str(script), "--job-id", "42"])
    try:
        assert kitelon_db._job_process_alive(unrelated.pid, 42) is False
        assert kitelon_db._job_process_alive(scan.pid, 41) is False
        if os.path.exists("/proc/self"):
            import time as _t

            for _ in range(50):  # wait for exec to land
                if kitelon_db._job_process_alive(scan.pid, 42):
                    break
                _t.sleep(0.02)
            assert kitelon_db._job_process_alive(scan.pid, 42) is True
    finally:
        unrelated.kill()
        scan.kill()
        unrelated.wait()
        scan.wait()


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


# --- helper CLI ----------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [["drain", "--timeout", "1h"], ["drain", "--timeout", "-5"], ["bogus"]],
)
def test_bad_arguments_exit_with_usage_code_not_timeout(argv, capsys):
    rc = kitelon_upgrade.main(argv)
    assert rc == kitelon_upgrade.EXIT_USAGE
    assert rc != kitelon_upgrade.EXIT_TIMEOUT


class _MainQueue:
    def __init__(self, paused):
        self.paused = paused
        self.resumed = 0

    def is_paused(self):
        return self.paused

    def resume(self):
        self.resumed += 1
        self.paused = False


@pytest.mark.parametrize(("already_paused", "resumes"), [(True, 0), (False, 1)])
def test_interrupted_drain_only_resumes_a_pause_it_made(monkeypatch, already_paused, resumes):
    queue = _MainQueue(already_paused)
    monkeypatch.setattr(kitelon_upgrade, "Queue", lambda: queue)

    def interrupted(*_a, **_kw):
        raise KeyboardInterrupt

    monkeypatch.setattr(kitelon_upgrade, "drain", interrupted)
    assert kitelon_upgrade.main(["drain"]) == 130
    assert queue.resumed == resumes


# --- direct scans ----------------------------------------------------------------


@pytest.fixture
def marker_dir(tmp_path, monkeypatch):
    path = tmp_path / "scans"
    monkeypatch.setenv("KITELON_SCAN_MARKER_DIR", str(path))
    monkeypatch.setenv("DB_ENABLED", "0")
    monkeypatch.setattr(kitelon_upgrade, "_proc_table", lambda: [])
    return path


def test_scan_guard_registers_scan_for_drains(marker_dir):
    import os

    with kitelon_upgrade.local_scan_guard("kitelon-cli scan x --sync"):
        markers = list(marker_dir.glob("*.json"))
        assert len(markers) == 1
        # The drain runs in another process, so it would see this one.
        seen = kitelon_upgrade._marker_scans()
        assert [m["pid"] for m in seen] == [os.getpid()]
    assert list(marker_dir.glob("*.json")) == []


def test_scan_guard_refuses_while_paused(marker_dir):
    kitelon_db.PAUSE_FILE.write_text("x")
    ran = []
    with pytest.raises(kitelon_upgrade.ScanBlocked):
        with kitelon_upgrade.local_scan_guard("scan"):
            ran.append(1)
    assert ran == [] and list(marker_dir.glob("*.json")) == []


def test_stale_markers_are_cleaned_up(marker_dir):
    marker_dir.mkdir()
    (marker_dir / "999999.json").write_text('{"pid": 999999, "cmd": "gone"}')
    assert kitelon_upgrade._marker_scans() == []
    assert not (marker_dir / "999999.json").exists()


def test_sync_cli_scan_is_blocked_while_paused(marker_dir, monkeypatch):
    services = pytest.importorskip("kitelon_engine.cli.services")
    kitelon_db.PAUSE_FILE.write_text("x")
    started = []
    monkeypatch.setattr(services, "run_scan", lambda **kw: started.append(kw) or 0)
    with pytest.raises(services.CliError, match="paused"):
        services.run_sync_scan(target="example.com", workspace="demo", mode="normal")
    assert started == []


def test_stop_local_leaves_worker_job_scans_to_their_worker(monkeypatch):
    killed = []
    monkeypatch.setattr(
        kitelon_upgrade,
        "local_scan_processes",
        lambda: [
            {"pid": 10, "cmd": "kitelon_scan.py -t a", "job": False},
            {"pid": 11, "cmd": "kitelon_scan.py --job-id 4", "job": True},
        ],
    )
    monkeypatch.setattr(kitelon_upgrade.os, "kill", lambda pid, sig: killed.append(pid))
    assert kitelon_upgrade.stop_local_scans() == [10]
    assert killed == [10]


def test_local_scan_processes_flags_job_scans(monkeypatch, marker_dir):
    monkeypatch.setattr(
        kitelon_upgrade,
        "_proc_table",
        lambda: [
            (10, ["python3", "/x/kitelon_scan.py", "-t", "a"]),
            (11, ["python3", "/x/kitelon_scan.py", "--job-id", "4"]),
            (12, ["python3", "other.py"]),
        ],
    )
    procs = {p["pid"]: p["job"] for p in kitelon_upgrade.local_scan_processes()}
    assert procs == {10: False, 11: True}
