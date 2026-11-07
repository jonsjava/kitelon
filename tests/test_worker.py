"""Tests for the worker's heartbeat, pause check, startup recover and shutdown requeue."""

from __future__ import annotations

import os
import signal
import sys
import tempfile
import threading
import time
from contextlib import contextmanager

os.environ.setdefault("LOG_DIR", tempfile.mkdtemp(prefix="kitelon-test-logs-"))

import pytest

import kitelon_worker as worker


class Recorder:
    """Stands in for the kitelon_db calls the worker makes; records them."""

    def __init__(self, job=None, paused=False):
        self.job = job
        self.paused = paused
        self.calls: list[tuple] = []

    def install(self, monkeypatch):
        @contextmanager
        def get_connection():
            yield object()

        def rec(name, result=None):
            def fn(_conn, *args, **kw):
                self.calls.append((name, args, kw))
                return result

            return fn

        monkeypatch.setattr(worker, "get_connection", get_connection)
        monkeypatch.setattr(worker, "queue_paused", lambda _c: self.paused)
        monkeypatch.setattr(worker, "get_running_scan_workspace_ids", lambda _c: set())
        monkeypatch.setattr(worker, "claim_next_job", rec("claim", self.job))
        monkeypatch.setattr(worker, "complete_job", rec("complete"))
        monkeypatch.setattr(worker, "requeue_job", rec("requeue", "requeued"))
        monkeypatch.setattr(worker, "touch_heartbeat", rec("heartbeat"))
        monkeypatch.setattr(worker, "touch_job_heartbeat", rec("job_heartbeat"))
        monkeypatch.setattr(worker, "set_job_pid", rec("set_pid"))
        return self

    def names(self):
        return [c[0] for c in self.calls]


@pytest.fixture(autouse=True)
def _reset_worker_state():
    worker._stop.clear()
    worker._active.clear()
    yield
    worker._stop.clear()
    for proc in list(worker._active.values()):
        worker._terminate(proc, signal.SIGKILL)
    worker._active.clear()


JOB = {"id": 5, "job_type": "report", "workspace_alias": "demo", "target": None}


# --- heartbeat ---------------------------------------------------------------


def test_job_heartbeat_touches_while_running_and_stops_after(monkeypatch):
    rec = Recorder().install(monkeypatch)
    with worker.job_heartbeat(5, interval=0.02):
        time.sleep(0.15)
    beats = rec.names().count("job_heartbeat")
    assert beats >= 3
    assert all(c[1] == (5,) for c in rec.calls)
    time.sleep(0.08)
    assert rec.names().count("job_heartbeat") == beats


def test_heartbeat_interval_stays_inside_recover_grace():
    # recover requeues a job whose PID looks dead once its heartbeat is >120s
    # old; in Docker the sidecar can't see worker PIDs, so beats must be faster.
    assert worker.HEARTBEAT_SEC < 120
    assert worker.STALE_MINUTES * 60 > worker.HEARTBEAT_SEC * 2


# --- claiming ----------------------------------------------------------------


def test_execute_one_does_not_claim_while_paused(monkeypatch):
    rec = Recorder(job=JOB, paused=True).install(monkeypatch)
    assert worker.execute_one("post") is False
    assert "claim" not in rec.names()


def test_execute_one_does_not_claim_while_stopping(monkeypatch):
    rec = Recorder(job=JOB).install(monkeypatch)
    worker._stop.set()
    assert worker.execute_one("post") is False
    assert rec.calls == []


def test_execute_one_completes_finished_job(monkeypatch):
    rec = Recorder(job=JOB).install(monkeypatch)
    monkeypatch.setattr(worker, "run_job", lambda job: (0, ""))
    assert worker.execute_one("post") is True
    assert "complete" in rec.names() and "requeue" not in rec.names()


def test_execute_one_fails_job_normally_when_not_stopping(monkeypatch):
    rec = Recorder(job=JOB).install(monkeypatch)
    monkeypatch.setattr(worker, "run_job", lambda job: (2, "boom"))
    worker.execute_one("post")
    complete = [c for c in rec.calls if c[0] == "complete"]
    assert complete and complete[0][2]["exit_code"] == 2
    assert "requeue" not in rec.names()


def test_execute_one_requeues_job_interrupted_by_shutdown(monkeypatch):
    rec = Recorder(job=JOB).install(monkeypatch)

    def interrupted(job):
        worker._stop.set()
        return -signal.SIGTERM, ""

    monkeypatch.setattr(worker, "run_job", interrupted)
    assert worker.execute_one("post") is True
    requeue = [c for c in rec.calls if c[0] == "requeue"]
    assert requeue and requeue[0][1] == (5,)
    assert "shut down" in requeue[0][2]["reason"]
    assert "complete" not in rec.names()


def test_execute_one_keeps_result_of_job_that_finished_during_shutdown(monkeypatch):
    rec = Recorder(job=JOB).install(monkeypatch)

    def finished(job):
        worker._stop.set()
        return 0, ""

    monkeypatch.setattr(worker, "run_job", finished)
    worker.execute_one("post")
    assert "complete" in rec.names() and "requeue" not in rec.names()


# --- shutdown ----------------------------------------------------------------


def _sleeper():
    return [sys.executable, "-c", "import time; time.sleep(30)"]


def _start_tracked(job_id, cmd):
    result = {}

    def target():
        result["out"] = worker._run_job_process(job_id, cmd)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while job_id not in worker._active and time.monotonic() < deadline:
        time.sleep(0.01)
    assert job_id in worker._active
    return thread, result


def test_sigterm_handler_stops_running_job_process(monkeypatch):
    rec = Recorder().install(monkeypatch)
    thread, result = _start_tracked(9, _sleeper())
    worker._request_stop(signal.SIGTERM, None)
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert worker._stop.is_set()
    assert result["out"][0] == -signal.SIGTERM
    assert 9 not in worker._active
    assert rec.calls[0][0] == "set_pid" and rec.calls[0][1][0] == 9


def test_process_started_after_stop_is_terminated_immediately(monkeypatch):
    Recorder().install(monkeypatch)
    worker._stop.set()
    start = time.monotonic()
    code, _out, _err = worker._run_job_process(3, _sleeper())
    assert code == -signal.SIGTERM
    assert time.monotonic() - start < 5


def test_shutdown_forces_and_requeues_jobs_that_ignore_sigterm(monkeypatch):
    rec = Recorder().install(monkeypatch)
    stubborn = [
        sys.executable,
        "-c",
        "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)",
    ]
    thread, result = _start_tracked(11, stubborn)
    time.sleep(0.2)  # let the child install its SIG_IGN handler
    worker._request_stop(signal.SIGTERM, None)
    worker.shutdown([thread], grace=0.3)
    thread.join(timeout=5)
    assert result["out"][0] == -signal.SIGKILL
    requeue = [c for c in rec.calls if c[0] == "requeue"]
    assert requeue and requeue[0][1] == (11,)
    assert "forced" in requeue[0][2]["reason"]


# --- recover -----------------------------------------------------------------


def test_recover_uses_short_stale_window(monkeypatch):
    seen = {}
    Recorder().install(monkeypatch)
    monkeypatch.setattr(
        worker, "recover_stuck_jobs", lambda _c, minutes: seen.setdefault("m", minutes) and 0
    )
    monkeypatch.setattr(worker, "promote_schedules", lambda _c: 0)
    worker.recover()
    assert seen["m"] == worker.STALE_MINUTES == 10


def test_daemon_recovers_at_startup_and_installs_signal_handlers(monkeypatch):
    Recorder().install(monkeypatch)
    order = []
    handlers = {}
    monkeypatch.setattr(worker, "recover", lambda: order.append("recover"))
    monkeypatch.setattr(worker.signal, "signal", lambda sig, fn: handlers.setdefault(sig, fn))
    monkeypatch.setattr(worker, "WORKER_ROLE", "both")
    worker._stop.set()  # loops exit at once; run_daemon goes straight to shutdown
    worker.run_daemon()
    assert order == ["recover"]
    assert handlers[signal.SIGTERM] is worker._request_stop
    assert handlers[signal.SIGINT] is worker._request_stop
