"""
Tests for step-5 capture-on-hit semantics.

Doesn't spin up the real StopWatcher thread — that's validated live. These
tests exercise:
  - capture_on_hit validation (unknown bp_id, bad captures)
  - get_capture_log predicate filtering
  - clear_capture_log
  - stop_capturing flips auto_continue off and tries to stop the watcher
  - wait_for_hit refuses while the watcher is running
"""
from __future__ import annotations

import pytest

from dolphin_re_mcp import session as session_mod
from dolphin_re_mcp.session import SessionState
from dolphin_re_mcp.tools import breakpoint_tools, execution_tools


class FakeStub:
    """Minimal stub: only the bits the capture flow touches."""

    def __init__(self):
        self.calls: list = []
        self.sock = object()

    def probe_responsive(self, timeout: float = 0.5) -> bool:
        return True

    def add_write_watchpoint(self, addr, size):
        self.calls.append(("Z2", addr, size))
        return "OK"

    def remove_write_watchpoint(self, addr, size):
        self.calls.append(("z2", addr, size))
        return "OK"

    def continue_async(self):
        self.calls.append(("c",))

    def interrupt(self):
        self.calls.append(("interrupt",))

    def wait_for_stop(self, timeout=None):
        return "T0540:80004304;01:81560000;"

    def drain_pending_replies(self):
        return []

    def drain_stop_replies(self, max_wait_s=0.1):
        return []

    def read_register(self, regnum):
        return 0x80004304

    def read_registers(self):
        return b"\x00" * 128


class FakeWatcher:
    """Stand-in for StopWatcher — pretend to be alive."""

    def __init__(self):
        self._alive = True

    def is_alive(self):
        return self._alive

    def stop(self):
        self._alive = False

    def join(self, timeout=None):
        pass


@pytest.fixture
def session_for_capture(monkeypatch):
    s = session_mod.Session()
    s.ensure_connected = lambda: None  # type: ignore[assignment]
    s.stub = FakeStub()
    s.state = SessionState.CONNECTED_PAUSED
    s.watcher = None
    monkeypatch.setattr(session_mod, "_session", s)
    return s


# Prevent the real watcher thread from being started in tests.
@pytest.fixture(autouse=True)
def stub_watcher_module(monkeypatch):
    import dolphin_re_mcp.stop_watcher as sw

    started: list = []

    def fake_ensure(session):
        if session.watcher is None:
            session.watcher = FakeWatcher()
            started.append(session.watcher)
        return session.watcher

    def fake_stop(session, timeout=2.0):
        if session.watcher:
            session.watcher.stop()
            session.watcher = None

    monkeypatch.setattr(sw, "ensure_watcher_running", fake_ensure)
    monkeypatch.setattr(sw, "stop_watcher", fake_stop)
    return started


def test_capture_on_hit_unknown_bp_id(session_for_capture):
    with pytest.raises(breakpoint_tools.BreakpointNotFound):
        breakpoint_tools.capture_on_hit(999)


def test_capture_on_hit_invalid_capture_key(session_for_capture):
    wp = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    with pytest.raises(breakpoint_tools.CaptureError):
        breakpoint_tools.capture_on_hit(wp["id"], captures=["junk"])


def test_capture_on_hit_marks_spec_and_starts_watcher(session_for_capture):
    s = session_for_capture
    wp = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    out = breakpoint_tools.capture_on_hit(wp["id"], captures=["gprs", "lr"])
    spec = s.breakpoints[wp["id"]]
    assert spec.auto_continue is True
    assert spec.captures == ["gprs", "lr"]
    assert out["watcher_running"] is True
    assert isinstance(s.watcher, FakeWatcher)


def test_capture_on_hit_default_captures_gprs(session_for_capture):
    s = session_for_capture
    wp = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    breakpoint_tools.capture_on_hit(wp["id"])
    assert s.breakpoints[wp["id"]].captures == ["gprs"]


def test_capture_on_hit_auto_resumes_when_paused(session_for_capture):
    s = session_for_capture
    s.state = SessionState.CONNECTED_PAUSED
    wp = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    breakpoint_tools.capture_on_hit(wp["id"], auto_resume=True)
    assert s.state == SessionState.CONNECTED_RUNNING
    # `c` was sent
    assert ("c",) in s.stub.calls


def test_get_capture_log_returns_entries(session_for_capture):
    s = session_for_capture
    wp = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    bp_id = wp["id"]
    s.breakpoints[bp_id].log = [
        {"pc": 0x80004304, "r3": 0xAA, "r4": 1},
        {"pc": 0x800042FC, "r3": 0xBB, "r4": 2},
    ]
    out = breakpoint_tools.get_capture_log(bp_id)
    assert len(out) == 2


def test_get_capture_log_where_predicate(session_for_capture):
    s = session_for_capture
    wp = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    bp_id = wp["id"]
    s.breakpoints[bp_id].log = [
        {"pc": 0x80004304, "r3": 0xAA, "r4": 1},
        {"pc": 0x800042FC, "r3": 0xBB, "r4": 2},
        {"pc": 0x80004304, "r3": 0xCC, "r4": 2},
    ]
    out = breakpoint_tools.get_capture_log(bp_id, where="pc == 0x80004304")
    assert len(out) == 2
    assert all(e["pc"] == 0x80004304 for e in out)


def test_get_capture_log_predicate_with_range(session_for_capture):
    s = session_for_capture
    wp = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    bp_id = wp["id"]
    s.breakpoints[bp_id].log = [
        {"pc": 0x80004304, "r3": 0x806ADAB0},
        {"pc": 0x80004304, "r3": 0x90000000},
    ]
    out = breakpoint_tools.get_capture_log(
        bp_id, where="r3 in range(0x806adab0, 0x806adac0)"
    )
    assert len(out) == 1
    assert out[0]["r3"] == 0x806ADAB0


def test_get_capture_log_limit(session_for_capture):
    s = session_for_capture
    wp = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    bp_id = wp["id"]
    s.breakpoints[bp_id].log = [{"pc": i} for i in range(10)]
    out = breakpoint_tools.get_capture_log(bp_id, limit=3)
    # tail-3 — most recent
    assert out == [{"pc": 7}, {"pc": 8}, {"pc": 9}]


def test_clear_capture_log(session_for_capture):
    s = session_for_capture
    wp = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    bp_id = wp["id"]
    s.breakpoints[bp_id].log = [{"pc": 0x80004304}, {"pc": 0x800042FC}]
    out = breakpoint_tools.clear_capture_log(bp_id)
    assert out == {"id": bp_id, "cleared": 2}
    assert s.breakpoints[bp_id].log == []


def test_stop_capturing_clears_auto_continue(session_for_capture):
    s = session_for_capture
    wp = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    bp_id = wp["id"]
    breakpoint_tools.capture_on_hit(bp_id)
    breakpoint_tools.stop_capturing(bp_id)
    assert s.breakpoints[bp_id].auto_continue is False
    # Watcher torn down because no other BP has auto_continue.
    assert s.watcher is None


def test_stop_capturing_all(session_for_capture):
    s = session_for_capture
    wp1 = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    wp2 = breakpoint_tools.add_watchpoint(0x80800000, 4, on="write")
    breakpoint_tools.capture_on_hit(wp1["id"])
    breakpoint_tools.capture_on_hit(wp2["id"])
    out = breakpoint_tools.stop_capturing(None)
    assert set(out["stopped_ids"]) == {wp1["id"], wp2["id"]}
    assert s.watcher is None


def test_wait_for_hit_refuses_while_watcher_running(session_for_capture):
    s = session_for_capture
    wp = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    breakpoint_tools.capture_on_hit(wp["id"])
    with pytest.raises(execution_tools.WrongState):
        breakpoint_tools.wait_for_hit(timeout_s=0.1)


def test_pause_refuses_while_watcher_running(session_for_capture):
    s = session_for_capture
    s.state = SessionState.CONNECTED_RUNNING
    wp = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    breakpoint_tools.capture_on_hit(wp["id"])
    with pytest.raises(execution_tools.WrongState):
        execution_tools.pause()


def test_get_pc_refuses_while_watcher_running(session_for_capture):
    s = session_for_capture
    wp = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    breakpoint_tools.capture_on_hit(wp["id"])
    with pytest.raises(execution_tools.WrongState):
        execution_tools.get_pc()


def test_predicate_safe_globals_blocks_builtins(session_for_capture):
    s = session_for_capture
    wp = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    bp_id = wp["id"]
    s.breakpoints[bp_id].log = [{"pc": 1}, {"pc": 2}]
    # __import__ etc. should not be available; predicate raises silently and entry is dropped.
    out = breakpoint_tools.get_capture_log(bp_id, where="__import__('os')")
    assert out == []
