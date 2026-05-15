"""Unit tests for breakpoint_tools against a mocked stub."""
from __future__ import annotations

import socket

import pytest

from dolphin_re_mcp import session as session_mod
from dolphin_re_mcp.session import SessionState
from dolphin_re_mcp.tools import breakpoint_tools


class FakeStub:
    """Tracks every BP/WP add/remove + can be fed a fake stop reply."""

    def __init__(self):
        self.calls: list[tuple] = []
        self._stop_reply: str | None = None
        self.sock = object()  # truthy → "connected"
        self._responsive = True  # _safe_to_modify probes this when running

    def probe_responsive(self, timeout: float = 0.5) -> bool:
        return self._responsive

    def add_sw_breakpoint(self, addr):
        self.calls.append(("Z0", addr))
        return "OK"

    def remove_sw_breakpoint(self, addr):
        self.calls.append(("z0", addr))
        return "OK"

    def add_write_watchpoint(self, addr, size):
        self.calls.append(("Z2", addr, size))
        return "OK"

    def remove_write_watchpoint(self, addr, size):
        self.calls.append(("z2", addr, size))
        return "OK"

    def add_read_watchpoint(self, addr, size):
        self.calls.append(("Z3", addr, size))
        return "OK"

    def remove_read_watchpoint(self, addr, size):
        self.calls.append(("z3", addr, size))
        return "OK"

    def add_access_watchpoint(self, addr, size):
        self.calls.append(("Z4", addr, size))
        return "OK"

    def remove_access_watchpoint(self, addr, size):
        self.calls.append(("z4", addr, size))
        return "OK"

    # for wait_for_hit:
    def queue_stop(self, reply: str):
        self._stop_reply = reply

    def wait_for_stop(self, timeout=None):
        if self._stop_reply is None:
            raise socket.timeout("no stop queued")
        r, self._stop_reply = self._stop_reply, None
        return r


@pytest.fixture
def session_with_fake_stub(monkeypatch):
    s = session_mod.Session()
    s.ensure_connected = lambda: None  # type: ignore[assignment]
    s.stub = FakeStub()
    s.state = SessionState.CONNECTED_PAUSED
    monkeypatch.setattr(session_mod, "_session", s)
    return s


def test_add_breakpoint_registers_and_sends_z0(session_with_fake_stub):
    s = session_with_fake_stub
    out = breakpoint_tools.add_breakpoint(0x80004304)
    assert out["addr"] == 0x80004304
    assert out["kind"] == "sw_bp"
    assert ("Z0", 0x80004304) in s.stub.calls
    assert len(s.breakpoints) == 1


def test_add_watchpoint_write(session_with_fake_stub):
    s = session_with_fake_stub
    out = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    assert out["kind"] == "write_wp"
    assert ("Z2", 0x806ADAC4, 4) in s.stub.calls


def test_add_watchpoint_read(session_with_fake_stub):
    s = session_with_fake_stub
    breakpoint_tools.add_watchpoint(0x80800000, 4, on="read")
    assert ("Z3", 0x80800000, 4) in s.stub.calls


def test_add_watchpoint_access(session_with_fake_stub):
    s = session_with_fake_stub
    breakpoint_tools.add_watchpoint(0x80800000, 4, on="access")
    assert ("Z4", 0x80800000, 4) in s.stub.calls


def test_add_watchpoint_bad_kind(session_with_fake_stub):
    with pytest.raises(ValueError):
        breakpoint_tools.add_watchpoint(0x80800000, 4, on="weird")


def test_remove_sends_correct_z_packet(session_with_fake_stub):
    s = session_with_fake_stub
    out = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    bp_id = out["id"]
    removed = breakpoint_tools.remove(bp_id)
    assert removed["removed"] is True
    assert ("z2", 0x806ADAC4, 4) in s.stub.calls
    assert bp_id not in s.breakpoints


def test_remove_unknown_id_is_idempotent(session_with_fake_stub):
    out = breakpoint_tools.remove(999)
    assert out["removed"] is False


def test_remove_all_clears_registry(session_with_fake_stub):
    s = session_with_fake_stub
    breakpoint_tools.add_breakpoint(0x80004304)
    breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    out = breakpoint_tools.remove_all()
    assert out["count"] == 2
    assert s.breakpoints == {}


def test_list_breakpoints_only_returns_bps(session_with_fake_stub):
    breakpoint_tools.add_breakpoint(0x80004304)
    breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    bps = breakpoint_tools.list_breakpoints()
    wps = breakpoint_tools.list_watchpoints()
    assert len(bps) == 1 and bps[0]["kind"] == "sw_bp"
    assert len(wps) == 1 and wps[0]["kind"] == "write_wp"


def test_wait_for_hit_requires_running(session_with_fake_stub):
    from dolphin_re_mcp.tools.execution_tools import WrongState

    s = session_with_fake_stub
    s.state = SessionState.CONNECTED_PAUSED
    with pytest.raises(WrongState):
        breakpoint_tools.wait_for_hit(timeout_s=0.1)


def test_wait_for_hit_matches_watchpoint(session_with_fake_stub):
    s = session_with_fake_stub
    spec = breakpoint_tools.add_watchpoint(0x806ADAC4, 4, on="write")
    s.state = SessionState.CONNECTED_RUNNING
    s.stub.queue_stop("T05watch:806adac4;40:8000ed53c;01:81560000;")
    out = breakpoint_tools.wait_for_hit(timeout_s=1.0)
    assert out["matched_bp_id"] == spec["id"]
    assert out["watch_addr"] == 0x806ADAC4
    assert s.state == SessionState.CONNECTED_PAUSED


def test_pause_raises_stub_wedged_when_unresponsive(session_with_fake_stub):
    """pause() must fail fast on a wedged stub, not burn 4s on interrupt retries."""
    from dolphin_re_mcp.gdb.client import StubWedged
    from dolphin_re_mcp.tools import execution_tools

    s = session_with_fake_stub
    s.state = SessionState.CONNECTED_RUNNING
    s.stub._responsive = False
    with pytest.raises(StubWedged):
        execution_tools.pause()
    assert s.state == SessionState.ERROR


def test_add_watchpoint_raises_stub_wedged_when_unresponsive(session_with_fake_stub):
    """If the stub isn't pumping packets (UI-pause / wedged), fail fast."""
    from dolphin_re_mcp.gdb.client import StubWedged

    s = session_with_fake_stub
    s.state = SessionState.CONNECTED_RUNNING
    s.stub._responsive = False
    with pytest.raises(StubWedged):
        breakpoint_tools.add_watchpoint(0x90121060, 4, on="write")
    # No Z2 packet should have been sent — we bailed before quiesce.
    assert not any(c[0] == "Z2" for c in s.stub.calls)
    # Session state should reflect the wedge so the agent sees it in health().
    assert s.state == SessionState.ERROR


def test_wait_for_hit_matches_sw_bp_by_pc(session_with_fake_stub):
    s = session_with_fake_stub
    spec = breakpoint_tools.add_breakpoint(0x80004304)
    s.state = SessionState.CONNECTED_RUNNING
    s.stub.queue_stop("T0540:80004304;01:81560000;")
    out = breakpoint_tools.wait_for_hit(timeout_s=1.0)
    assert out["matched_bp_id"] == spec["id"]
    assert out["pc"] == 0x80004304
