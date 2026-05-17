"""Tests for the background auto-connect worker."""
from __future__ import annotations

import threading
import time
from unittest.mock import patch

import pytest

from dolphin_re_mcp import auto_connect
from dolphin_re_mcp.session import Session, SessionState, get_session


@pytest.fixture(autouse=True)
def _reset_session_state():
    """Ensure each test starts with a DISCONNECTED session — the global
    singleton would otherwise leak state across tests."""
    s = get_session()
    s.state = SessionState.DISCONNECTED
    yield
    s.state = SessionState.DISCONNECTED


def test_step_interval_resets_when_connected():
    assert auto_connect._step_interval(3.0, connected=True) == auto_connect.POLL_INTERVAL_S


def test_step_interval_grows_geometrically_when_not_connected():
    cur = auto_connect.POLL_INTERVAL_S
    nxt = auto_connect._step_interval(cur, connected=False)
    assert nxt == pytest.approx(cur * auto_connect.BACKOFF_FACTOR)


def test_step_interval_clamps_at_max():
    huge = auto_connect.BACKOFF_MAX_S * 100
    assert auto_connect._step_interval(huge, connected=False) == auto_connect.BACKOFF_MAX_S


def test_start_returns_none_when_disabled(monkeypatch):
    monkeypatch.setenv("DOLPHIN_NO_BG_CONNECT", "1")
    stop = auto_connect.start()
    assert stop is None


def test_start_returns_event_and_thread_runs(monkeypatch):
    monkeypatch.delenv("DOLPHIN_NO_BG_CONNECT", raising=False)
    # Don't let the worker actually call ensure_connected — patch it out.
    with patch.object(Session, "ensure_connected", lambda self: None):
        stop = auto_connect.start()
        assert isinstance(stop, threading.Event)
        # Give the worker one tick, then shut it down cleanly.
        time.sleep(auto_connect.POLL_INTERVAL_S * 1.5)
        stop.set()


def test_worker_triggers_ensure_connected_when_disconnected(monkeypatch):
    """Worker should call ensure_connected only while state == DISCONNECTED."""
    monkeypatch.delenv("DOLPHIN_NO_BG_CONNECT", raising=False)
    # Speed up the test: shrink the poll interval for this test only.
    monkeypatch.setattr(auto_connect, "POLL_INTERVAL_S", 0.01)

    calls: list[SessionState] = []

    def fake_ensure(self):
        calls.append(self.state)
        # Simulate successful connect on first call.
        self.state = SessionState.CONNECTED_RUNNING

    with patch.object(Session, "ensure_connected", fake_ensure):
        stop = auto_connect.start()
        # Wait enough ticks that the worker will have run a few times.
        time.sleep(0.1)
        stop.set()

    # At least one call should have happened, and it should have seen
    # DISCONNECTED (the initial state). Subsequent ticks should NOT have
    # re-entered ensure_connected because state moved off DISCONNECTED.
    assert calls, "worker never invoked ensure_connected"
    assert calls[0] == SessionState.DISCONNECTED
    # Idempotent: once connected, no further attempts.
    assert all(s == SessionState.DISCONNECTED for s in calls)
