"""
Background worker that keeps the MCP connected to Dolphin's GDB stub.

Problem: Dolphin's GDB stub halts the CPU at boot. If no debugger is connected
when the user loads a game, the CPU stays halted and the game appears frozen
(the UI doesn't reflect this — only the CPU thread is paused at the stub
level). The MCP's auto-resume on connect (Session.ensure_connected) only fires
when a tool is called.

Fix: as soon as the MCP server starts, run a low-frequency background loop
that tries to connect any time the session is DISCONNECTED. The connect path
itself auto-resumes (unless DOLPHIN_NO_AUTO_RESUME), so the moment Dolphin
becomes reachable the game unblocks without the user needing to ask Claude to
call a tool first.

Disable via env var DOLPHIN_NO_BG_CONNECT=1.
"""
from __future__ import annotations

import logging
import os
import threading

from .session import SessionState, get_session

log = logging.getLogger(__name__)

POLL_INTERVAL_S = 0.5
BACKOFF_MAX_S = 5.0
BACKOFF_FACTOR = 1.5


def _step_interval(current: float, connected: bool) -> float:
    """Pure helper so the backoff curve is unit-testable."""
    if connected:
        return POLL_INTERVAL_S
    return min(current * BACKOFF_FACTOR, BACKOFF_MAX_S)


def _worker(stop: threading.Event) -> None:
    interval = POLL_INTERVAL_S
    while not stop.wait(interval):
        try:
            session = get_session()
            if session.state == SessionState.DISCONNECTED:
                try:
                    session.ensure_connected()
                    log.info(
                        "auto-connect: connected to Dolphin GDB stub at %s:%d",
                        session.host, session.port,
                    )
                    interval = POLL_INTERVAL_S
                except Exception as e:
                    log.debug("auto-connect: not connected (%s)", e)
                    interval = _step_interval(interval, connected=False)
            else:
                interval = POLL_INTERVAL_S
        except Exception:
            log.exception("auto-connect: unexpected error in worker loop")
            interval = _step_interval(interval, connected=False)


def start() -> threading.Event | None:
    """Start the auto-connect worker. Returns the stop Event (caller can .set() it),
    or None if disabled via env."""
    if os.environ.get("DOLPHIN_NO_BG_CONNECT"):
        log.info("auto-connect: disabled via DOLPHIN_NO_BG_CONNECT")
        return None
    stop = threading.Event()
    t = threading.Thread(
        target=_worker, args=(stop,), name="dolphin-auto-connect", daemon=True
    )
    t.start()
    log.info("auto-connect: background worker started (poll=%.2fs)", POLL_INTERVAL_S)
    return stop
