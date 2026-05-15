"""
Background "stop watcher" thread.

While any BP/WP is marked auto_continue, the watcher owns the GDB connection.
Per iteration:
  1. Acquire session.gdb_lock.
  2. wait_for_stop(timeout=poll_interval).
     - Timeout → release lock, brief sleep, repeat.
     - Stop reply → process: identify bp_id, capture state, append to log.
     - Connection lost → exit cleanly.
  3. continue_async() — auto-resume.
  4. Release lock.

Tools that need exclusive GDB access (pause, step, set/clear BPs, etc.) must
acquire session.gdb_lock too. The watcher's short poll_interval bounds how
long they wait.
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from typing import TYPE_CHECKING

from .gdb.client import ConnectionLost
from .gdb.registers import LR, parse_dolphin_gprs, parse_fpr_value
from .gdb.stop_reply import parse_stop_reply

if TYPE_CHECKING:
    from .session import Session

log = logging.getLogger(__name__)


class StopWatcher(threading.Thread):
    """One per Session. Started lazily by capture_on_hit, stopped when no
    auto-continue BPs remain."""

    def __init__(self, session: "Session", poll_interval: float = 0.2):
        super().__init__(daemon=True, name="DolphinStopWatcher")
        self.session = session
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        # Set after run() exits — tools can join and check if needed.
        self.exited_with_error: BaseException | None = None
        # Bookkeeping: how many hits we've processed (for debug/diagnostics).
        self.hits_total = 0

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        log.info("stop watcher started (poll=%.2fs)", self.poll_interval)
        try:
            while not self._stop_event.is_set():
                # Exit if no more work — caller disabled all auto-continue BPs.
                if not _any_auto_continue(self.session):
                    log.info("watcher: no auto_continue BPs left; exiting")
                    return
                # Hold the gdb_lock for the full iteration. Other tools wait
                # at most one poll_interval to grab the socket.
                with self.session.gdb_lock:
                    if self._stop_event.is_set():
                        break
                    try:
                        raw = self.session.stub.wait_for_stop(
                            timeout=self.poll_interval
                        )
                    except socket.timeout:
                        continue
                    except ConnectionLost:
                        log.warning("watcher: connection lost; exiting")
                        return
                    consumed = self._handle_stop(raw)
                    if not consumed:
                        # Non-auto-continue stop — the BP belongs to wait_for_hit
                        # or is unmatched. Surface it via _pending_replies so the
                        # next wait_for_hit sees it, and exit so the foreground
                        # can take over.
                        self.session.stub._pending_replies.append(raw)
                        self.session.mark_paused()
                        log.info("watcher: surfacing non-auto stop; exiting")
                        return
                    # Auto-continue path — resume so the next hit can come in.
                    try:
                        self.session.stub.continue_async()
                    except (ConnectionLost, OSError) as e:
                        log.warning("watcher: continue failed (%s); exiting", e)
                        return
                # Brief sleep outside the lock so tools waiting on gdb_lock
                # actually get a chance.
                time.sleep(0.001)
        except BaseException as e:
            log.exception("watcher: unexpected error")
            self.exited_with_error = e
            raise
        finally:
            log.info("stop watcher exiting (hits=%d)", self.hits_total)

    def _handle_stop(self, raw: str) -> bool:
        """
        Returns True if the stop was an auto_continue BP (watcher should
        continue), False if it should be surfaced to the foreground.
        """
        from .tools.breakpoint_tools import _match_bp  # local import: avoid cycle

        parsed = parse_stop_reply(raw)
        matched_id = _match_bp(parsed, self.session)
        if matched_id is None:
            log.debug("watcher: stop with no matched BP; raw=%s", raw[:80])
            return False
        spec = self.session.breakpoints.get(matched_id)
        if spec is None or not spec.auto_continue:
            log.debug(
                "watcher: BP #%s not configured for auto-capture (raw=%s)",
                matched_id,
                raw[:80],
            )
            return False

        capture: dict = {
            "ts": time.time(),
            "pc": parsed.pc,
            "sp": parsed.sp,
            "signal": parsed.signal,
        }
        if parsed.watch_addr is not None:
            capture["watch_addr"] = parsed.watch_addr

        # Pull register state per spec.captures
        cap_set = set(spec.captures or ())
        try:
            if "gprs" in cap_set:
                blob = self.session.stub.read_registers()
                gprs = parse_dolphin_gprs(blob)
                capture["gprs"] = gprs
                # Flatten r3..r10 (PPC arg regs) for ergonomic predicate access
                for i in range(3, 11):
                    capture[f"r{i}"] = gprs.get(f"r{i}")
            if "lr" in cap_set or "stack" in cap_set:
                lr = self.session.stub.read_register(LR)
                if lr is not None:
                    capture["lr"] = lr
            if "fprs" in cap_set:
                fprs: dict[str, float] = {}
                for i in range(32):
                    raw_b = self.session.stub.read_register_bytes(0x20 + i)
                    if raw_b is not None and len(raw_b) == 8:
                        try:
                            fprs[f"f{i}"] = parse_fpr_value(raw_b)
                        except ValueError:
                            pass
                capture["fprs"] = fprs
        except (ConnectionLost, OSError) as e:
            log.warning("watcher: register read failed: %s", e)
            # Save what we have anyway

        # Apply optional condition filter — if it returns false, drop this hit
        # but still auto-continue.
        if spec.condition:
            if not _eval_condition(spec.condition, capture):
                log.debug("bp #%d: condition false, hit dropped", spec.bp_id)
                return True
        spec.log.append(capture)
        self.hits_total += 1
        return True


def _eval_condition(expr: str, snap: dict) -> bool:
    """Evaluate a Python expression against a capture dict. Restricted globals."""
    ns: dict = dict(snap)
    if "gprs" in snap and isinstance(snap["gprs"], dict):
        ns.update(snap["gprs"])
    try:
        return bool(eval(expr, {"__builtins__": None}, ns))
    except Exception as e:
        log.warning("condition %r eval failed: %s", expr, e)
        # Don't drop hits because of a bad filter.
        return True


def _any_auto_continue(session) -> bool:
    return any(spec.auto_continue for spec in session.breakpoints.values())


def ensure_watcher_running(session: "Session") -> StopWatcher:
    """Idempotent — start the watcher if not already running."""
    if session.watcher is not None and session.watcher.is_alive():
        return session.watcher
    watcher = StopWatcher(session)
    session.watcher = watcher
    watcher.start()
    return watcher


def stop_watcher(session: "Session", timeout: float = 2.0) -> None:
    """Signal the watcher to exit and wait briefly for it to finish."""
    w = session.watcher
    if w is None:
        return
    w.stop()
    w.join(timeout=timeout)
    if w.is_alive():
        log.warning("watcher did not exit within %.1fs", timeout)
    session.watcher = None
