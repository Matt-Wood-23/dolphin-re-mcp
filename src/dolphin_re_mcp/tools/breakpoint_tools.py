"""
Breakpoint & watchpoint management.

Step 4 surface: add/remove BP+WP, list them, wait_for_hit. No capture-on-hit
yet — that requires the stop-watcher task and lands in step 5.

ID model:
  The session assigns monotonic integer IDs. Tools refer to IDs, not raw
  (addr, size, kind) triples — that lets us swap out the kind later and keeps
  the API stable.

State invariant:
  Calling add_*/remove from CONNECTED_RUNNING is allowed only if the stub
  accepts BPs while running. Dolphin does — but it's cleaner to pause first.
  We don't enforce this; the agent can do whichever pattern fits the task.
"""
from __future__ import annotations

import logging
import socket
from typing import Any

from contextlib import contextmanager

from ..gdb.client import ConnectionLost, GDBStubError, StubWedged
from ..gdb.stop_reply import parse_stop_reply
from ..memory.routing import coerce_addr
from ..session import BreakpointSpec, SessionState, get_session


def _quiesce_for_modify(session) -> None:
    """
    Force the stub into a known-paused, no-bytes-in-flight state.

    Sequence:
      1. Send `\\x03` interrupt.
      2. Consume stop replies until we see one (or hit a short total budget).
      3. Drain any further stop replies that arrived during the consume.
      4. Send `qC` (heartbeat). The stub's response acts as a fence — once
         we've seen it, we KNOW any prior stop replies have been delivered.
         Anything queued in front of qC's response is also drained.

    Without this, the stub may have multiple stop replies in flight (a real
    watchpoint hit AND the SIGINT) and we'd consume the wrong one, leaving
    the SIGINT to corrupt the next packet's ack read.
    """
    import time as _time

    stub = session.stub
    # 1. Interrupt.
    try:
        stub.interrupt()
    except Exception:
        log.exception("_quiesce_for_modify: interrupt failed")

    # 2. Drain any/all stop replies for up to ~1 second.
    deadline = _time.monotonic() + 1.0
    saw_one = False
    while _time.monotonic() < deadline:
        try:
            stub.wait_for_stop(timeout=0.1)
            saw_one = True
        except Exception:
            if saw_one:
                break  # nothing further; we saw at least one stop
            # haven't seen any stop yet — keep waiting until deadline
            continue

    # 3. Drain any tail noise.
    stub.drain_stop_replies(max_wait_s=0.05)

    # 4. Fence with qC. Anything that comes back before the qC response is
    #    treated as another stop reply we should drain.
    try:
        # Send qC manually so we can recognize its response shape.
        stub._send_packet("qC")  # type: ignore[attr-defined]
        deadline = _time.monotonic() + 1.0
        while _time.monotonic() < deadline:
            try:
                pkt = stub._read_packet_from_wire(timeout=0.2)  # type: ignore[attr-defined]
            except Exception:
                continue
            # The qC response starts with "QC" (current thread id).
            if pkt.startswith("QC") or pkt == "" or pkt.startswith("E"):
                break
            # Anything else (T<sig>...) is a delayed stop reply — buffer it.
            log.debug("_quiesce_for_modify: drained packet during qC fence: %s", pkt[:40])
    except Exception:
        log.exception("_quiesce_for_modify: qC fence failed (continuing)")

    session.mark_paused()


@contextmanager
def _safe_to_modify(session):
    """
    Stub modifications (Z*/z*) can race with stop replies if the CPU is running:
    the stub may send `$T05...` *just as* we're sending `Z2,...`, and our
    `_send_packet` read of the `+` ack sees the `$` of the stop reply instead.

    Solution: pause if running, do the modification, resume if we paused.
    The stop reply we induce by interrupt() is consumed inside the helper.
    """
    # Acquire the GDB lock so we don't race the watcher thread. RLock means
    # nested _safe_to_modify (or other lock-holding code on this thread) works.
    with session.gdb_lock:
        was_running = session.state == SessionState.CONNECTED_RUNNING
        if was_running:
            # Pre-flight: confirm the stub's serve loop is actually pumping
            # packets before we commit to the interrupt dance. A wedged stub
            # (UI-paused, or tangled by a prior race) will hang every step
            # of _quiesce_for_modify; fail fast with a clear message instead.
            if not session.stub.probe_responsive(timeout=0.5):
                session.state = SessionState.ERROR
                raise StubWedged(
                    "GDB stub stopped responding to qC. Dolphin is likely "
                    "UI-paused or the stub got tangled by a prior race. "
                    "Unpause via the UI if applicable, otherwise relaunch "
                    "Dolphin (stub listener is one-shot per launch)."
                )
            _quiesce_for_modify(session)
            # The CPU may have queued multiple stop replies before our
            # interrupt landed (e.g. watcher just resumed and an in-flight
            # hit fired). Drain them so the next command's ack read isn't
            # tangled with stale `$...` packets.
            stale = session.stub.drain_stop_replies(max_wait_s=0.1)
            if stale:
                log.debug("_safe_to_modify: drained %d stale stop replies pre-modify", len(stale))
            session.mark_paused()
        try:
            yield
        finally:
            if was_running:
                # After the modify, drain again — Dolphin may have sent a
                # post-modify stop reply we don't want lingering.
                more_stale = session.stub.drain_stop_replies(max_wait_s=0.05)
                if more_stale:
                    log.debug(
                        "_safe_to_modify: drained %d stale stop replies post-modify",
                        len(more_stale),
                    )
                session.stub.continue_async()
                session.mark_running()

log = logging.getLogger(__name__)


class BreakpointNotFound(KeyError):
    pass


# ---- BP / WP add ----

def add_breakpoint(addr: int) -> dict[str, Any]:
    """Software breakpoint at `addr` (Z0,addr,4)."""
    session = get_session()
    session.ensure_connected()
    with _safe_to_modify(session):
        session.stub.add_sw_breakpoint(addr)
    bp_id = session.alloc_bp_id()
    spec = BreakpointSpec(bp_id=bp_id, addr=addr, kind="sw_bp", size=4)
    session.register_bp(spec)
    log.info("added sw_bp #%d at 0x%08x", bp_id, addr)
    return {"id": bp_id, "addr": addr, "kind": "sw_bp", "size": 4}


def add_watchpoint(addr: int, size: int = 4, on: str = "write") -> dict[str, Any]:
    """
    Hardware watchpoint. `on` is one of:
      'write'  → Z2 (writes only — most useful for cheatmine writer-trace)
      'read'   → Z3
      'access' → Z4 (reads + writes)
    """
    session = get_session()
    session.ensure_connected()
    on = on.lower()
    with _safe_to_modify(session):
        if on == "write":
            session.stub.add_write_watchpoint(addr, size)
            kind = "write_wp"
        elif on == "read":
            session.stub.add_read_watchpoint(addr, size)
            kind = "read_wp"
        elif on == "access":
            session.stub.add_access_watchpoint(addr, size)
            kind = "access_wp"
        else:
            raise ValueError(f"invalid on={on!r}; expected 'write', 'read', or 'access'")
    bp_id = session.alloc_bp_id()
    spec = BreakpointSpec(bp_id=bp_id, addr=addr, kind=kind, size=size)
    session.register_bp(spec)
    log.info("added %s #%d at 0x%08x size=%d", kind, bp_id, addr, size)
    return {"id": bp_id, "addr": addr, "kind": kind, "size": size}


# ---- remove ----

def remove(bp_id: int) -> dict[str, Any]:
    """Remove a BP/WP by ID. Idempotent — removing a non-existent ID is OK."""
    session = get_session()
    session.ensure_connected()
    spec = session.unregister_bp(bp_id)
    if spec is None:
        return {"id": bp_id, "removed": False, "reason": "not_found"}
    try:
        with _safe_to_modify(session):
            if spec.kind == "sw_bp":
                session.stub.remove_sw_breakpoint(spec.addr)
            elif spec.kind == "hw_bp":
                session.stub.remove_hw_breakpoint(spec.addr)
            elif spec.kind == "write_wp":
                session.stub.remove_write_watchpoint(spec.addr, spec.size)
            elif spec.kind == "read_wp":
                session.stub.remove_read_watchpoint(spec.addr, spec.size)
            elif spec.kind == "access_wp":
                session.stub.remove_access_watchpoint(spec.addr, spec.size)
    except GDBStubError as e:
        log.warning("stub error removing #%d: %s (registry already cleared)", bp_id, e)
    except (socket.timeout, TimeoutError) as e:
        # The stub didn't ack the z* in time — usually a Dolphin race after
        # an interrupt. The session's view is already correct (we cleared
        # the registry above); Dolphin's stale BP state washes out on next
        # launch since the stub is one-shot per launch anyway.
        log.warning("stub timeout removing #%d: %s (registry cleared anyway)", bp_id, e)
    log.info("removed %s #%d at 0x%08x", spec.kind, bp_id, spec.addr)
    return {"id": bp_id, "removed": True, "addr": spec.addr, "kind": spec.kind}


def remove_all() -> dict[str, Any]:
    """Remove every BP/WP. Useful for a clean reset."""
    session = get_session()
    session.ensure_connected()
    ids = list(session.breakpoints.keys())
    removed = []
    for bp_id in ids:
        result = remove(bp_id)
        if result.get("removed"):
            removed.append(bp_id)
    return {"removed_ids": removed, "count": len(removed)}


# ---- list ----

def list_breakpoints() -> list[dict]:
    session = get_session()
    return [
        {"id": b.bp_id, "addr": b.addr, "kind": b.kind, "size": b.size}
        for b in session.breakpoints.values()
        if b.kind in ("sw_bp", "hw_bp")
    ]


def list_watchpoints() -> list[dict]:
    session = get_session()
    return [
        {"id": b.bp_id, "addr": b.addr, "kind": b.kind, "size": b.size}
        for b in session.breakpoints.values()
        if b.kind in ("write_wp", "read_wp", "access_wp")
    ]


def list_all() -> list[dict]:
    session = get_session()
    return [
        {"id": b.bp_id, "addr": b.addr, "kind": b.kind, "size": b.size}
        for b in session.breakpoints.values()
    ]


# ---- wait_for_hit ----

def wait_for_hit(timeout_s: float = 30.0) -> dict[str, Any]:
    """
    Block on the next stop reply. The emulator must be RUNNING — usually
    means you called `resume()` first.

    Returns:
      {raw, signal, pc, sp, watch_kind, watch_addr, matched_bp_id}

    `matched_bp_id` is best-effort: for software BPs we match on PC, for
    watchpoints we match on the watch_addr field if Dolphin includes it.
    If multiple BPs cover the same addr, the first matching ID is returned.

    Raises:
      WrongState — if the session is paused (no continue has been issued).
      socket.timeout — if no stop occurs within `timeout_s`.
    """
    from .execution_tools import WrongState

    session = get_session()
    session.ensure_connected()
    if session.watcher is not None and session.watcher.is_alive():
        raise WrongState(
            "wait_for_hit conflicts with the running stop watcher; "
            "call stop_capturing() first"
        )
    if session.state != SessionState.CONNECTED_RUNNING:
        raise WrongState(
            f"wait_for_hit needs CONNECTED_RUNNING; current state is {session.state.value}"
        )
    with session.gdb_lock:
        try:
            raw = session.stub.wait_for_stop(timeout=timeout_s)
        except socket.timeout:
            # Caller will see an empty result; state unchanged (still running).
            raise
        parsed = parse_stop_reply(raw)
        session.mark_paused()

    matched = _match_bp(parsed, session)
    return {
        "raw": raw,
        "signal": parsed.signal,
        "pc": parsed.pc,
        "sp": parsed.sp,
        "watch_kind": parsed.watch_kind,
        "watch_addr": parsed.watch_addr,
        "matched_bp_id": matched,
    }


def _match_bp(parsed, session) -> int | None:
    """
    Best-effort: figure out which registered BP/WP fired.

    Order of attribution:
      1. Stop reply carries a `watch:`/`rwatch:`/`awatch:` annotation → match by addr.
      2. Stop reply's PC matches a registered sw_bp/hw_bp → match by PC.
      3. Stop reply has no annotation AND there's exactly one watchpoint armed
         AND the PC is NOT one of our BPs → attribute to that lone WP.
         (Dolphin 2603a empirically does not annotate watchpoint hits.)
    """
    if parsed.watch_addr is not None:
        kind_filter = {
            "watch": "write_wp",
            "rwatch": "read_wp",
            "awatch": "access_wp",
        }.get(parsed.watch_kind or "")
        for spec in session.breakpoints.values():
            if spec.addr == parsed.watch_addr and (
                kind_filter is None or spec.kind == kind_filter
            ):
                return spec.bp_id

    pc = parsed.pc
    if pc is not None:
        for spec in session.breakpoints.values():
            if spec.kind in ("sw_bp", "hw_bp") and spec.addr == pc:
                return spec.bp_id

    # Fallback: lone-watchpoint inference (Dolphin doesn't annotate WP hits).
    wps = [s for s in session.breakpoints.values()
           if s.kind in ("write_wp", "read_wp", "access_wp")]
    if len(wps) == 1:
        return wps[0].bp_id
    return None


# ---- capture-on-hit (step 5: the transformative milestone) ----

class CaptureError(RuntimeError):
    """Capture/predicate configuration is invalid."""


_CAPTURE_CHOICES = {"gprs", "fprs", "lr", "stack"}


def capture_on_hit(
    bp_id: int,
    captures: list[str] | None = None,
    auto_resume: bool = True,
) -> dict[str, Any]:
    """
    Mark BP/WP `bp_id` as auto-continue with state capture.

    `captures` is a subset of {'gprs', 'fprs', 'lr', 'stack'}. The watcher
    records {pc, sp, signal, watch_addr, ts} plus whatever you ask for.

    Starts the background StopWatcher thread if not already running. If
    `auto_resume` is True (default) and the CPU is paused, also resumes.
    """
    from ..stop_watcher import ensure_watcher_running

    session = get_session()
    session.ensure_connected()
    if bp_id not in session.breakpoints:
        raise BreakpointNotFound(f"no BP/WP registered with id {bp_id}")
    captures = list(captures or ["gprs"])
    unknown = set(captures) - _CAPTURE_CHOICES
    if unknown:
        raise CaptureError(
            f"unknown capture keys {sorted(unknown)}; allowed: {sorted(_CAPTURE_CHOICES)}"
        )
    spec = session.breakpoints[bp_id]
    spec.captures = captures
    spec.auto_continue = True

    if auto_resume and session.state == SessionState.CONNECTED_PAUSED:
        session.stub.continue_async()
        session.mark_running()

    ensure_watcher_running(session)
    log.info("capture_on_hit #%d captures=%s auto_resume=%s", bp_id, captures, auto_resume)
    return {
        "id": bp_id,
        "captures": captures,
        "auto_continue": True,
        "watcher_running": True,
    }


def get_capture_log(
    bp_id: int,
    where: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    """
    Return captured hits for `bp_id`. Optional `where` is a Python expression
    evaluated against each capture dict; only matching hits are returned.

    Predicate scope is the capture dict itself — keys like `pc`, `lr`,
    `r3`..`r10`, `watch_addr`. Examples:
      where="r4 == 0x2"
      where="pc != 0x80004304 and r3 in range(0x806ada00, 0x806adb00)"

    Built-ins are stripped from the eval scope; predicates can't import
    or call arbitrary code.
    """
    session = get_session()
    if bp_id not in session.breakpoints:
        raise BreakpointNotFound(f"no BP/WP registered with id {bp_id}")
    log_entries = list(session.breakpoints[bp_id].log)

    if where:
        filt: list[dict] = []
        compiled = compile(where, "<capture-predicate>", "eval")
        safe_globals = {"__builtins__": None, "range": range, "len": len}
        for entry in log_entries:
            try:
                if eval(compiled, safe_globals, entry):
                    filt.append(entry)
            except Exception as e:
                log.debug("predicate raised on entry pc=%s: %s", entry.get("pc"), e)
        log_entries = filt

    if limit is not None and limit > 0:
        log_entries = log_entries[-limit:]
    return log_entries


def clear_capture_log(bp_id: int) -> dict[str, Any]:
    session = get_session()
    if bp_id not in session.breakpoints:
        raise BreakpointNotFound(f"no BP/WP registered with id {bp_id}")
    spec = session.breakpoints[bp_id]
    n = len(spec.log)
    spec.log.clear()
    return {"id": bp_id, "cleared": n}


def stop_capturing(bp_id: int | None = None) -> dict[str, Any]:
    """
    Stop the auto-continue flag on one BP (or all if bp_id is None).

    Stops the watcher thread once no BP has auto_continue. Leaves the CPU
    in whatever state it was — caller can pause() afterwards if needed.
    """
    from ..stop_watcher import stop_watcher

    session = get_session()
    if bp_id is None:
        affected = []
        for spec in session.breakpoints.values():
            if spec.auto_continue:
                spec.auto_continue = False
                affected.append(spec.bp_id)
    else:
        if bp_id not in session.breakpoints:
            raise BreakpointNotFound(f"no BP/WP registered with id {bp_id}")
        session.breakpoints[bp_id].auto_continue = False
        affected = [bp_id]

    if not any(s.auto_continue for s in session.breakpoints.values()):
        stop_watcher(session)

    return {"stopped_ids": affected, "watcher_running": session.watcher is not None}


# ---- registration ----

def register(mcp) -> None:
    @mcp.tool()
    def add_breakpoint_tool(addr: int | str) -> dict:
        """Software BP at addr ("0x..." or decimal). Returns {id, addr, kind, size}."""
        return add_breakpoint(coerce_addr(addr))

    @mcp.tool()
    def add_watchpoint_tool(addr: int | str, size: int = 4, on: str = "write") -> dict:
        """HW watchpoint at addr ("0x..." or decimal). `on` = 'write' | 'read' | 'access'."""
        return add_watchpoint(coerce_addr(addr), size, on)

    @mcp.tool()
    def remove_breakpoint_tool(bp_id: int) -> dict:
        """Remove BP/WP by ID. Idempotent."""
        return remove(bp_id)

    @mcp.tool()
    def remove_all_breakpoints_tool() -> dict:
        """Remove every armed BP and WP."""
        return remove_all()

    @mcp.tool()
    def list_breakpoints_tool() -> list:
        return list_breakpoints()

    @mcp.tool()
    def list_watchpoints_tool() -> list:
        return list_watchpoints()

    @mcp.tool()
    def list_all_breakpoints_tool() -> list:
        return list_all()

    @mcp.tool()
    def wait_for_hit_tool(timeout_s: float = 30.0) -> dict:
        """Block until the next BP/WP fires. Pauses the emulator on hit."""
        try:
            return wait_for_hit(timeout_s=timeout_s)
        except socket.timeout:
            return {"hit": False, "timed_out": True, "timeout_s": timeout_s}

    @mcp.tool()
    def capture_on_hit_tool(
        bp_id: int,
        captures: list[str] | None = None,
        auto_resume: bool = True,
    ) -> dict:
        """
        Mark a BP/WP as auto-continue with state capture. Starts the background
        watcher. `captures` ⊆ {'gprs','fprs','lr','stack'}. Default ['gprs'].
        """
        return capture_on_hit(bp_id, captures=captures, auto_resume=auto_resume)

    @mcp.tool()
    def get_capture_log_tool(
        bp_id: int, where: str | None = None, limit: int | None = None
    ) -> list:
        """Return captured hits for bp_id. Optional `where` is a Python predicate."""
        return get_capture_log(bp_id, where=where, limit=limit)

    @mcp.tool()
    def clear_capture_log_tool(bp_id: int) -> dict:
        """Drop all captured hits for bp_id."""
        return clear_capture_log(bp_id)

    @mcp.tool()
    def stop_capturing_tool(bp_id: int | None = None) -> dict:
        """Stop auto-continue on one BP (or all). Stops the watcher when empty."""
        return stop_capturing(bp_id)
