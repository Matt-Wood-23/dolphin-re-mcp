"""
Execution control + register access — the minimum needed to make breakpoints useful.

Step-family tools (step, step_over, step_out, run_until) live in disasm_tools
once Capstone is wired in (step 6 of the build plan).
"""
from __future__ import annotations

import logging
from typing import Any

from ..gdb.client import ConnectionLost, StubWedged
from ..gdb.registers import LR, PC, CTR, CR, MSR, XER, parse_fpr_value
from ..gdb.stop_reply import parse_stop_reply
from ..memory.routing import coerce_addr
from ..session import SessionState, get_session

log = logging.getLogger(__name__)


class WrongState(RuntimeError):
    """Operation isn't valid in the current session state."""


def _refuse_if_watcher_running(session, op: str) -> None:
    if session.watcher is not None and session.watcher.is_alive():
        raise WrongState(
            f"{op} conflicts with the running stop watcher; "
            f"call stop_capturing() first"
        )


# ---- core control ----

def pause() -> dict[str, Any]:
    """Interrupt a running target. Returns {pc, sp} from the resulting stop reply."""
    import socket as _socket

    session = get_session()
    session.ensure_connected()
    _refuse_if_watcher_running(session, "pause")
    if session.state == SessionState.CONNECTED_PAUSED:
        # Already paused — return current PC instead of trying to interrupt.
        pc = get_pc()
        return {"already_paused": True, "pc": pc}
    with session.gdb_lock:
        # Pre-flight: confirm the stub is actually pumping packets. If it
        # isn't (Dolphin UI-paused, or stub wedged by a prior race), the
        # interrupt byte goes nowhere and we'd burn 4s timing out twice.
        if not session.stub.probe_responsive(timeout=0.5):
            session.state = SessionState.ERROR
            raise StubWedged(
                "GDB stub stopped responding to qC. Dolphin may be UI-paused, "
                "or the stub got tangled by a prior race. Unpause via the UI "
                "if applicable, otherwise relaunch Dolphin."
            )
        # Dolphin's stub occasionally drops the first 0x03 interrupt — drain
        # any stale stop replies first, then retry once on timeout.
        stale = session.stub.drain_stop_replies(max_wait_s=0.05)
        if stale:
            log.debug("pause: drained %d stale stop replies", len(stale))
        reply: str | None = None
        last_err: Exception | None = None
        for attempt in (1, 2):
            try:
                session.stub.interrupt()
                reply = session.stub.wait_for_stop(timeout=2.0)
                break
            except _socket.timeout as e:
                last_err = e
                log.warning("pause: interrupt attempt %d timed out, retrying", attempt)
        if reply is None:
            raise TimeoutError(
                "pause: stub did not respond to interrupt after 2 attempts"
            ) from last_err
        session.mark_paused()
    parsed = parse_stop_reply(reply)
    return {
        "raw": reply,
        "signal": parsed.signal,
        "pc": parsed.pc,
        "sp": parsed.sp,
    }


def resume() -> dict[str, Any]:
    """Continue execution. Does NOT wait for a stop — pair with wait_for_hit if needed."""
    session = get_session()
    session.ensure_connected()
    _refuse_if_watcher_running(session, "resume")
    if session.state == SessionState.CONNECTED_RUNNING:
        return {"ok": True, "was": "already_running"}
    with session.gdb_lock:
        session.stub.continue_async()
        session.mark_running()
    return {"ok": True}


def is_paused() -> bool:
    session = get_session()
    return session.state == SessionState.CONNECTED_PAUSED


# ---- register access ----

def get_pc() -> int:
    session = get_session()
    session.ensure_connected()
    _refuse_if_watcher_running(session, "get_pc")
    with session.gdb_lock:
        v = session.stub.read_register(PC)
    if v is None:
        raise RuntimeError("stub returned no value for PC")
    return v


def get_lr() -> int:
    session = get_session()
    session.ensure_connected()
    _refuse_if_watcher_running(session, "get_lr")
    with session.gdb_lock:
        v = session.stub.read_register(LR)
    if v is None:
        raise RuntimeError("stub returned no value for LR")
    return v


def get_ctr() -> int:
    session = get_session()
    session.ensure_connected()
    _refuse_if_watcher_running(session, "get_ctr")
    with session.gdb_lock:
        v = session.stub.read_register(CTR)
    if v is None:
        raise RuntimeError("stub returned no value for CTR")
    return v


def get_gprs() -> dict[str, int]:
    """Returns {r0..r31: int}."""
    from ..gdb.registers import parse_dolphin_gprs

    session = get_session()
    session.ensure_connected()
    _refuse_if_watcher_running(session, "get_gprs")
    with session.gdb_lock:
        blob = session.stub.read_registers()
    return parse_dolphin_gprs(blob)


def get_sprs() -> dict[str, int]:
    """PC, MSR, CR, LR, CTR, XER. Skips any that the stub doesn't report."""
    session = get_session()
    session.ensure_connected()
    _refuse_if_watcher_running(session, "get_sprs")
    out: dict[str, int] = {}
    with session.gdb_lock:
        for name, num in (
            ("pc", PC),
            ("msr", MSR),
            ("cr", CR),
            ("lr", LR),
            ("ctr", CTR),
            ("xer", XER),
        ):
            v = session.stub.read_register(num)
            if v is not None:
                out[name] = v
    return out


def get_fprs() -> dict[str, float]:
    """f0..f31, each as a Python float (decoded from 8-byte IEEE 754 BE doubles)."""
    session = get_session()
    session.ensure_connected()
    _refuse_if_watcher_running(session, "get_fprs")
    out: dict[str, float] = {}
    with session.gdb_lock:
        for i in range(32):
            raw = session.stub.read_register_bytes(0x20 + i)
            if raw is not None and len(raw) == 8:
                try:
                    out[f"f{i}"] = parse_fpr_value(raw)
                except ValueError:
                    pass
    return out


def get_stack(depth: int = 4) -> list[dict[str, int]]:
    """
    Walk back `depth` frames using PPC's standard linkage:
      saved-LR at [sp + 4], previous sp at [sp].
    Returns frames from inner to outer: [{frame_sp, saved_lr}, ...].
    """
    session = get_session()
    session.ensure_connected()
    gprs = get_gprs()
    sp = gprs.get("r1", 0)
    out: list[dict[str, int]] = []
    for _ in range(max(0, depth)):
        if sp == 0:
            break
        try:
            blob = session.mem.read(sp, 8)
        except Exception as e:
            log.debug("stack walk stopped at sp=0x%08x: %s", sp, e)
            break
        prev_sp = int.from_bytes(blob[0:4], "big")
        saved_lr = int.from_bytes(blob[4:8], "big")
        out.append({"frame_sp": sp, "saved_lr": saved_lr})
        if prev_sp <= sp:
            break
        sp = prev_sp
    return out


# ---- step family ----

def step() -> dict[str, Any]:
    """
    Single-instruction step (`s` packet). Returns the new PC + disasm of the
    instruction now at PC.
    """
    session = get_session()
    session.ensure_connected()
    _refuse_if_watcher_running(session, "step")
    with session.gdb_lock:
        raw = session.stub.step(timeout=5.0)
        session.mark_paused()
    parsed = parse_stop_reply(raw)
    pc = parsed.pc
    if pc is None:
        # Some stubs don't include PC in step replies — fall back to a read.
        pc = get_pc()
    insn = _disasm_one_at(pc)
    return {"raw": raw, "pc": pc, "sp": parsed.sp, "instruction": insn}


def step_over() -> dict[str, Any]:
    """
    Step over the instruction at PC.

    For `bl <abs>` (branch-and-link to a known address), we set a temporary
    BP at PC+4 and continue, then remove it. For other branches we fall back
    to plain `step` and document the limitation per BUILD_PLAN §5.2.
    """
    from .breakpoint_tools import add_breakpoint, remove

    session = get_session()
    session.ensure_connected()
    _refuse_if_watcher_running(session, "step_over")
    pc = get_pc()
    insn = _disasm_one_at(pc)
    mnem = (insn.get("mnemonic") or "").lower()
    is_bl = mnem == "bl" and insn.get("branch_target") is not None
    if not is_bl:
        return step()
    # bl with a static target — skip past the call.
    return_addr = pc + 4
    bp = add_breakpoint(return_addr)
    try:
        resume()
        # Wait for that BP to fire (or anything else).
        import socket as _socket

        with session.gdb_lock:
            raw = session.stub.wait_for_stop(timeout=10.0)
            session.mark_paused()
        parsed = parse_stop_reply(raw)
        new_pc = parsed.pc if parsed.pc is not None else get_pc()
        return {"raw": raw, "pc": new_pc, "sp": parsed.sp, "instruction": _disasm_one_at(new_pc)}
    finally:
        try:
            remove(bp["id"])
        except Exception:
            log.exception("step_over: bp cleanup failed (continuing)")


def step_out() -> dict[str, Any]:
    """
    Run until the current function returns: set a BP at LR, continue.
    """
    from .breakpoint_tools import add_breakpoint, remove

    session = get_session()
    session.ensure_connected()
    _refuse_if_watcher_running(session, "step_out")
    lr = get_lr()
    bp = add_breakpoint(lr)
    try:
        resume()
        with session.gdb_lock:
            raw = session.stub.wait_for_stop(timeout=30.0)
            session.mark_paused()
        parsed = parse_stop_reply(raw)
        new_pc = parsed.pc if parsed.pc is not None else get_pc()
        return {"raw": raw, "pc": new_pc, "sp": parsed.sp, "instruction": _disasm_one_at(new_pc)}
    finally:
        try:
            remove(bp["id"])
        except Exception:
            log.exception("step_out: bp cleanup failed (continuing)")


def run_until(addr: int, timeout_s: float = 30.0) -> dict[str, Any]:
    """
    Set a BP at `addr`, continue, wait up to `timeout_s` for it (or any other
    stop) to fire, then remove the BP.
    """
    from .breakpoint_tools import add_breakpoint, remove

    session = get_session()
    session.ensure_connected()
    _refuse_if_watcher_running(session, "run_until")
    bp = add_breakpoint(addr)
    try:
        resume()
        import socket as _socket

        with session.gdb_lock:
            try:
                raw = session.stub.wait_for_stop(timeout=timeout_s)
            except _socket.timeout:
                return {"hit": False, "timed_out": True, "addr": addr}
            session.mark_paused()
        parsed = parse_stop_reply(raw)
        new_pc = parsed.pc if parsed.pc is not None else get_pc()
        return {
            "hit": True,
            "raw": raw,
            "pc": new_pc,
            "sp": parsed.sp,
            "reached_target": new_pc == addr,
        }
    finally:
        try:
            remove(bp["id"])
        except Exception:
            log.exception("run_until: bp cleanup failed (continuing)")


def _disasm_one_at(addr: int) -> dict | None:
    """Disasm a single instruction. Imports here to avoid cycle."""
    from .disasm_tools import disasm as _disasm

    try:
        out = _disasm(addr, count=1, with_gprs=False)
        return out[0] if out else None
    except Exception as e:
        log.debug("disasm at 0x%x failed: %s", addr, e)
        return None


# ---- registration ----

def register(mcp) -> None:
    @mcp.tool()
    def pause_tool() -> dict:
        """Send Ctrl+C-style interrupt to Dolphin. Returns the stop reply."""
        return pause()

    @mcp.tool()
    def resume_tool() -> dict:
        """Continue execution. Does not wait."""
        return resume()

    @mcp.tool()
    def is_paused_tool() -> bool:
        """Whether the emulator is currently paused at the stub."""
        return is_paused()

    @mcp.tool()
    def get_pc_tool() -> int:
        return get_pc()

    @mcp.tool()
    def get_lr_tool() -> int:
        return get_lr()

    @mcp.tool()
    def get_ctr_tool() -> int:
        return get_ctr()

    @mcp.tool()
    def get_gprs_tool() -> dict:
        """Read r0..r31 in one call (via the `g` packet)."""
        return get_gprs()

    @mcp.tool()
    def get_sprs_tool() -> dict:
        """Read PC, MSR, CR, LR, CTR, XER."""
        return get_sprs()

    @mcp.tool()
    def get_fprs_tool() -> dict:
        """Read f0..f31 as floats."""
        return get_fprs()

    @mcp.tool()
    def get_stack_tool(depth: int = 4) -> list:
        """Walk PPC stack frames; returns [{frame_sp, saved_lr}, ...]."""
        return get_stack(depth)

    @mcp.tool()
    def step_tool() -> dict:
        """Single-instruction step. Returns new PC + disasm of next instruction."""
        return step()

    @mcp.tool()
    def step_over_tool() -> dict:
        """
        Step over a `bl <abs>` call by setting a temporary BP at PC+4.
        Falls back to plain `step` for non-`bl` instructions (bctrl etc.).
        """
        return step_over()

    @mcp.tool()
    def step_out_tool() -> dict:
        """Continue until LR — run to the current function's return site."""
        return step_out()

    @mcp.tool()
    def run_until_tool(addr: int | str, timeout_s: float = 30.0) -> dict:
        """Set a BP at addr ("0x..." or decimal), continue, wait for it (or any stop) up to timeout_s."""
        return run_until(coerce_addr(addr), timeout_s=timeout_s)
