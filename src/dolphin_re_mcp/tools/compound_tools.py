"""
Compound tools — call other tools internally; no new GDB primitives.

These are the agent's day-to-day workhorses; everything below is implemented
as orchestration over breakpoint_tools + execution_tools.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from ..memory.routing import coerce_addr
from ..symbol_map import enrich as _sym_enrich
from . import breakpoint_tools

log = logging.getLogger(__name__)


def trace_writes_to(
    addr: int,
    size: int = 4,
    duration_s: float = 10.0,
    captures: list[str] | None = None,
) -> list[dict]:
    """
    Cheatmine writer-trace in one tool call.

    Sets a write watchpoint on `addr`, runs the CPU for `duration_s`,
    captures every writer's PC + GPRs, then removes the watchpoint and
    returns the captured hits.

    The user just plays the game; this tool collects everything in the
    background via the StopWatcher.
    """
    if duration_s <= 0 or duration_s > 600:
        raise ValueError(f"duration_s must be in (0, 600]; got {duration_s}")
    captures = list(captures or ["gprs", "lr"])

    wp = breakpoint_tools.add_watchpoint(addr, size=size, on="write")
    bp_id = wp["id"]
    hits: list[dict] = []
    try:
        breakpoint_tools.capture_on_hit(bp_id, captures=captures, auto_resume=True)
        log.info("trace_writes_to 0x%x running for %.1fs ...", addr, duration_s)
        time.sleep(duration_s)
        hits = breakpoint_tools.get_capture_log(bp_id)
    finally:
        # Cleanup can fail (race with in-flight stop replies, stub state, etc.).
        # We already have `hits` — don't lose them to a cleanup exception.
        try:
            breakpoint_tools.stop_capturing(bp_id)
        except Exception:
            log.exception("trace_writes_to: stop_capturing raised; ignoring")
        try:
            breakpoint_tools.remove(bp_id)
        except Exception:
            log.exception("trace_writes_to: remove raised; ignoring")
    return hits


def trace_calls_to(
    entry_addr: int,
    duration_s: float = 10.0,
    captures: list[str] | None = None,
) -> list[dict]:
    """
    Trace every call to a known function entry point.

    Sets a sw breakpoint at `entry_addr`, captures r3..r10 (PPC arg regs) +
    LR on each hit. Useful when you know what function you want to log calls
    to but not who's calling it.
    """
    if duration_s <= 0 or duration_s > 600:
        raise ValueError(f"duration_s must be in (0, 600]; got {duration_s}")
    captures = list(captures or ["gprs", "lr"])

    bp = breakpoint_tools.add_breakpoint(entry_addr)
    bp_id = bp["id"]
    hits: list[dict] = []
    try:
        breakpoint_tools.capture_on_hit(bp_id, captures=captures, auto_resume=True)
        log.info("trace_calls_to 0x%x running for %.1fs ...", entry_addr, duration_s)
        time.sleep(duration_s)
        hits = breakpoint_tools.get_capture_log(bp_id)
    finally:
        try:
            breakpoint_tools.stop_capturing(bp_id)
        except Exception:
            log.exception("trace_calls_to: stop_capturing raised; ignoring")
        try:
            breakpoint_tools.remove(bp_id)
        except Exception:
            log.exception("trace_calls_to: remove raised; ignoring")
    return hits


def trace_until(
    until_pc: int | None = None,
    until_blr: bool = False,
    max_steps: int = 1000,
    capture: list[str] | None = None,
) -> list[dict]:
    """
    Step-by-step trace from the current PC, capturing per-instruction state.

    Stop conditions (whichever fires first):
      - until_pc=ADDR     : stop when PC reaches ADDR.
      - until_blr=True    : stop at the first blr / bctr (function return).
      - max_steps=N       : hard cap, always enforced.

    `capture` is a subset of {'gprs', 'fprs', 'mem_operands'}. The disasm is
    always recorded. For load/store ops with 'gprs' we resolve the EA. With
    'mem_operands' we also read u32 at that EA.

    Useful for walking overlay-blocked functions where the decompiler can't help.
    """
    from . import execution_tools
    from .disasm_tools import disasm as _disasm

    if max_steps <= 0:
        return []
    if until_pc is None and not until_blr and max_steps > 10_000:
        raise ValueError(
            "trace_until with no until_pc/until_blr is capped at max_steps=10000"
        )

    capture = list(capture or ["gprs"])
    cap_set = set(capture)
    timeline: list[dict] = []

    for i in range(max_steps):
        pc = execution_tools.get_pc()
        disasm_out = _disasm(pc, count=1, with_gprs=("gprs" in cap_set))
        insn = disasm_out[0] if disasm_out else None
        entry: dict = {"step": i, "pc": pc, "instruction": insn}

        if "gprs" in cap_set:
            entry["gprs"] = execution_tools.get_gprs()
        if "fprs" in cap_set and insn and insn.get("kind") == "fp_arith":
            entry["fprs"] = execution_tools.get_fprs()
        if "mem_operands" in cap_set and insn and insn.get("ea") is not None:
            try:
                from . import memory_tools

                blob = bytes.fromhex(memory_tools.read_mem(insn["ea"], 4)["hex"])
                entry["mem_value"] = int.from_bytes(blob, "big")
            except Exception:
                pass

        sym = _sym_enrich(pc)
        if sym is not None:
            entry["pc_symbol"] = sym["display"]
        timeline.append(entry)

        # Stop conditions evaluated AFTER recording — so the matching insn
        # appears in the timeline.
        if until_pc is not None and pc == until_pc:
            break
        if until_blr and insn and (insn.get("mnemonic") or "").lower() in ("blr", "bctr"):
            break

        try:
            execution_tools.step()
        except Exception as e:
            log.warning("trace_until: step failed at pc=0x%x: %s", pc, e)
            break

    return timeline


def register(mcp) -> None:
    @mcp.tool()
    def trace_writes_to_tool(
        addr: int | str,
        size: int = 4,
        duration_s: float = 10.0,
        captures: list[str] | None = None,
    ) -> list:
        """
        Arm a write watchpoint at addr ("0x..." or decimal string), run for
        duration_s, return every writer's captured state. Primary cheatmine
        workflow.
        """
        return trace_writes_to(coerce_addr(addr), size=size, duration_s=duration_s, captures=captures)

    @mcp.tool()
    def trace_calls_to_tool(
        entry_addr: int | str,
        duration_s: float = 10.0,
        captures: list[str] | None = None,
    ) -> list:
        """Arm a sw BP at entry_addr ("0x..." or decimal), run for duration_s, return every caller's state."""
        return trace_calls_to(coerce_addr(entry_addr), duration_s=duration_s, captures=captures)

    @mcp.tool()
    def trace_until_tool(
        until_pc: str | None = None,
        until_blr: bool = False,
        max_steps: int = 1000,
        capture: list[str] | None = None,
    ) -> list:
        """
        Step-by-step trace from current PC. Stops at until_pc ("0x..." or
        decimal string), until_blr, or max_steps (whichever first). `capture`
        ⊆ {'gprs','fprs','mem_operands'}. Useful for walking overlay-blocked
        functions.
        """
        return trace_until(
            until_pc=coerce_addr(until_pc) if until_pc is not None else None,
            until_blr=until_blr,
            max_steps=max_steps,
            capture=capture,
        )
