"""
Disasm tools — Capstone-backed PPC disassembly with the classifier from
disasm/ppc.py. Memory bytes come from the active memory backend (attach
preferred, GDB fallback), so disasm works whether the CPU is paused or
running.
"""
from __future__ import annotations

import logging
from typing import Any

from ..disasm.ppc import disasm_bytes, post_process_imm_load_pairs
from ..memory.routing import coerce_addr
from ..session import get_session
from ..symbol_map import enrich as _sym_enrich

log = logging.getLogger(__name__)


def disasm(addr: int, count: int = 1, with_gprs: bool = False) -> list[dict]:
    """
    Disassemble `count` instructions starting at `addr`.

    If `with_gprs` is True (and the CPU is paused or attach is available),
    also read the current GPR snapshot so effective addresses can be
    computed for load/store instructions.
    """
    if count <= 0:
        return []
    session = get_session()
    session.ensure_connected()
    blob = session.mem.read(addr, count * 4)
    gprs: dict[str, int] | None = None
    if with_gprs:
        # Avoid pulling in execution_tools at import time.
        from .execution_tools import get_gprs as _get_gprs

        try:
            gprs = _get_gprs()
        except Exception as e:
            log.debug("disasm: could not read gprs (continuing without): %s", e)
    insns = disasm_bytes(addr, blob, gprs=gprs)
    post_process_imm_load_pairs(insns)
    out = [i.to_dict() for i in insns]
    _annotate_targets(out)
    return out


def _annotate_targets(insns: list[dict]) -> None:
    """
    Attach a `comment` field naming the symbol that a labeled target resolves
    to. Sources of "target" we consider:
      - branch_target: bl/b/bne/etc. to a known address
      - imm_value:     lis+addi/ori pair fused into a 32-bit constant
      - ea:            load/store effective address (only when gprs were
                       supplied at disasm time)
    `branch_target` is preferred; otherwise we fall back to ea/imm_value.
    Lines without a labeled target are left untouched.
    """
    for ins in insns:
        target: int | None = None
        for key in ("branch_target", "imm_value", "ea"):
            v = ins.get(key)
            if isinstance(v, int):
                target = v
                break
        if target is None:
            continue
        sym = _sym_enrich(target)
        if sym is not None:
            ins["comment"] = f"-> {sym['display']}"


def register(mcp) -> None:
    @mcp.tool()
    def disasm_tool(addr: int | str, count: int = 1, with_gprs: bool = False) -> list:
        """
        Disassemble `count` PPC instructions starting at `addr` ("0x..." or
        decimal string). With `with_gprs=True`, computes effective addresses
        for load/store ops and post-processes lis+addi/ori pairs into single
        imm-load entries.
        """
        return disasm(coerce_addr(addr), count=count, with_gprs=with_gprs)
