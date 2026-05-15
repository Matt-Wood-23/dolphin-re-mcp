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
    return [i.to_dict() for i in insns]


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
