"""
FastMCP entry point for dolphin-re-mcp.

Run as:
    python -m dolphin_re_mcp.server
or via console script:
    dolphin-re-mcp
"""
from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from .logging_setup import setup_logging
from .tools import register_all

log = logging.getLogger(__name__)


def build_mcp() -> FastMCP:
    setup_logging()
    mcp = FastMCP("dolphin-re-mcp")
    register_all(mcp)
    log.info("FastMCP built; tools registered")
    return mcp


def main() -> None:
    mcp = build_mcp()
    # FastMCP default transport is stdio — what Claude Code expects.
    mcp.run()


if __name__ == "__main__":
    main()
