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

from .auto_connect import start as start_auto_connect
from .logging_setup import setup_logging
from .symbol_map import load_from_env as load_symbol_map_from_env
from .tools import register_all

log = logging.getLogger(__name__)


def build_mcp() -> FastMCP:
    setup_logging()
    load_symbol_map_from_env()
    mcp = FastMCP("dolphin-re-mcp")
    register_all(mcp)
    start_auto_connect()
    log.info("FastMCP built; tools registered")
    return mcp


def main() -> None:
    mcp = build_mcp()
    # FastMCP default transport is stdio — what Claude Code expects.
    mcp.run()


if __name__ == "__main__":
    main()
