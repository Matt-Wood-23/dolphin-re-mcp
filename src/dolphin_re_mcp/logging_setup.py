"""
File-only logging for the MCP server.

MCP uses stdout for the JSON-RPC protocol — logging to stdout corrupts it.
All output goes to the path in DOLPHIN_RE_MCP_LOG (default ./logs/session.log).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

_DEFAULT = "logs/session.log"


def setup_logging() -> Path:
    log_path = Path(os.environ.get("DOLPHIN_RE_MCP_LOG") or _DEFAULT)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    debug = os.environ.get("DOLPHIN_RE_MCP_DEBUG", "").strip() in ("1", "true", "yes")
    level = logging.DEBUG if debug else logging.INFO

    root = logging.getLogger("dolphin_re_mcp")
    root.setLevel(level)
    # Idempotent — don't pile up handlers on reload.
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    root.addHandler(handler)
    root.propagate = False
    root.info("logging initialized; level=%s path=%s", logging.getLevelName(level), log_path)
    return log_path
