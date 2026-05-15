"""MCP tool modules. Each registers its tools on an FastMCP instance via `register(mcp)`."""

from . import (
    breakpoint_tools,
    compound_tools,
    disasm_tools,
    execution_tools,
    memory_tools,
)

__all__ = [
    "breakpoint_tools",
    "compound_tools",
    "disasm_tools",
    "execution_tools",
    "memory_tools",
    "register_all",
]


def register_all(mcp) -> None:
    """Register every tool group on the given FastMCP instance."""
    memory_tools.register(mcp)
    execution_tools.register(mcp)
    breakpoint_tools.register(mcp)
    disasm_tools.register(mcp)
    compound_tools.register(mcp)
