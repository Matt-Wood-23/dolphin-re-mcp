"""
Virtual address → (region, offset) routing for GameCube / Wii memory.

Wii memory layout we care about:
  MEM1: 0x80000000 .. 0x81800000  (24 MB, main RAM mirror)
  MEM2: 0x90000000 .. 0x94000000  (64 MB, expansion RAM)

Caches (0xC0000000+) and the mirror at 0x00000000 are deliberately unsupported —
the project only uses 0x8XXXXXXX / 0x9XXXXXXX addresses.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

MEM1_BASE = 0x80000000
MEM1_SIZE = 0x01800000  # 24 MB
MEM1_END = MEM1_BASE + MEM1_SIZE

MEM2_BASE = 0x90000000
MEM2_SIZE = 0x04000000  # 64 MB
MEM2_END = MEM2_BASE + MEM2_SIZE


class Region(str, Enum):
    MEM1 = "MEM1"
    MEM2 = "MEM2"


class AddressOutOfRange(ValueError):
    """Virtual address falls outside MEM1 or MEM2."""


@dataclass(frozen=True)
class RoutedAddress:
    region: Region
    offset: int
    size: int  # bytes available from offset to end of region


def route(addr: int, size: int = 1) -> RoutedAddress:
    """
    Map a virtual addr to (region, offset_in_region).

    Raises AddressOutOfRange if either the start or the [addr, addr+size)
    range escapes a single contiguous region (no MEM1↔MEM2 straddling).
    """
    if size <= 0:
        raise ValueError(f"size must be positive, got {size}")
    if MEM1_BASE <= addr < MEM1_END:
        end = addr + size
        if end > MEM1_END:
            raise AddressOutOfRange(
                f"0x{addr:08x}+{size} crosses MEM1 end 0x{MEM1_END:08x}"
            )
        return RoutedAddress(Region.MEM1, addr - MEM1_BASE, MEM1_END - addr)
    if MEM2_BASE <= addr < MEM2_END:
        end = addr + size
        if end > MEM2_END:
            raise AddressOutOfRange(
                f"0x{addr:08x}+{size} crosses MEM2 end 0x{MEM2_END:08x}"
            )
        return RoutedAddress(Region.MEM2, addr - MEM2_BASE, MEM2_END - addr)
    raise AddressOutOfRange(f"0x{addr:08x} is not in MEM1 or MEM2")


def is_valid(addr: int, size: int = 1) -> bool:
    try:
        route(addr, size)
        return True
    except (AddressOutOfRange, ValueError):
        return False


def coerce_addr(x: str | int) -> int:
    """
    Parse an MCP-tool address argument. Accepts:
      - int (passed straight through — already decoded by the caller)
      - hex string ("0x806BBC74")
      - decimal string ("2154544244")

    Bare hex without prefix (e.g. "806BBC74") is rejected so an ambiguous
    value can't be silently misread as decimal — the caller must say which
    base they meant.

    Accepting both `int` and `str` lets MCP tool wrappers declare
    `addr: int | str` and have callers pass either form, which avoids
    the agent doing hex→decimal mental conversion and getting it wrong.
    """
    if isinstance(x, int) and not isinstance(x, bool):
        return x
    if not isinstance(x, str):
        raise TypeError(f"address must be a string or int, got {type(x).__name__}")
    s = x.strip()
    if not s:
        raise ValueError("address string is empty")
    try:
        return int(s, 0)
    except ValueError as e:
        raise ValueError(
            f"address {x!r} not parseable; use '0x...' hex or plain decimal"
        ) from e
