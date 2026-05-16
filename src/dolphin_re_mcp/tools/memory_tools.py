"""
Memory tools — read/write live game state, follow pointers, search, snapshot.

All addresses use the MH Tri virtual address space (0x80xxxxxx / 0x90xxxxxx).
Reads prefer the process-attach backend (no JIT pause); writes too. Falls back
to GDB `m`/`M` packets if attach isn't available.
"""
from __future__ import annotations

import logging
import struct
from pathlib import Path
from typing import Any

from ..memory.routing import (
    MEM1_BASE,
    MEM1_SIZE,
    MEM2_BASE,
    MEM2_SIZE,
    AddressOutOfRange,
    Region,
    coerce_addr,
    is_valid,
    route,
)
from ..session import get_session
from ..symbol_map import enrich as _sym_enrich, get_symbol_map

log = logging.getLogger(__name__)


class WriteRefused(RuntimeError):
    """write_mem called without confirm=True."""


class DumpDirNotConfigured(RuntimeError):
    """MHTRI_DUMPS_DIR env var was needed and not set."""


# ----- primitives -----

def _read(addr: int, size: int) -> bytes:
    session = get_session()
    session.ensure_connected()
    return session.mem.read(addr, size)


def _write(addr: int, data: bytes) -> None:
    session = get_session()
    session.ensure_connected()
    session.mem.write(addr, data)


# ----- tool implementations (also callable as plain functions for tests) -----

def read_mem(addr: int, size: int) -> dict[str, Any]:
    data = _read(addr, size)
    return {"addr": addr, "size": size, "hex": data.hex()}


def read_u8(addr: int) -> int:
    return _read(addr, 1)[0]


def read_u16(addr: int) -> int:
    return int.from_bytes(_read(addr, 2), "big")


def read_u32(addr: int) -> int:
    return int.from_bytes(_read(addr, 4), "big")


def read_s32(addr: int) -> int:
    return struct.unpack(">i", _read(addr, 4))[0]


def read_f32(addr: int) -> float:
    return struct.unpack(">f", _read(addr, 4))[0]


def read_f64(addr: int) -> float:
    return struct.unpack(">d", _read(addr, 8))[0]


# ----- dual-format wrappers (return both raw int AND hex string) -----

def _u_dict(addr: int, value: int, hex_width: int) -> dict:
    """Format a uN read as {addr, value, hex}. hex_width is digit count."""
    return {
        "addr": f"0x{addr:08x}",
        "value": value,
        "hex": f"0x{value:0{hex_width}x}",
    }


def read_u8_dict(addr: int) -> dict:
    return _u_dict(addr, read_u8(addr), hex_width=2)


def read_u16_dict(addr: int) -> dict:
    return _u_dict(addr, read_u16(addr), hex_width=4)


def read_u32_dict(addr: int) -> dict:
    return _u_dict(addr, read_u32(addr), hex_width=8)


def read_s32_dict(addr: int) -> dict:
    v = read_s32(addr)
    # For signed, expose the unsigned 32-bit hex too (useful when the bits
    # look like an address even though the value is being read as signed).
    return {
        "addr": f"0x{addr:08x}",
        "value": v,
        "hex": f"0x{v & 0xFFFFFFFF:08x}",
    }


def read_ptr(addr: int) -> dict:
    """
    Read 4 bytes at `addr`, interpret as a pointer. Identical wire-shape to
    read_u32 but the response leads with `hex` to make pointer chains scan-
    able. Use when the value at `addr` is conceptually an address.
    """
    v = read_u32(addr)
    return {
        "addr": f"0x{addr:08x}",
        "hex": f"0x{v:08x}",
        "value": v,
    }


def dump_hex(addr: int, size: int, width: int = 16) -> dict:
    """
    `xxd`-style memory dump. Returns a list of formatted lines plus the raw
    hex string. `width` is the bytes-per-line (must be a multiple of 4 for
    PPC word alignment readability).
    """
    if size <= 0:
        return {"addr": f"0x{addr:08x}", "size": 0, "lines": [], "hex": ""}
    if size > 4096:
        raise ValueError(f"dump_hex size {size} exceeds 4096-byte safety cap")
    if width < 4 or width % 4 != 0:
        raise ValueError(f"width must be a positive multiple of 4; got {width}")
    blob = _read(addr, size)
    lines: list[str] = []
    for off in range(0, size, width):
        row = blob[off : off + width]
        # Hex columns: group by 4 bytes (one PPC word) with double space.
        groups: list[str] = []
        for g in range(0, len(row), 4):
            groups.append(row[g : g + 4].hex())
        hex_col = "  ".join(groups).ljust(width * 2 + (width // 4 - 1) * 1)
        # Printable-ASCII column.
        ascii_col = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"0x{addr + off:08x}: {hex_col}  {ascii_col}")
    return {
        "addr": f"0x{addr:08x}",
        "size": size,
        "lines": lines,
        "hex": blob.hex(),
    }


def write_mem(addr: int, hex_data: str, confirm: bool = False) -> dict[str, Any]:
    """
    Write `hex_data` (hex string) to `addr`. Requires confirm=True — guards
    against the agent accidentally corrupting live game state.
    """
    if not confirm:
        raise WriteRefused(
            "write_mem requires confirm=True to guard against accidental writes"
        )
    data = bytes.fromhex(hex_data)
    _write(addr, data)
    return {"addr": addr, "written": len(data)}


def follow_pointer(addr: int, *offsets: int) -> int:
    """
    Walk a pointer chain. read u32 at addr, add offsets[0], read u32, ...
    Final return = last dereference + last offset *not applied*. Convention:
    follow_pointer(slot1_addr, 0x10, 0x4) →
        ptr = u32[slot1_addr + 0x10]
        return ptr + 0x4   (NOT dereferenced)
    """
    if not offsets:
        return read_u32(addr)
    cursor = read_u32(addr) + offsets[0]
    for off in offsets[1:]:
        cursor = read_u32(cursor) + off
    return cursor


def is_valid_ptr(addr: int) -> bool:
    """Range-check + readability probe at addr (1 byte)."""
    if not is_valid(addr, 1):
        return False
    try:
        _read(addr, 1)
        return True
    except Exception:
        return False


# ----- structured reads -----

# Layout = list of (name, kind, offset)
# kind = 'u8' | 'u16' | 'u32' | 's32' | 'f32' | 'f64' | ('bytes', N)
def read_struct(addr: int, layout: list[tuple]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for entry in layout:
        if len(entry) == 3:
            name, kind, off = entry
        else:
            raise ValueError(f"bad layout entry: {entry!r}")
        ea = addr + off
        if kind == "u8":
            out[name] = read_u8(ea)
        elif kind == "u16":
            out[name] = read_u16(ea)
        elif kind == "u32":
            out[name] = read_u32(ea)
        elif kind == "s32":
            out[name] = read_s32(ea)
        elif kind == "f32":
            out[name] = read_f32(ea)
        elif kind == "f64":
            out[name] = read_f64(ea)
        elif isinstance(kind, (list, tuple)) and len(kind) == 2 and kind[0] == "bytes":
            out[name] = _read(ea, int(kind[1])).hex()
        else:
            raise ValueError(f"unsupported kind {kind!r} for {name!r}")
    return out


# ----- search -----

def search_mem(pattern_hex: str, region: str = "MEM1") -> list[int]:
    """Find all occurrences of `pattern_hex` in the named region. Returns vaddrs."""
    pat = bytes.fromhex(pattern_hex)
    if not pat:
        raise ValueError("empty pattern")
    if region.upper() == "MEM1":
        base, size = MEM1_BASE, MEM1_SIZE
    elif region.upper() == "MEM2":
        base, size = MEM2_BASE, MEM2_SIZE
    else:
        raise ValueError(f"unknown region {region!r}; expected MEM1 or MEM2")
    # Read in chunks (4 MB) to avoid one huge buffer. Overlap by len(pat)-1.
    CHUNK = 4 * 1024 * 1024
    hits: list[int] = []
    cursor = 0
    overlap = len(pat) - 1
    prev_tail = b""
    while cursor < size:
        n = min(CHUNK, size - cursor)
        chunk = _read(base + cursor, n)
        buf = prev_tail + chunk
        start = 0
        while True:
            i = buf.find(pat, start)
            if i < 0:
                break
            # Translate buf-relative index → vaddr
            vaddr = base + cursor + (i - len(prev_tail))
            hits.append(vaddr)
            start = i + 1
        prev_tail = chunk[-overlap:] if overlap > 0 else b""
        cursor += n
    return hits


# ----- snapshot / diff -----

def _dump_dir() -> Path:
    session = get_session()
    if not session.dumps_dir:
        raise DumpDirNotConfigured(
            "MHTRI_DUMPS_DIR env var not set; cannot write/read dumps"
        )
    return Path(session.dumps_dir)


def snapshot_to_dump(scenario_name: str) -> dict[str, str]:
    """Bulk read MEM1 + MEM2 and write them as `<scenario>.mem1.raw` / `.mem2.raw`."""
    dump_dir = _dump_dir()
    dump_dir.mkdir(parents=True, exist_ok=True)
    safe = "".join(c for c in scenario_name if c.isalnum() or c in "._-")
    if not safe:
        raise ValueError("scenario_name produced empty filename after sanitization")
    mem1_path = dump_dir / f"{safe}.mem1.raw"
    mem2_path = dump_dir / f"{safe}.mem2.raw"
    mem1_path.write_bytes(_read(MEM1_BASE, MEM1_SIZE))
    mem2_path.write_bytes(_read(MEM2_BASE, MEM2_SIZE))
    return {"mem1_path": str(mem1_path), "mem2_path": str(mem2_path)}


def diff_live_vs_dump(addr: int, size: int, dump_path: str) -> list[dict]:
    """Compare live memory vs a slice of a saved dump. Returns differing offsets."""
    p = Path(dump_path)
    if not p.exists():
        raise FileNotFoundError(f"dump file not found: {dump_path}")
    # Figure out which region the addr is in, derive file offset.
    routed = route(addr, size)
    blob = p.read_bytes()
    file_off = routed.offset
    if file_off + size > len(blob):
        raise ValueError(
            f"dump {dump_path} too small: offset {file_off}+{size} > {len(blob)}"
        )
    live = _read(addr, size)
    saved = blob[file_off : file_off + size]
    out: list[dict] = []
    for i, (a, b) in enumerate(zip(live, saved)):
        if a != b:
            out.append({"offset": i, "addr": addr + i, "live": a, "dump": b})
    return out


# ----- registration -----

def register(mcp) -> None:
    # All `addr` params are STRINGS — pass "0x806BBC74" or decimal "2154544244".
    # JSON has no hex literal, so requiring a string lets the caller write hex
    # naturally and avoids in-head decimal-conversion bugs.

    @mcp.tool()
    def read_mem_tool(addr: int | str, size: int) -> dict:
        """Read `size` bytes from MH Tri virtual addr. addr is "0x..." or decimal string."""
        return read_mem(coerce_addr(addr), size)

    @mcp.tool()
    def read_u8_tool(addr: int | str) -> dict:
        """Read a single byte at addr ("0x..." or decimal). Returns {addr, value, hex}."""
        return read_u8_dict(coerce_addr(addr))

    @mcp.tool()
    def read_u16_tool(addr: int | str) -> dict:
        """Read a big-endian u16 at addr ("0x..." or decimal). Returns {addr, value, hex}."""
        return read_u16_dict(coerce_addr(addr))

    @mcp.tool()
    def read_u32_tool(addr: int | str) -> dict:
        """Read a big-endian u32 at addr ("0x..." or decimal). Returns {addr, value, hex}."""
        return read_u32_dict(coerce_addr(addr))

    @mcp.tool()
    def read_s32_tool(addr: int | str) -> dict:
        """Read a big-endian s32 at addr ("0x..." or decimal). Returns {addr, value (signed), hex (unsigned 32-bit)}."""
        return read_s32_dict(coerce_addr(addr))

    @mcp.tool()
    def read_ptr_tool(addr: int | str) -> dict:
        """
        Read 4 bytes at addr ("0x..." or decimal), interpret as pointer. Same
        wire shape as read_u32 but the response leads with `hex` for
        readability. Use for pointer chains.
        """
        return read_ptr(coerce_addr(addr))

    @mcp.tool()
    def dump_hex_tool(addr: int | str, size: int, width: int = 16) -> dict:
        """
        xxd-style hex dump of `size` bytes starting at `addr` ("0x..." or
        decimal string). `width` is bytes-per-line (default 16; must be a
        multiple of 4). Returns formatted lines + raw hex. Capped at 4096
        bytes per call.
        """
        return dump_hex(coerce_addr(addr), size, width)

    @mcp.tool()
    def read_f32_tool(addr: int | str) -> float:
        """Read a big-endian IEEE 754 single-precision float at addr ("0x..." or decimal)."""
        return read_f32(coerce_addr(addr))

    @mcp.tool()
    def read_f64_tool(addr: int | str) -> float:
        """Read a big-endian IEEE 754 double-precision float at addr ("0x..." or decimal)."""
        return read_f64(coerce_addr(addr))

    @mcp.tool()
    def write_mem_tool(addr: int | str, hex_data: str, confirm: bool = False) -> dict:
        """Write `hex_data` (hex) to `addr` ("0x..." or decimal). Requires confirm=True."""
        return write_mem(coerce_addr(addr), hex_data, confirm=confirm)

    @mcp.tool()
    def follow_pointer_tool(addr: int | str, offsets: list[int]) -> int:
        """Walk a pointer chain starting at addr ("0x..." or decimal). Offsets stay int."""
        return follow_pointer(coerce_addr(addr), *offsets)

    @mcp.tool()
    def is_valid_ptr_tool(addr: int | str) -> bool:
        """Range-check + readability probe at addr ("0x..." or decimal)."""
        return is_valid_ptr(coerce_addr(addr))

    @mcp.tool()
    def read_struct_tool(addr: int | str, layout: list[list]) -> dict:
        """
        Read a structured layout. addr is "0x..." or decimal. `layout` = list
        of [name, kind, offset] where kind is one of 'u8','u16','u32','s32',
        'f32','f64', or ['bytes', N]. Offsets within the layout stay int.
        """
        normalized = [tuple(e) for e in layout]
        return read_struct(coerce_addr(addr), normalized)

    @mcp.tool()
    def search_mem_tool(pattern_hex: str, region: str = "MEM1") -> list[int]:
        """Find every occurrence of `pattern_hex` in MEM1 or MEM2."""
        return search_mem(pattern_hex, region)

    @mcp.tool()
    def snapshot_to_dump_tool(scenario_name: str) -> dict:
        """Write MEM1+MEM2 to the configured dumps dir as `<scenario>.{mem1,mem2}.raw`."""
        return snapshot_to_dump(scenario_name)

    @mcp.tool()
    def diff_live_vs_dump_tool(addr: int | str, size: int, dump_path: str) -> list[dict]:
        """Compare live memory at addr ("0x..." or decimal) against a slice of a saved dump."""
        return diff_live_vs_dump(coerce_addr(addr), size, dump_path)

    @mcp.tool()
    def health_check_tool() -> dict:
        """Connection state, attach status, BP count."""
        return get_session().health()

    @mcp.tool()
    def stub_diag_tool(last_n: int = 32) -> dict:
        """
        Dump the GDB stub's diagnostic ring buffer — the last `last_n` packet
        events (sent/recv/oob/note) with relative timestamps and latency.
        Use this after a wedge or unexpected behavior to see the exact
        sequence of packets that preceded it.

        `dir` values:
          - sent: client → stub
          - recv: stub → client (solicited reply)
          - oob:  stub → client (out-of-band stop reply during another ack)
          - note: free-form annotation injected via record_note()

        `rel_ms` is milliseconds relative to "now" (0 = most recent, negative
        = ms ago). `latency_ms` on a `recv` is the round-trip from the most
        recent `sent`.
        """
        s = get_session()
        events = s.stub.diag_snapshot(last_n=last_n)
        return {
            "count": len(events),
            "pending_replies": len(s.stub._pending_replies),
            "events": events,
        }

    @mcp.tool()
    def addr_info_tool(addr: int | str) -> dict:
        """
        Conversion + range-check for an address, plus symbol lookup. Accepts
        hex ("0x806adac4"), decimal string, or int. Returns {decimal, hex,
        region, valid, mem1_offset|mem2_offset, symbol?}. Cheap, read-only —
        the canonical "what is this address" tool.
        """
        n = coerce_addr(addr)
        out: dict = {"decimal": n, "hex": f"0x{n:08x}"}
        try:
            r = route(n, 1)
            out["region"] = r.region.value
            out["valid"] = True
            if r.region == Region.MEM1:
                out["mem1_offset"] = r.offset
            else:
                out["mem2_offset"] = r.offset
        except (AddressOutOfRange, ValueError):
            out["region"] = None
            out["valid"] = False
        sym = _sym_enrich(n)
        if sym is not None:
            out["symbol"] = sym
        return out

    @mcp.tool()
    def resolve_addr_tool(addr: int | str) -> dict:
        """
        Resolve `addr` ("0x..." or decimal string) to its enclosing symbol
        from the loaded .map file. Returns {address, name, symbol_address,
        offset_in_symbol, display} for a hit, or {address, name: null} when
        no symbol contains the address (or no map is loaded).
        """
        try:
            n = coerce_addr(addr)
        except (ValueError, TypeError) as e:
            return {"error": "invalid address", "input": addr, "detail": str(e)}
        sym = _sym_enrich(n)
        if sym is None:
            return {"address": f"0x{n:08x}", "name": None}
        return sym

    @mcp.tool()
    def reload_symbol_map_tool(path: str | None = None) -> dict:
        """
        Reparse the symbol map. With no `path`, uses
        $DOLPHIN_RE_MCP_SYMBOL_MAP. Returns {loaded: N, path: str, skipped:
        N}. Use after exporting a fresh map from Ghidra so enrichment picks
        up new symbols without restarting the MCP.
        """
        import os as _os

        sm = get_symbol_map()
        target = path or _os.environ.get("DOLPHIN_RE_MCP_SYMBOL_MAP")
        if not target:
            return {"loaded": 0, "path": None, "error": "no path provided and DOLPHIN_RE_MCP_SYMBOL_MAP unset"}
        from pathlib import Path as _Path
        p = _Path(target)
        if not p.exists():
            return {"loaded": 0, "path": str(p), "error": "file does not exist"}
        try:
            n = sm.load(p)
        except OSError as e:
            return {"loaded": 0, "path": str(p), "error": f"read failed: {e}"}
        log.info("reload_symbol_map_tool: loaded %d symbols from %s", n, p)
        return {"loaded": n, "path": str(p), "skipped": sm._skipped}
