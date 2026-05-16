"""
Symbol map — load a CodeWarrior/Dolphin-style .map file once at server
startup, then resolve addresses → labels for tool-response enrichment.

File format (Dolphin-simple, no section headers):
    address  size  vaddr  align  name        section
    80004000 00029c 80004000  4   memcpy     Global
    802c2988 0001a4 802c2988  4   chacha_..  Global

Lines are indented by two spaces. Sizes are hex. `align` is decimal. Lines
that don't parse are skipped (counted, logged at debug). Non-data lines
(section headers, dashed separators) are ignored.

Lookup uses bisect on the sorted start-address list, then verifies the
queried address falls within the symbol's [addr, addr+size) range. Zero-
size entries are treated as covering only their start address.
"""
from __future__ import annotations

import bisect
import logging
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


ENV_VAR = "DOLPHIN_RE_MCP_SYMBOL_MAP"


@dataclass(frozen=True)
class Symbol:
    addr: int
    size: int
    name: str


class SymbolMap:
    """
    In-memory symbol table built from a Dolphin-style .map file.

    Thread-safe for reads; reloads grab a lock so a concurrent lookup
    sees either the old map or the new one, never a half-rebuilt state.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sorted_addrs: list[int] = []
        self._symbols: list[Symbol] = []          # parallel to _sorted_addrs
        self._exact: dict[int, Symbol] = {}
        self._path: Optional[Path] = None
        self._skipped: int = 0

    # ---- loading ----

    def load(self, path: str | os.PathLike[str]) -> int:
        """
        Parse `path` into the in-memory structure (replacing any prior load).
        Returns the number of symbols loaded. Raises on missing/unreadable
        file — callers that want graceful no-op behavior should check first.
        """
        p = Path(path)
        text = p.read_text(encoding="utf-8", errors="replace")
        syms, skipped = _parse_text(text)
        # Stable sort by addr, then by descending size so an enclosing symbol
        # appears before a contained symbol when they share a start address
        # (rare in CodeWarrior maps but cheap to handle).
        syms.sort(key=lambda s: (s.addr, -s.size))
        with self._lock:
            self._symbols = syms
            self._sorted_addrs = [s.addr for s in syms]
            self._exact = {s.addr: s for s in syms}
            self._path = p
            self._skipped = skipped
        log.info(
            "symbol_map: loaded %d symbols from %s (%d malformed lines skipped)",
            len(syms),
            p,
            skipped,
        )
        return len(syms)

    def clear(self) -> None:
        with self._lock:
            self._symbols = []
            self._sorted_addrs = []
            self._exact = {}
            self._path = None
            self._skipped = 0

    @property
    def path(self) -> Optional[Path]:
        return self._path

    def __len__(self) -> int:
        return len(self._symbols)

    @property
    def loaded(self) -> bool:
        return bool(self._symbols)

    # ---- lookup ----

    def lookup(self, addr: int) -> Optional[dict]:
        """
        Resolve `addr` → enrichment dict, or None if no symbol contains it.
        A symbol (a, s, name) contains addr iff a <= addr < a + max(s, 1).
        """
        with self._lock:
            if not self._symbols:
                return None
            # Exact-match fast path.
            exact = self._exact.get(addr)
            if exact is not None:
                return _to_lookup_dict(addr, exact)
            # bisect_right gives index of first start > addr; back up one.
            i = bisect.bisect_right(self._sorted_addrs, addr) - 1
            if i < 0:
                return None
            sym = self._symbols[i]
            end = sym.addr + (sym.size if sym.size > 0 else 1)
            if sym.addr <= addr < end:
                return _to_lookup_dict(addr, sym)
            return None

    def name_of(self, addr: int) -> Optional[str]:
        """Just the display string (e.g. 'memcpy+0x10'), or None."""
        d = self.lookup(addr)
        return d["display"] if d else None


# ---- parsing helpers ----

def _parse_text(text: str) -> tuple[list[Symbol], int]:
    syms: list[Symbol] = []
    skipped = 0
    seen: set[tuple[int, str]] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # Section headers and separators in CodeWarrior maps — skip.
        # Examples:
        #   ".text section layout"
        #   "  Starting        Virtual"
        #   "  ---------------- ----------------"
        if line.startswith("---") or line.startswith("Starting") or line.endswith("section layout"):
            continue
        sym = _parse_line(line)
        if sym is None:
            skipped += 1
            log.debug("symbol_map: skipped unparseable line: %r", raw)
            continue
        key = (sym.addr, sym.name)
        if key in seen:
            continue
        seen.add(key)
        syms.append(sym)
    return syms, skipped


def _parse_line(line: str) -> Optional[Symbol]:
    """
    Parse one stripped line of the Dolphin-simple map format.

    Expected columns: addr(hex) size(hex) vaddr(hex) align(dec) name [section]
    The name column is everything between align and a trailing tab/section
    marker. We accept any whitespace separator and just require the first
    four columns to be parseable as the right radices.
    """
    parts = line.split(None, 4)
    if len(parts) < 5:
        return None
    addr_s, size_s, _vaddr_s, align_s, rest = parts
    try:
        addr = int(addr_s, 16)
        size = int(size_s, 16)
        # align is decimal; tolerate hex-looking values too, but require it
        # to parse as some integer or we reject the line.
        int(align_s)
    except ValueError:
        return None
    # `rest` may be "name\tSection" or "name Section" — split on tab first,
    # fall back to splitting off a trailing section keyword.
    if "\t" in rest:
        name = rest.split("\t", 1)[0].strip()
    else:
        # Fall back: name is everything up to the last whitespace-separated
        # token *if* that token looks like a section name (Global, Local,
        # Weak, etc.). Otherwise treat the whole thing as the name.
        bits = rest.rsplit(None, 1)
        if len(bits) == 2 and bits[1] in {"Global", "Local", "Weak", "Common"}:
            name = bits[0].strip()
        else:
            name = rest.strip()
    if not name:
        return None
    return Symbol(addr=addr, size=size, name=name)


def _to_lookup_dict(addr: int, sym: Symbol) -> dict:
    off = addr - sym.addr
    display = sym.name if off == 0 else f"{sym.name}+0x{off:x}"
    return {
        "address": f"0x{addr:08x}",
        "name": sym.name,
        "symbol_address": f"0x{sym.addr:08x}",
        "offset_in_symbol": f"0x{off:x}",
        "display": display,
    }


# ---- module-level singleton ----

_singleton: Optional[SymbolMap] = None
_singleton_lock = threading.Lock()


def get_symbol_map() -> SymbolMap:
    """
    Process-wide SymbolMap. Lazy on first access; the server's startup hook
    populates it from the env var.
    """
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = SymbolMap()
        return _singleton


def load_from_env() -> int:
    """
    Initialize the singleton from $DOLPHIN_RE_MCP_SYMBOL_MAP.

    Returns:
      number of symbols loaded (0 if env var unset or file missing).

    Never raises — bad paths log a warning and leave the map empty so
    enrichment becomes a no-op.
    """
    sm = get_symbol_map()
    path = os.environ.get(ENV_VAR)
    if not path:
        log.info("symbol_map: %s unset; enrichment disabled", ENV_VAR)
        return 0
    p = Path(path)
    if not p.exists():
        log.warning(
            "symbol_map: %s=%s does not exist; enrichment disabled", ENV_VAR, path
        )
        return 0
    try:
        return sm.load(p)
    except OSError as e:
        log.warning("symbol_map: failed to read %s: %s", path, e)
        return 0


# ---- enrichment helpers used by tool wrappers ----

def enrich(addr: Optional[int]) -> Optional[dict]:
    """Look up `addr` in the singleton; return the dict or None."""
    if addr is None:
        return None
    return get_symbol_map().lookup(addr)


def name_of(addr: Optional[int]) -> Optional[str]:
    """Convenience: just the display string, or None."""
    if addr is None:
        return None
    return get_symbol_map().name_of(addr)
