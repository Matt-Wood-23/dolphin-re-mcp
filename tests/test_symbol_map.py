"""
Tests for the symbol-map parser and lookup.

No Dolphin connection required — these tests operate on small in-memory
fixtures and verify parse behavior, range lookup, and the env-var-driven
no-op path.
"""
from __future__ import annotations

import textwrap

import pytest

from dolphin_re_mcp import symbol_map
from dolphin_re_mcp.symbol_map import SymbolMap, _parse_line, _parse_text


FIXTURE = textwrap.dedent(
    """\
      80004000 00029c 80004000  4 memcpy 	Global
      8000429c 0000b4 8000429c  4 fill_mem 	Global
      80004350 000030 80004350  4 memset 	Global
      802c2988 0001a4 802c2988  4 chacha_spawn_enter 	Global
      806bd360 000400 806bd360  4 g_chacha_work 	Global
      806bd760 000000 806bd760  4 zero_sized_marker 	Global
      80700000 000010 80700000  4 short_blob 	Global

      not a real line at all
      80abc000  oops not hex 80abc000  4 broken 	Global
    """
)


def test_parse_text_counts_skips():
    syms, skipped = _parse_text(FIXTURE)
    # 7 valid + 2 malformed lines (the blank one is silently dropped, not counted)
    names = {s.name for s in syms}
    assert "memcpy" in names
    assert "chacha_spawn_enter" in names
    assert skipped == 2


def test_parse_line_basic():
    sym = _parse_line("80004000 00029c 80004000  4 memcpy 	Global")
    assert sym is not None
    assert sym.addr == 0x80004000
    assert sym.size == 0x29c
    assert sym.name == "memcpy"


def test_parse_line_no_tab_name():
    # No tab before section — still parseable, name strips off the trailing
    # "Global" / "Local" / "Weak" / "Common" token.
    sym = _parse_line("80004000 00029c 80004000 4 memcpy Global")
    assert sym is not None
    assert sym.name == "memcpy"


def test_parse_line_rejects_malformed():
    assert _parse_line("not a line") is None
    assert _parse_line("zzzz 0001 80004000 4 memcpy") is None  # bad hex
    assert _parse_line("80004000 00029c 80004000 4") is None    # missing name


def test_lookup_exact_match(tmp_path):
    p = tmp_path / "map.txt"
    p.write_text(FIXTURE)
    sm = SymbolMap()
    sm.load(p)

    hit = sm.lookup(0x806BD360)
    assert hit is not None
    assert hit["name"] == "g_chacha_work"
    assert hit["offset_in_symbol"] == "0x0"
    assert hit["display"] == "g_chacha_work"
    assert hit["symbol_address"] == "0x806bd360"
    assert hit["address"] == "0x806bd360"


def test_lookup_inside_body(tmp_path):
    p = tmp_path / "map.txt"
    p.write_text(FIXTURE)
    sm = SymbolMap()
    sm.load(p)

    # chacha_spawn_enter is 0x802c2988 + 0x1a4. 0x802c29d4 is +0x4c.
    hit = sm.lookup(0x802C29D4)
    assert hit is not None
    assert hit["name"] == "chacha_spawn_enter"
    assert hit["offset_in_symbol"] == "0x4c"
    assert hit["display"] == "chacha_spawn_enter+0x4c"


def test_lookup_gap_returns_none(tmp_path):
    p = tmp_path / "map.txt"
    p.write_text(FIXTURE)
    sm = SymbolMap()
    sm.load(p)

    # Between memset (ends at 0x80004380) and chacha_spawn_enter (0x802c2988)
    # — there's nothing labeled here.
    assert sm.lookup(0x80100000) is None


def test_lookup_just_past_end_returns_none(tmp_path):
    """memcpy spans [0x80004000, 0x80004000 + 0x29c). The byte at +0x29c is
    fill_mem (0x8000429c), not memcpy."""
    p = tmp_path / "map.txt"
    p.write_text(FIXTURE)
    sm = SymbolMap()
    sm.load(p)

    hit = sm.lookup(0x8000429c)
    assert hit is not None
    assert hit["name"] == "fill_mem"


def test_lookup_zero_size_symbol(tmp_path):
    """A zero-size symbol should match only its exact start address."""
    p = tmp_path / "map.txt"
    p.write_text(FIXTURE)
    sm = SymbolMap()
    sm.load(p)

    hit = sm.lookup(0x806BD760)
    assert hit is not None
    assert hit["name"] == "zero_sized_marker"
    # one byte past — no longer in zero_sized_marker, and nothing else covers it
    assert sm.lookup(0x806BD761) is None


def test_lookup_empty_map_returns_none():
    sm = SymbolMap()
    assert sm.lookup(0x80004000) is None


def test_reload_replaces_contents(tmp_path):
    p1 = tmp_path / "m1.txt"
    p1.write_text("  80004000 000010 80004000  4 alpha \tGlobal\n")
    p2 = tmp_path / "m2.txt"
    p2.write_text("  80004000 000010 80004000  4 beta \tGlobal\n")
    sm = SymbolMap()
    sm.load(p1)
    assert sm.lookup(0x80004000)["name"] == "alpha"
    sm.load(p2)
    assert sm.lookup(0x80004000)["name"] == "beta"


def test_load_from_env_missing_file(monkeypatch, tmp_path):
    monkeypatch.setenv("DOLPHIN_RE_MCP_SYMBOL_MAP", str(tmp_path / "nope.map"))
    # Reset singleton so the test isn't sensitive to prior tests.
    symbol_map._singleton = None
    n = symbol_map.load_from_env()
    assert n == 0
    assert symbol_map.get_symbol_map().loaded is False


def test_load_from_env_unset(monkeypatch):
    monkeypatch.delenv("DOLPHIN_RE_MCP_SYMBOL_MAP", raising=False)
    symbol_map._singleton = None
    n = symbol_map.load_from_env()
    assert n == 0
    assert symbol_map.enrich(0x80004000) is None


def test_load_from_env_happy_path(monkeypatch, tmp_path):
    p = tmp_path / "real.map"
    p.write_text(FIXTURE)
    monkeypatch.setenv("DOLPHIN_RE_MCP_SYMBOL_MAP", str(p))
    symbol_map._singleton = None
    n = symbol_map.load_from_env()
    assert n >= 5
    hit = symbol_map.enrich(0x802C29D4)
    assert hit is not None
    assert hit["display"] == "chacha_spawn_enter+0x4c"


def test_enrich_handles_none():
    assert symbol_map.enrich(None) is None
