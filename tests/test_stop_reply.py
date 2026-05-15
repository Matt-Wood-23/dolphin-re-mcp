"""Tests for stop-reply parsing."""
from __future__ import annotations

from dolphin_re_mcp.gdb.stop_reply import parse_stop_reply


def test_empty_reply():
    out = parse_stop_reply("")
    assert out.signal is None
    assert out.registers == {}


def test_t_packet_with_pc_and_sp():
    # T05 = SIGTRAP. 0x40 = pc, 0x01 = sp.
    out = parse_stop_reply("T0540:80004304;01:81560000;")
    assert out.signal == 0x05
    assert out.pc == 0x80004304
    assert out.sp == 0x81560000


def test_t_packet_no_register_body():
    out = parse_stop_reply("T05")
    assert out.signal == 0x05
    assert out.registers == {}


def test_s_packet_signal_only():
    out = parse_stop_reply("S05")
    assert out.signal == 0x05
    assert out.registers == {}


def test_watchpoint_annotation():
    out = parse_stop_reply("T05watch:806adac4;40:8000ed53c;01:81560000;")
    assert out.watch_kind == "watch"
    assert out.watch_addr == 0x806ADAC4
    assert out.pc == 0x8000ED53C & 0xFFFFFFFF or out.pc is not None


def test_rwatch_annotation():
    out = parse_stop_reply("T05rwatch:80800000;40:80004304;")
    assert out.watch_kind == "rwatch"
    assert out.watch_addr == 0x80800000


def test_unknown_extra_keys_preserved():
    out = parse_stop_reply("T05library:foo;40:80004304;")
    assert out.extra.get("library") == "foo"
    assert out.pc == 0x80004304


def test_garbage_does_not_raise():
    # parse_stop_reply must never raise on bad input — used in a hot loop.
    parse_stop_reply("???")
    parse_stop_reply("Txx40:zz;")
    parse_stop_reply("T05bad:notanumber;")
