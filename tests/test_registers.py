"""Tests for register layout decoding."""
from __future__ import annotations

import struct

from dolphin_re_mcp.gdb.registers import (
    LR,
    PC,
    REG_NAMES,
    REG_NUMS,
    parse_dolphin_gprs,
    parse_fpr_value,
)


def test_reg_names_special_purpose():
    assert REG_NAMES[PC] == "pc"
    assert REG_NAMES[LR] == "lr"
    # r1 == sp in stop replies (Dolphin convention)
    assert REG_NAMES[0x01] == "sp"
    assert REG_NAMES[0x44] == "ctr"
    assert REG_NAMES[0x45] == "xer"


def test_reg_names_cover_gprs_and_fprs():
    assert REG_NAMES[0x00] == "r0"
    assert REG_NAMES[0x1F] == "r31"
    assert REG_NAMES[0x20] == "f0"
    assert REG_NAMES[0x3F] == "f31"


def test_reg_nums_is_inverse_of_names():
    assert REG_NUMS["pc"] == PC
    assert REG_NUMS["lr"] == LR
    assert REG_NUMS["r3"] == 0x03


def test_parse_dolphin_gprs_full_blob():
    # 32 GPRs, each 4 bytes, big-endian. Pack r_i = i for distinguishability.
    blob = b"".join(i.to_bytes(4, "big") for i in range(32))
    gprs = parse_dolphin_gprs(blob)
    assert gprs["r0"] == 0
    assert gprs["r3"] == 3
    assert gprs["r31"] == 31


def test_parse_dolphin_gprs_partial_blob_truncates():
    # 4 bytes only → just r0.
    blob = b"\xde\xad\xbe\xef"
    gprs = parse_dolphin_gprs(blob)
    assert gprs == {"r0": 0xDEADBEEF}


def test_parse_fpr_value_decodes_double():
    expected = 3.14159
    blob = struct.pack(">d", expected)
    assert parse_fpr_value(blob) == expected
