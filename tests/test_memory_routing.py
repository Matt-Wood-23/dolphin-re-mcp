"""Tests for MEM1/MEM2 address routing."""
from __future__ import annotations

import pytest

from dolphin_re_mcp.memory.routing import (
    MEM1_BASE,
    MEM1_END,
    MEM2_BASE,
    MEM2_END,
    AddressOutOfRange,
    Region,
    coerce_addr,
    is_valid,
    route,
)


def test_mem1_start():
    r = route(MEM1_BASE, 4)
    assert r.region is Region.MEM1
    assert r.offset == 0


def test_mem1_middle():
    r = route(0x806ADAC4, 4)
    assert r.region is Region.MEM1
    assert r.offset == 0x806ADAC4 - MEM1_BASE


def test_mem1_just_before_end():
    r = route(MEM1_END - 4, 4)
    assert r.region is Region.MEM1
    assert r.offset == 0x01800000 - 4


def test_mem1_crosses_end_raises():
    with pytest.raises(AddressOutOfRange):
        route(MEM1_END - 2, 4)


def test_mem2_start():
    r = route(MEM2_BASE, 8)
    assert r.region is Region.MEM2
    assert r.offset == 0


def test_mem2_crosses_end_raises():
    with pytest.raises(AddressOutOfRange):
        route(MEM2_END - 2, 4)


def test_between_regions_raises():
    # The gap between MEM1 end and MEM2 start has no valid mapping.
    with pytest.raises(AddressOutOfRange):
        route(0x85000000, 4)


def test_zero_raises():
    with pytest.raises(AddressOutOfRange):
        route(0x00000000, 4)


def test_negative_size_raises():
    with pytest.raises(ValueError):
        route(MEM1_BASE, 0)


def test_is_valid_returns_bool():
    assert is_valid(0x80000000, 4) is True
    assert is_valid(0x00000000, 4) is False
    assert is_valid(MEM2_END - 1, 4) is False


# ----- coerce_addr -----


def test_coerce_addr_hex():
    assert coerce_addr("0x806BBC74") == 0x806BBC74
    assert coerce_addr("0X806bbc74") == 0x806BBC74


def test_coerce_addr_decimal():
    assert coerce_addr("2154544244") == 0x806BBC74


def test_coerce_addr_strips_whitespace():
    assert coerce_addr("  0x806BBC74  ") == 0x806BBC74


def test_coerce_addr_bare_hex_rejected():
    # Bare hex without 0x prefix is ambiguous and must be refused.
    with pytest.raises(ValueError):
        coerce_addr("806BBC74")


def test_coerce_addr_empty_rejected():
    with pytest.raises(ValueError):
        coerce_addr("")


def test_coerce_addr_int_passthrough():
    # Ints are accepted (already-decoded by the MCP wrapper) and pass through.
    assert coerce_addr(0x806BBC74) == 0x806BBC74


def test_coerce_addr_non_string_non_int_rejected():
    with pytest.raises(TypeError):
        coerce_addr(3.14)  # type: ignore[arg-type]


def test_coerce_addr_bool_rejected_as_typeerror():
    # bool is an int subclass but we explicitly reject it — too confusing.
    with pytest.raises(TypeError):
        coerce_addr(True)  # type: ignore[arg-type]
