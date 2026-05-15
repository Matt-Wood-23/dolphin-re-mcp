"""Tests for memory_tools, using a fake backend installed on the session singleton."""
from __future__ import annotations

import pytest

from dolphin_re_mcp import session as session_mod
from dolphin_re_mcp.memory.routing import MEM1_BASE
from dolphin_re_mcp.tools import memory_tools


class FakeBackend:
    """In-memory dict-backed backend keyed by virtual addr — just for unit tests."""

    def __init__(self, blob_by_region: dict[int, bytes] | None = None):
        # store as a flat dict of {vaddr: byte} for simplicity
        self.bytes_by_addr: dict[int, int] = {}
        self.writes: list[tuple[int, bytes]] = []
        if blob_by_region:
            for base, blob in blob_by_region.items():
                for i, b in enumerate(blob):
                    self.bytes_by_addr[base + i] = b

    def read(self, addr: int, size: int) -> bytes:
        return bytes(self.bytes_by_addr.get(addr + i, 0) for i in range(size))

    def write(self, addr: int, data: bytes) -> None:
        self.writes.append((addr, data))
        for i, b in enumerate(data):
            self.bytes_by_addr[addr + i] = b

    def is_attached(self) -> bool:
        return True

    def close(self) -> None:
        pass


@pytest.fixture
def fake_session(monkeypatch):
    """Replace the session singleton with one that uses FakeBackend."""
    s = session_mod.Session()
    # Don't actually try to connect.
    s.ensure_connected = lambda: None  # type: ignore[assignment]
    backend = FakeBackend()
    monkeypatch.setattr(type(s), "mem", property(lambda self: backend))
    monkeypatch.setattr(session_mod, "_session", s)
    return s, backend


def test_read_u32_big_endian(fake_session):
    _, backend = fake_session
    backend.bytes_by_addr.update({MEM1_BASE + i: v for i, v in enumerate([0xDE, 0xAD, 0xBE, 0xEF])})
    assert memory_tools.read_u32(MEM1_BASE) == 0xDEADBEEF


def test_read_u16_big_endian(fake_session):
    _, backend = fake_session
    backend.bytes_by_addr.update({MEM1_BASE + i: v for i, v in enumerate([0x12, 0x34])})
    assert memory_tools.read_u16(MEM1_BASE) == 0x1234


def test_read_u8(fake_session):
    _, backend = fake_session
    backend.bytes_by_addr[MEM1_BASE] = 0x42
    assert memory_tools.read_u8(MEM1_BASE) == 0x42


def test_read_mem_returns_hex(fake_session):
    _, backend = fake_session
    backend.bytes_by_addr.update({MEM1_BASE + i: v for i, v in enumerate([1, 2, 3, 4])})
    out = memory_tools.read_mem(MEM1_BASE, 4)
    assert out == {"addr": MEM1_BASE, "size": 4, "hex": "01020304"}


def test_read_u32_dict_shape(fake_session):
    _, backend = fake_session
    backend.bytes_by_addr.update({MEM1_BASE + i: v for i, v in enumerate([0xDE, 0xAD, 0xBE, 0xEF])})
    out = memory_tools.read_u32_dict(MEM1_BASE)
    assert out == {"addr": "0x80000000", "value": 0xDEADBEEF, "hex": "0xdeadbeef"}


def test_read_u8_dict_shape(fake_session):
    _, backend = fake_session
    backend.bytes_by_addr[MEM1_BASE] = 0x07
    out = memory_tools.read_u8_dict(MEM1_BASE)
    assert out == {"addr": "0x80000000", "value": 7, "hex": "0x07"}


def test_read_u16_dict_shape(fake_session):
    _, backend = fake_session
    backend.bytes_by_addr.update({MEM1_BASE + i: v for i, v in enumerate([0x12, 0x34])})
    out = memory_tools.read_u16_dict(MEM1_BASE)
    assert out == {"addr": "0x80000000", "value": 0x1234, "hex": "0x1234"}


def test_read_s32_dict_negative_value(fake_session):
    _, backend = fake_session
    # -1 in big-endian 4-byte = 0xFFFFFFFF
    backend.bytes_by_addr.update({MEM1_BASE + i: 0xFF for i in range(4)})
    out = memory_tools.read_s32_dict(MEM1_BASE)
    assert out == {"addr": "0x80000000", "value": -1, "hex": "0xffffffff"}


def test_read_ptr_shape(fake_session):
    _, backend = fake_session
    backend.bytes_by_addr.update({MEM1_BASE + i: v for i, v in enumerate([0x90, 0x14, 0xAB, 0x40])})
    out = memory_tools.read_ptr(MEM1_BASE)
    assert out == {"addr": "0x80000000", "hex": "0x9014ab40", "value": 0x9014AB40}


def test_dump_hex_basic(fake_session):
    _, backend = fake_session
    blob = b"RMHE" + bytes([0x01, 0x02, 0x03, 0x04, 0x80, 0x00, 0x00, 0x00])
    backend.bytes_by_addr.update({MEM1_BASE + i: b for i, b in enumerate(blob)})
    out = memory_tools.dump_hex(MEM1_BASE, len(blob), width=16)
    assert out["addr"] == "0x80000000"
    assert out["size"] == 12
    assert out["hex"] == blob.hex()
    assert len(out["lines"]) == 1
    line = out["lines"][0]
    assert line.startswith("0x80000000:")
    assert "524d4845" in line.lower()
    assert "RMHE" in line  # ASCII column


def test_dump_hex_multiline(fake_session):
    _, backend = fake_session
    blob = bytes(range(32))  # 32 bytes, 16/line → 2 lines
    backend.bytes_by_addr.update({MEM1_BASE + i: b for i, b in enumerate(blob)})
    out = memory_tools.dump_hex(MEM1_BASE, 32, width=16)
    assert len(out["lines"]) == 2
    assert out["lines"][0].startswith("0x80000000:")
    assert out["lines"][1].startswith("0x80000010:")


def test_dump_hex_width_must_be_multiple_of_4(fake_session):
    with pytest.raises(ValueError):
        memory_tools.dump_hex(MEM1_BASE, 4, width=7)


def test_dump_hex_size_cap(fake_session):
    with pytest.raises(ValueError):
        memory_tools.dump_hex(MEM1_BASE, 5000)


def test_dump_hex_zero_size(fake_session):
    out = memory_tools.dump_hex(MEM1_BASE, 0)
    assert out == {"addr": "0x80000000", "size": 0, "lines": [], "hex": ""}


def test_read_f32_big_endian(fake_session):
    import struct

    _, backend = fake_session
    blob = struct.pack(">f", 3.14)
    backend.bytes_by_addr.update({MEM1_BASE + i: v for i, v in enumerate(blob)})
    assert memory_tools.read_f32(MEM1_BASE) == pytest.approx(3.14, rel=1e-6)


def test_read_struct(fake_session):
    _, backend = fake_session
    # u32 at +0 = 0x11223344, u8 at +4 = 0x55
    layout = [("a", "u32", 0), ("b", "u8", 4)]
    backend.bytes_by_addr.update(
        {MEM1_BASE + i: v for i, v in enumerate([0x11, 0x22, 0x33, 0x44, 0x55])}
    )
    out = memory_tools.read_struct(MEM1_BASE, layout)
    assert out == {"a": 0x11223344, "b": 0x55}


def test_write_mem_refuses_without_confirm(fake_session):
    with pytest.raises(memory_tools.WriteRefused):
        memory_tools.write_mem(MEM1_BASE, "01020304")


def test_write_mem_writes_with_confirm(fake_session):
    _, backend = fake_session
    out = memory_tools.write_mem(MEM1_BASE, "01020304", confirm=True)
    assert out == {"addr": MEM1_BASE, "written": 4}
    assert backend.writes == [(MEM1_BASE, b"\x01\x02\x03\x04")]


def test_follow_pointer(fake_session):
    _, backend = fake_session
    # at MEM1_BASE, u32 = 0x80000010
    # at 0x80000010 + 0x4 = 0x80000014, u32 = 0x80000020
    # final = 0x80000020 + 0x8 = 0x80000028
    backend.bytes_by_addr.update(
        {MEM1_BASE + i: v for i, v in enumerate([0x80, 0x00, 0x00, 0x10])}
    )
    backend.bytes_by_addr.update(
        {0x80000014 + i: v for i, v in enumerate([0x80, 0x00, 0x00, 0x20])}
    )
    out = memory_tools.follow_pointer(MEM1_BASE, 0x4, 0x8)
    assert out == 0x80000028


def test_is_valid_ptr_in_range(fake_session):
    assert memory_tools.is_valid_ptr(MEM1_BASE) is True
    assert memory_tools.is_valid_ptr(0x00000000) is False


def test_search_mem_finds_pattern(fake_session, monkeypatch):
    """Search a tiny synthetic region — patch MEM1_SIZE so we don't scan 24 MB."""
    _, backend = fake_session
    backend.bytes_by_addr.update(
        {MEM1_BASE + i: v for i, v in enumerate(b"AAAAtargetBBBBtargetCC")}
    )
    # Patch MEM1_SIZE just for this call
    monkeypatch.setattr(memory_tools, "MEM1_SIZE", 22)
    hits = memory_tools.search_mem("746172676574", region="MEM1")  # 'target'
    assert hits == [MEM1_BASE + 4, MEM1_BASE + 14]
