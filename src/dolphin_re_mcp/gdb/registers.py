"""
PowerPC register layout for Dolphin's GDB stub.

Dolphin's `p<n>` register query layout (validated against build 2603a):
  0x00–0x1F: r0–r31  (4 bytes each)
  0x20–0x3F: f0–f31  (8 bytes each, IEEE 754 double)
  0x40:      PC
  0x41:      MSR    (NOT LR — common mistake)
  0x42:      CR
  0x43:      LR
  0x44:      CTR
  0x45:      XER

The `g` packet returns ONLY the 32 GPRs concatenated (128 bytes total).
Everything else needs individual `p` queries.
"""
from __future__ import annotations

import struct

# Special-purpose registers, by GDB regnum.
PC = 0x40
MSR = 0x41
CR = 0x42
LR = 0x43
CTR = 0x44
XER = 0x45

# regnum → canonical name. Used by stop-reply parsing and capture logs.
REG_NAMES: dict[int, str] = {
    0x01: "sp",  # r1 == stack pointer; Dolphin reports it as sp in stop replies
    PC: "pc",
    MSR: "msr",
    CR: "cr",
    LR: "lr",
    CTR: "ctr",
    XER: "xer",
}
for _i in range(32):
    REG_NAMES.setdefault(_i, f"r{_i}")
for _i in range(32):
    REG_NAMES.setdefault(0x20 + _i, f"f{_i}")

REG_NUMS: dict[str, int] = {v: k for k, v in REG_NAMES.items()}


def parse_dolphin_gprs(reg_blob: bytes) -> dict[str, int]:
    """Decode the 128-byte `g` packet payload into {r0..r31: int} (big-endian)."""
    out: dict[str, int] = {}
    for i in range(32):
        off = i * 4
        if off + 4 > len(reg_blob):
            break
        out[f"r{i}"] = int.from_bytes(reg_blob[off : off + 4], "big")
    return out


def parse_fpr_value(reg_bytes: bytes) -> float:
    """Decode an 8-byte FPR value (big-endian IEEE 754 double)."""
    if len(reg_bytes) != 8:
        raise ValueError(f"FPR must be 8 bytes, got {len(reg_bytes)}")
    return struct.unpack(">d", reg_bytes)[0]
