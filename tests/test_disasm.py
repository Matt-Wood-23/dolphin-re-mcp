"""
Tests for the PPC disasm classifier and imm-load-pair post-processing.

Builds raw instruction words by hand (well-known encodings) and asserts
classification + EA computation.
"""
from __future__ import annotations

import pytest

from dolphin_re_mcp.disasm.ppc import (
    InstructionKind,
    compute_effective_address,
    classify,
    disasm_bytes,
    post_process_imm_load_pairs,
)


# Well-known PPC instruction encodings (big-endian 32-bit words):
#   lis r3, 0x8000   = 0x3c608000
#   ori r3, r3, 0x4304 = 0x60634304   (so r3 = 0x80004304)
#   lwz r4, 0x10(r3)  = 0x80830010
#   stw r5, -0x4(r1)  = 0x90a1fffc
#   bl  +0x100         (relative, target 0x80001100 from 0x80001000) = 0x48000101
#   blr                = 0x4e800020
#   nop                = 0x60000000
#   add r3, r4, r5     = 0x7c632214


def _disasm_words(pc, *words, gprs=None):
    blob = b"".join(w.to_bytes(4, "big") for w in words)
    return disasm_bytes(pc, blob, gprs=gprs)


def test_classify_loads_stores():
    assert classify("lwz") == InstructionKind.LOAD
    assert classify("stw") == InstructionKind.STORE
    assert classify("lfd") == InstructionKind.LOAD
    assert classify("stfd") == InstructionKind.STORE


def test_classify_branches():
    assert classify("b") == InstructionKind.BRANCH
    assert classify("bl") == InstructionKind.BRANCH_LINK
    assert classify("blr") == InstructionKind.BRANCH_RETURN
    assert classify("bne") == InstructionKind.BRANCH_COND
    assert classify("bdnz") == InstructionKind.BRANCH_COND
    assert classify("bctrl") == InstructionKind.BRANCH_LINK


def test_classify_arith_and_misc():
    assert classify("add") == InstructionKind.INT_ARITH
    assert classify("fadd") == InstructionKind.FP_ARITH
    assert classify("cmpw") == InstructionKind.CMP
    assert classify("lis") == InstructionKind.IMM_LOAD
    assert classify("nop") == InstructionKind.NOP
    assert classify("sc") == InstructionKind.SYSCALL
    assert classify("unknownop") == InstructionKind.OTHER


def test_disasm_one_lwz():
    out = _disasm_words(0x80004304, 0x80830010)
    assert len(out) == 1
    assert out[0].mnemonic == "lwz"
    assert out[0].kind == InstructionKind.LOAD


def test_disasm_one_stw():
    out = _disasm_words(0x80004304, 0x90A1FFFC)
    assert len(out) == 1
    assert out[0].mnemonic == "stw"
    assert out[0].kind == InstructionKind.STORE


def test_disasm_blr():
    out = _disasm_words(0x80004304, 0x4E800020)
    assert out[0].mnemonic == "blr"
    assert out[0].kind == InstructionKind.BRANCH_RETURN


def test_disasm_nop():
    out = _disasm_words(0x80004304, 0x60000000)
    # Capstone may emit "nop" or canonicalize to "ori r0, r0, 0" — either is fine.
    assert out[0].kind in (InstructionKind.NOP, InstructionKind.INT_ARITH)


def test_compute_ea_disp_form():
    gprs = {"r3": 0x80004304, "r31": 0x806ADA00}
    # "r4, 0x10(r31)"  → 0x806ADA10
    ea = compute_effective_address("r4, 0x10(r31)", gprs)
    assert ea == 0x806ADA10


def test_compute_ea_negative_disp():
    gprs = {"r1": 0x81560000}
    # "r5, -0x4(r1)"  → 0x8155fffc
    ea = compute_effective_address("r5, -0x4(r1)", gprs)
    assert ea == 0x8155FFFC


def test_compute_ea_r0_means_zero():
    gprs = {"r0": 0xDEADBEEF}
    # When the base reg is r0, PPC defines EA = 0 + disp (NOT r0's value).
    # Our implementation respects "reg == '0'" but Capstone emits "0" not "r0"
    # for that special form. Disambiguate by literal string.
    ea = compute_effective_address("r4, 0x1000(0)", gprs)
    assert ea == 0x1000


def test_compute_ea_returns_none_when_reg_missing():
    gprs = {"r1": 0x81560000}
    ea = compute_effective_address("r4, 0x10(r31)", gprs)
    assert ea is None  # no r31 in gprs


def test_imm_load_pair_lis_ori():
    # lis r3, 0x8000  ; ori r3, r3, 0x4304
    insns = _disasm_words(0x80001000, 0x3C608000, 0x60634304)
    post_process_imm_load_pairs(insns)
    # The first stays IMM_LOAD; the second becomes IMM_LOAD_PAIR with imm_value=0x80004304.
    assert insns[0].kind == InstructionKind.IMM_LOAD
    assert insns[1].kind == InstructionKind.IMM_LOAD_PAIR
    assert insns[1].imm_value == 0x80004304


def test_imm_load_pair_lis_addi_negative_lo():
    # lis r3, 0x8001  ; addi r3, r3, -0x4
    # → r3 = (0x8001 << 16) + (-4) = 0x80010000 - 4 = 0x8000FFFC
    insns = _disasm_words(0x80001000, 0x3C608001, 0x3863FFFC)
    post_process_imm_load_pairs(insns)
    assert insns[1].kind == InstructionKind.IMM_LOAD_PAIR
    assert insns[1].imm_value == 0x8000FFFC


def test_imm_load_pair_interrupted_by_clobbering_write():
    # lis r3, 0x8000  ; li r3, 0  ; ori r3, r3, 0x4304
    # The middle insn overwrites r3, so the ori is NOT part of the original pair.
    insns = _disasm_words(0x80001000, 0x3C608000, 0x38600000, 0x60634304)
    post_process_imm_load_pairs(insns)
    # The ori should NOT have imm_value set (no high half pending after li).
    assert insns[2].imm_value is None


def test_disasm_with_gprs_resolves_ea():
    gprs = {"r31": 0x806ADA00}
    # lwz r4, 0x10(r31)
    out = _disasm_words(0x80001000, 0x80830010)
    # The first call doesn't pass gprs so ea will be None.
    assert out[0].ea is None
    # Now with gprs:
    out2 = _disasm_words(0x80001000, 0x80830010, gprs=gprs)
    # r3 is the dst; base is r3 in this encoding? Let me recheck: 0x80830010
    # lwz rD, d(rA) — bits: 100000 (op=32), 00100(rD=4), 00011(rA=3), d=0x10
    # So this is "lwz r4, 0x10(r3)" — needs r3 in gprs.
    gprs2 = {"r3": 0x80004000}
    out3 = _disasm_words(0x80001000, 0x80830010, gprs=gprs2)
    assert out3[0].ea == 0x80004010
