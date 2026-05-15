"""
PowerPC disassembler — thin wrapper over Capstone, plus an instruction
classifier the agent uses to walk overlay-blocked functions.

Capstone is imported lazily so steps 1-5 don't pull it in.

Classification kinds:
  load          — lwz/lbz/lhz/lwzx/lfd/lfs/etc.
  store         — stw/stb/sth/stwx/stfd/stfs/etc.
  branch        — b (unconditional)
  branch_cond   — bne, beq, blt, ... and the synthetic forms
  branch_link   — bl, bctrl, blrl  (function calls)
  branch_return — blr  (return-to-caller)
  imm_load      — li, lis
  imm_load_pair — synthesized: lis Rx,hi ; addi/subi/ori Rx,Rx,lo  (one logical 32-bit load)
  fp_arith      — fadd, fmul, fmadd, fcmpu, etc.
  int_arith     — add, sub, mullw, slw, ...
  cmp           — cmpw, cmpwi, cmplw, cmplwi
  syscall       — sc, rfi, trap
  nop           — nop / ori 0,0,0
  other

For loads and stores, when a GPR snapshot is supplied, we compute the
effective address.
"""
from __future__ import annotations

import enum
import struct
from dataclasses import dataclass, field
from typing import Optional


class InstructionKind(str, enum.Enum):
    LOAD = "load"
    STORE = "store"
    BRANCH = "branch"
    BRANCH_COND = "branch_cond"
    BRANCH_LINK = "branch_link"
    BRANCH_RETURN = "branch_return"
    IMM_LOAD = "imm_load"
    IMM_LOAD_PAIR = "imm_load_pair"
    FP_ARITH = "fp_arith"
    INT_ARITH = "int_arith"
    CMP = "cmp"
    SYSCALL = "syscall"
    NOP = "nop"
    OTHER = "other"


@dataclass
class DisasmInstruction:
    pc: int
    bytes_hex: str        # 4-byte big-endian, hex
    mnemonic: str         # e.g. "lwz"
    operands: str         # e.g. "r3, 0x10(r31)"
    kind: InstructionKind
    # For loads/stores, the effective address when a GPR snapshot is supplied.
    ea: Optional[int] = None
    # For imm_load_pair, the resolved 32-bit value spanning two instructions.
    imm_value: Optional[int] = None
    # For branches with a static target (b, bl, bne, ...), the target PC.
    branch_target: Optional[int] = None

    def to_dict(self) -> dict:
        out: dict = {
            "pc": self.pc,
            "bytes": self.bytes_hex,
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "kind": self.kind.value,
        }
        if self.ea is not None:
            out["ea"] = self.ea
        if self.imm_value is not None:
            out["imm_value"] = self.imm_value
        if self.branch_target is not None:
            out["branch_target"] = self.branch_target
        return out


# Capstone module is imported lazily — `disasm_bytes` is the first user.
_CS = None
_CS_MODE = None


def _capstone():
    global _CS, _CS_MODE
    if _CS is None:
        import capstone

        _CS = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
        _CS.detail = True
        _CS_MODE = capstone
    return _CS


# Mnemonic → kind tables. Capstone normalizes most PPC mnemonics; we match by
# canonical name, falling back to prefix heuristics.
_LOAD_MNEMS = {
    "lwz", "lwzu", "lwzx", "lwzux",
    "lbz", "lbzu", "lbzx", "lbzux",
    "lhz", "lhzu", "lhzx", "lhzux",
    "lha", "lhau", "lhax", "lhaux",
    "lwa", "ld", "ldu", "ldx", "ldux",
    "lmw",
    "lfd", "lfdu", "lfdx", "lfdux",
    "lfs", "lfsu", "lfsx", "lfsux",
    "psq_l", "psq_lu",
}
_STORE_MNEMS = {
    "stw", "stwu", "stwx", "stwux",
    "stb", "stbu", "stbx", "stbux",
    "sth", "sthu", "sthx", "sthux",
    "std", "stdu", "stdx", "stdux",
    "stmw",
    "stfd", "stfdu", "stfdx", "stfdux",
    "stfs", "stfsu", "stfsx", "stfsux",
    "psq_st", "psq_stu",
}
_INT_ARITH_MNEMS = {
    "add", "addc", "adde", "addi", "addic", "addic.", "addis", "addme", "addze",
    "and", "andc", "andi.", "andis.",
    "divw", "divwu",
    "extsb", "extsh", "extsw",
    "mulhw", "mulhwu", "mulli", "mullw",
    "nand", "neg", "nor",
    "or", "orc", "ori", "oris",
    "rlwimi", "rlwinm", "rlwnm",
    "slw", "sraw", "srawi", "srw",
    "sub", "subc", "subf", "subfc", "subfe", "subfic", "subfme", "subfze",
    "xor", "xori", "xoris",
}
_FP_ARITH_MNEMS = {
    "fabs", "fadd", "fadds", "fcfid", "fctid", "fctidz", "fctiw", "fctiwz",
    "fdiv", "fdivs", "fmadd", "fmadds", "fmr", "fmsub", "fmsubs",
    "fmul", "fmuls", "fnabs", "fneg", "fnmadd", "fnmadds", "fnmsub", "fnmsubs",
    "fres", "frsp", "frsqrte", "fsel", "fsqrt", "fsqrts", "fsub", "fsubs",
    "fcmpo", "fcmpu",
    "ps_add", "ps_sub", "ps_mul", "ps_div", "ps_madd", "ps_msub", "ps_nmadd",
    "ps_nmsub", "ps_neg", "ps_mr", "ps_abs", "ps_sum0", "ps_sum1", "ps_muls0",
    "ps_muls1", "ps_madds0", "ps_madds1", "ps_cmpu0", "ps_cmpu1",
}
_CMP_MNEMS = {"cmp", "cmpw", "cmpwi", "cmpl", "cmplw", "cmplwi"}
_BRANCH_COND_MNEMS = {
    # Capstone often emits the synthetic forms directly.
    "bc", "bcl", "bca", "bcla",
    "bne", "beq", "blt", "ble", "bgt", "bge", "bnl", "bng", "bso", "bns", "bun", "bnu",
    "bne+", "beq+", "blt+", "ble+", "bgt+", "bge+",  # branch-likely hints
    "bne-", "beq-", "blt-", "ble-", "bgt-", "bge-",
    "bdz", "bdnz", "bdzf", "bdnzf", "bdzt", "bdnzt",
}
_UNCOND_BRANCH_MNEMS = {"b", "ba"}
_BRANCH_LINK_MNEMS = {"bl", "bla", "bctrl", "blrl", "bcctrl", "bclrl"}
_BRANCH_RETURN_MNEMS = {"blr", "bctr", "bclr"}


def classify(mnem: str) -> InstructionKind:
    m = mnem.lower().rstrip(".")
    if m in _LOAD_MNEMS:
        return InstructionKind.LOAD
    if m in _STORE_MNEMS:
        return InstructionKind.STORE
    if m in _UNCOND_BRANCH_MNEMS:
        return InstructionKind.BRANCH
    if m in _BRANCH_LINK_MNEMS:
        return InstructionKind.BRANCH_LINK
    if m in _BRANCH_RETURN_MNEMS:
        return InstructionKind.BRANCH_RETURN
    if m in _BRANCH_COND_MNEMS or (m.startswith("b") and m[1:] in {
        "ne", "eq", "lt", "le", "gt", "ge", "nl", "ng", "so", "ns", "un", "nu"
    }):
        return InstructionKind.BRANCH_COND
    if m in {"li", "lis"}:
        return InstructionKind.IMM_LOAD
    if m in _CMP_MNEMS:
        return InstructionKind.CMP
    if m in _FP_ARITH_MNEMS or m.startswith(("f", "ps_")):
        return InstructionKind.FP_ARITH
    if m in _INT_ARITH_MNEMS:
        return InstructionKind.INT_ARITH
    if m in {"sc", "rfi", "trap", "twi", "tw"}:
        return InstructionKind.SYSCALL
    if m == "nop":
        return InstructionKind.NOP
    return InstructionKind.OTHER


def disasm_bytes(pc: int, blob: bytes, gprs: dict | None = None) -> list[DisasmInstruction]:
    """
    Disassemble a contiguous byte blob starting at `pc`.

    If `gprs` is supplied (mapping like {"r0": 0, "r1": 0x81560000, ...}),
    effective addresses are computed for load/store instructions.
    """
    if len(blob) == 0:
        return []
    if len(blob) % 4 != 0:
        # PPC instructions are 4 bytes; align down.
        blob = blob[: len(blob) - (len(blob) % 4)]
    cs = _capstone()
    out: list[DisasmInstruction] = []
    for insn in cs.disasm(blob, pc):
        mnem = insn.mnemonic
        kind = classify(mnem)
        # Reconstruct raw bytes from blob (big-endian word).
        off = insn.address - pc
        bytes_hex = blob[off : off + 4].hex()
        ins = DisasmInstruction(
            pc=insn.address,
            bytes_hex=bytes_hex,
            mnemonic=mnem,
            operands=insn.op_str,
            kind=kind,
        )
        # Branch targets — Capstone fills the operand string with the absolute
        # target for direct branches.
        if kind in (
            InstructionKind.BRANCH,
            InstructionKind.BRANCH_COND,
            InstructionKind.BRANCH_LINK,
        ):
            tgt = _parse_branch_target(insn.op_str)
            if tgt is not None:
                ins.branch_target = tgt
        # Effective address for memory ops, if gprs were provided.
        if kind in (InstructionKind.LOAD, InstructionKind.STORE) and gprs:
            ea = compute_effective_address(insn.op_str, gprs)
            if ea is not None:
                ins.ea = ea
        out.append(ins)
    return out


def _parse_branch_target(op_str: str) -> Optional[int]:
    """Capstone PPC formats direct branch targets as '0x80004304' (no prefix decoration)."""
    parts = [p.strip() for p in op_str.split(",")]
    candidate = parts[-1] if parts else ""
    if candidate.startswith("0x"):
        try:
            return int(candidate, 16)
        except ValueError:
            return None
    return None


def compute_effective_address(op_str: str, gprs: dict[str, int]) -> Optional[int]:
    """
    Parse the displacement-form operand syntax "offset(rN)" or the indexed
    form "rA, rB" (no parens) and compute the EA. Returns None if it can't.

    Examples:
      "r3, 0x10(r31)"   → gprs[r31] + 0x10
      "r3, -0x4(r1)"    → gprs[r1] - 4
      "r3, r4, r5"      → indexed; gprs[r4] + gprs[r5]
    """
    # Strip the destination register (everything before the first comma).
    rhs = op_str.split(",", 1)[-1].strip() if "," in op_str else op_str.strip()
    # Disp form: "<imm>(rN)"
    if "(" in rhs and rhs.endswith(")"):
        lp = rhs.index("(")
        imm = rhs[:lp].strip()
        reg = rhs[lp + 1 : -1].strip()
        try:
            disp = int(imm, 0)
        except ValueError:
            return None
        if reg == "0":
            base = 0
        elif reg in gprs:
            base = gprs[reg] & 0xFFFFFFFF
        else:
            return None
        # If disp was written as a positive unsigned 16-bit value with the
        # high bit set (e.g. 0xfffc for -4), sign-extend to int32. Already-
        # negative ints (from "-0x4") are left alone.
        if 0 < disp <= 0xFFFF and (disp & 0x8000):
            disp = disp - 0x10000
        return (base + disp) & 0xFFFFFFFF
    # Indexed form: "rA, rB" (after stripping dst we should still have two regs)
    parts = [p.strip() for p in rhs.split(",")]
    if len(parts) == 2:
        ra, rb = parts
        a = 0 if ra == "0" else gprs.get(ra)
        b = gprs.get(rb)
        if a is None or b is None:
            return None
        return (a + b) & 0xFFFFFFFF
    return None


def post_process_imm_load_pairs(insns: list[DisasmInstruction]) -> None:
    """
    Walk a timeline of decoded instructions and tag `lis Rx, hi` followed
    (eventually, with no clobbering write to Rx between) by `addi/subi/ori Rx, Rx, lo`
    as a single logical IMM_LOAD_PAIR. Mutates the list in place.

    Sets `kind=IMM_LOAD_PAIR` on the second instruction and stores the resolved
    32-bit value in `imm_value`.
    """
    # Map destination register → (idx of lis, high16 value).
    pending: dict[str, tuple[int, int]] = {}
    for idx, ins in enumerate(insns):
        mnem = ins.mnemonic.lower()
        # `lis Rx, imm` → high half of a 32-bit imm.
        if mnem == "lis":
            dst, hi = _parse_lis(ins.operands)
            if dst is not None:
                pending[dst] = (idx, (hi & 0xFFFF) << 16)
            continue
        # addi/subi/ori finalizes the pair if it's combining the lis's dst.
        if mnem in ("addi", "subi", "ori"):
            dst, src, imm = _parse_three_op(ins.operands)
            if dst is not None and src == dst and dst in pending:
                _, hi = pending.pop(dst)
                lo_raw = imm
                if mnem == "ori":
                    value = hi | (lo_raw & 0xFFFF)
                else:
                    # Capstone normalizes "addi r,r,-4" to imm=-4 already;
                    # if it gave us a positive 16-bit with top bit set, sign-extend.
                    if 0 < lo_raw <= 0xFFFF and (lo_raw & 0x8000):
                        sext = lo_raw - 0x10000
                    else:
                        sext = lo_raw
                    if mnem == "subi":
                        sext = -sext
                    value = (hi + sext) & 0xFFFFFFFF
                ins.kind = InstructionKind.IMM_LOAD_PAIR
                ins.imm_value = value
            continue
        # Any other write to a pending register invalidates the pair candidate.
        # Best-effort: look at operands for the dst register.
        dst = _first_destination_register(ins.operands)
        if dst and dst in pending:
            pending.pop(dst, None)


def _parse_lis(op_str: str) -> tuple[Optional[str], int]:
    parts = [p.strip() for p in op_str.split(",")]
    if len(parts) != 2:
        return None, 0
    dst, imm = parts
    try:
        return dst, int(imm, 0) & 0xFFFF
    except ValueError:
        return None, 0


def _parse_three_op(op_str: str) -> tuple[Optional[str], Optional[str], int]:
    parts = [p.strip() for p in op_str.split(",")]
    if len(parts) != 3:
        return None, None, 0
    dst, src, imm = parts
    try:
        return dst, src, int(imm, 0)
    except ValueError:
        return dst, src, 0


def _first_destination_register(op_str: str) -> Optional[str]:
    """Conservative: first comma-separated token if it looks like a register."""
    first = op_str.split(",", 1)[0].strip() if "," in op_str else ""
    if first.startswith("r") and first[1:].isdigit():
        return first
    return None


def insn_word_to_bytes(word: int) -> bytes:
    """Pack a 32-bit instruction word as big-endian bytes."""
    return struct.pack(">I", word & 0xFFFFFFFF)
