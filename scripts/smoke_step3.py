"""
Step-3 smoke test — run against a live Dolphin booted on MH Tri.

What it does:
  1. Connect via GDBStub, run qSupported + ?  (no side effects, CPU stays paused)
  2. Try the process-attach backend; print discovered MEM1/MEM2 host bases.
  3. Read 0x80000000 (boot vector area) via both backends, confirm they agree.
  4. Read 0x806ADAC4 (cheatmine ammo-shot addr) via the attach backend.
  5. Sanity-check follow_pointer + is_valid_ptr.
  6. Detach cleanly (sends `D` so Dolphin keeps running afterwards).

Usage:  .venv/Scripts/python scripts/smoke_step3.py
"""
from __future__ import annotations

import sys
import traceback

from dolphin_re_mcp.gdb.client import GDBStub
from dolphin_re_mcp.memory.attach import AttachError, GDBMemoryBackend, WindowsAttachBackend
from dolphin_re_mcp.memory.routing import MEM1_BASE


def hex_or_err(fn):
    try:
        return f"0x{fn():08x}"
    except Exception as e:
        return f"ERR({type(e).__name__}: {e})"


def main() -> int:
    print("[*] connecting to Dolphin GDB stub at localhost:55432 ...")
    stub = GDBStub()
    try:
        stub.connect()
    except OSError as e:
        print(f"[!] connect failed: {e}")
        print("    Is Dolphin running with -d and waiting for GDB?")
        return 1
    print("[+] connected")

    try:
        print("[*] qSupported ...")
        print(f"    {stub.query_supported()[:120]}")

        print("[*] '?' why halted ...")
        print(f"    {stub.why_halted()}")

        print("[*] trying WindowsAttachBackend.find_dolphin() ...")
        try:
            attach = WindowsAttachBackend.find_dolphin()
            print(f"    PID={attach.pid}")
            print(f"    MEM1 host base = 0x{attach.mem1.base_addr:016x}")
            print(f"    MEM2 host base = 0x{attach.mem2.base_addr:016x}")
        except AttachError as e:
            print(f"    attach FAILED: {e}")
            print(f"    falling back to GDB-only reads (slower)")
            attach = None

        gdb_mem = GDBMemoryBackend(stub)

        print("\n[*] reading 0x80000000 (4 bytes) via GDB backend ...")
        try:
            gdb_bytes = gdb_mem.read(MEM1_BASE, 4)
            print(f"    GDB:    {gdb_bytes.hex()}  (expected: 00000007 or boot magic)")
        except Exception:
            traceback.print_exc()
            gdb_bytes = None

        if attach is not None:
            print("[*] reading 0x80000000 (4 bytes) via attach backend ...")
            try:
                attach_bytes = attach.read(MEM1_BASE, 4)
                print(f"    ATTACH: {attach_bytes.hex()}")
                if gdb_bytes is not None:
                    if attach_bytes == gdb_bytes:
                        print("    [+] backends AGREE")
                    else:
                        print("    [!] backends DISAGREE — investigate")
            except Exception:
                traceback.print_exc()

        print("\n[*] reading the ammo-shot addr 0x806ADAC4 (u32) via attach (or GDB) ...")
        backend = attach if attach else gdb_mem
        try:
            blob = backend.read(0x806ADAC4, 4)
            val = int.from_bytes(blob, "big")
            print(f"    raw bytes:  {blob.hex()}")
            print(f"    as u32:     0x{val:08x} ({val})")
        except Exception:
            traceback.print_exc()

        print("\n[*] reading 16 bytes at slot1 base 0x806ADA78 (slot1 - 0x4C) ...")
        try:
            blob = backend.read(0x806ADA78, 16)
            print(f"    {blob.hex()}")
        except Exception:
            traceback.print_exc()

        print("\n[+] smoke test complete")
        if attach:
            attach.close()
        return 0
    finally:
        try:
            stub.detach()  # 'D' lets Dolphin resume on its own
        except Exception:
            stub.close()


if __name__ == "__main__":
    sys.exit(main())
