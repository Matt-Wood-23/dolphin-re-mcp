"""
Combined step 3 + 4 + 5 smoke test against live Dolphin.

Does everything in ONE connection (Dolphin's stub is one-shot per launch):
  Phase A — step 3:
    - Connect, why-halted, process attach, read 0x80000000 via both backends.
  Phase B — step 4 (manual):
    - Add WP at 0x806ADAC4, resume, wait_for_hit ONCE, remove WP, dump state.
  Phase C — step 5 (the transformative test):
    - Call trace_writes_to(0x806ADAC4, duration_s=20).
    - Print every captured hit.
  Phase D — cleanup:
    - Hang up socket without sending D, so Dolphin keeps running.
"""
from __future__ import annotations

import sys
import time

from dolphin_re_mcp.memory.routing import MEM1_BASE
from dolphin_re_mcp.session import get_session
from dolphin_re_mcp.tools import breakpoint_tools, compound_tools, execution_tools, memory_tools


WATCH_ADDR = 0x806ADAC4


def banner(title: str) -> None:
    print()
    print("=" * 60)
    print(f"  {title}")
    print("=" * 60)


def phase_a_step3():
    banner("PHASE A — step 3: connect + memory backends")
    session = get_session()
    session.ensure_connected()
    print(f"state: {session.state.value}")
    print(f"attached: PID={session.attach_backend.pid if session.attach_backend else 'no'}")

    gdb_bytes = session.gdb_mem_backend.read(MEM1_BASE, 4)
    print(f"GDB read 0x80000000 = {gdb_bytes.hex()}  (expect RMHE = 524d4845)")
    if session.attach_backend:
        att = session.attach_backend.read(MEM1_BASE, 4)
        print(f"ATTACH read 0x80000000 = {att.hex()}  {'AGREE' if att == gdb_bytes else 'DISAGREE'}")


def phase_b_step4():
    banner("PHASE B — step 4: manual watchpoint + wait_for_hit")
    wp = breakpoint_tools.add_watchpoint(WATCH_ADDR, 4, on="write")
    print(f"armed WP: {wp}")
    print("resume() ...")
    execution_tools.resume()
    print("wait_for_hit(timeout=30) ...")
    import socket
    try:
        hit = breakpoint_tools.wait_for_hit(timeout_s=30.0)
        print(f"hit: pc=0x{hit['pc']:08x} sp=0x{hit['sp']:08x} matched_id={hit['matched_bp_id']}")
        gprs = execution_tools.get_gprs()
        lr = execution_tools.get_lr()
        print(f"  LR=0x{lr:08x}  r3=0x{gprs['r3']:08x}  r4=0x{gprs['r4']:08x}  r31=0x{gprs['r31']:08x}")
    except socket.timeout:
        print("(no hit within 30s)")
    finally:
        # remove via _safe_to_modify (which auto-pauses if running)
        out = breakpoint_tools.remove(wp["id"])
        print(f"removed: {out}")


def phase_c_step5():
    banner("PHASE C — step 5: trace_writes_to (transformative milestone)")
    print(f"trace_writes_to(0x{WATCH_ADDR:08x}, duration_s=40) ...")
    print("(play the game — fire shots, take damage, etc., for 40s)")
    hits = compound_tools.trace_writes_to(
        WATCH_ADDR, duration_s=40.0, captures=["gprs", "lr"]
    )
    print(f"\n=== {len(hits)} hit(s) captured ===")
    # Group by PC for compactness
    by_pc: dict[int, list] = {}
    for h in hits:
        pc = h.get("pc")
        by_pc.setdefault(pc, []).append(h)
    for pc, group in sorted(by_pc.items(), key=lambda x: (x[0] is None, x[0])):
        sample = group[0]
        gprs = sample.get("gprs", {})
        pc_str = f"0x{pc:08x}" if pc else "?"
        lr_str = f"0x{sample.get('lr', 0):08x}"
        r3 = gprs.get("r3", 0)
        r4 = gprs.get("r4", 0)
        r5 = gprs.get("r5", 0)
        print(
            f"  PC={pc_str} ×{len(group):3d}  LR={lr_str}  "
            f"r3=0x{r3:08x} r4=0x{r4:08x} r5=0x{r5:08x}"
        )


def main() -> int:
    try:
        phase_a_step3()
    except Exception as e:
        print(f"[!] phase A failed: {e}")
        return 1

    try:
        phase_b_step4()
    except Exception as e:
        print(f"[!] phase B failed: {e}")
        import traceback; traceback.print_exc()

    try:
        phase_c_step5()
    except Exception as e:
        print(f"[!] phase C failed: {e}")
        import traceback; traceback.print_exc()

    banner("PHASE D — cleanup")
    session = get_session()
    # Make sure CPU is running before we hang up (so Dolphin keeps going).
    if session.state.value == "connected_paused":
        execution_tools.resume()
    session.disconnect(send_detach=False)
    print("disconnected (no D — Dolphin should keep running, but the stub")
    print("listener will likely close anyway given prior observations).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
