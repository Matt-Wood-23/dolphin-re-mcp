"""
Step-4 smoke test against live Dolphin.

Replicates the spike via the new tool surface:
  1. Connect.
  2. add_watchpoint(0x806ADAC4, 4, on='write') — same as the spike.
  3. resume().
  4. wait_for_hit(timeout_s=120).
  5. On hit: read PC, LR, GPRs, print.
  6. Loop a few times, then remove the WP and detach.

If we see hits with valid-looking PCs (0x80xxxxxx range), step 4 works.

You'll need to throw an ammo shot in-game within 120 seconds of `resume` for
the WP to fire. The boot-init memset at 0x800042FC will also fire it during
startup if you haven't booted into a save yet.
"""
from __future__ import annotations

import socket
import sys
import time

from dolphin_re_mcp.session import get_session
from dolphin_re_mcp.tools import breakpoint_tools, execution_tools


WATCH_ADDR = 0x806ADAC4
WAIT_SECONDS = 60
MAX_HITS = 5


def main() -> int:
    session = get_session()
    print("[*] ensuring connection ...")
    try:
        session.ensure_connected()
    except Exception as e:
        print(f"[!] connect failed: {e}")
        return 1
    print(f"    state: {session.state.value}")
    print(f"    attached: {session.attach_backend is not None}")

    print(f"[*] arming write watchpoint at 0x{WATCH_ADDR:08x} ...")
    wp = breakpoint_tools.add_watchpoint(WATCH_ADDR, 4, on="write")
    print(f"    {wp}")

    print(f"[*] resume() ...")
    print(f"    {execution_tools.resume()}")
    print(f"    state after resume: {session.state.value}")

    hits = 0
    t0 = time.time()
    try:
        for i in range(MAX_HITS):
            print(f"\n[*] wait_for_hit (up to {WAIT_SECONDS}s) — throw an ammo shot ...")
            try:
                hit = breakpoint_tools.wait_for_hit(timeout_s=WAIT_SECONDS)
            except socket.timeout:
                print(f"    timed out after {WAIT_SECONDS}s")
                break
            hits += 1
            elapsed = time.time() - t0
            pc = hit.get("pc")
            sp = hit.get("sp")
            watch_addr = hit.get("watch_addr")
            matched = hit.get("matched_bp_id")
            print(f"    [+{elapsed:5.1f}s] hit#{hits}")
            print(
                f"        signal={hit.get('signal'):#04x} pc=0x{pc:08x} sp=0x{sp:08x} "
                f"watch=0x{watch_addr or 0:08x} matched_id={matched}"
            )
            # Pull the rest of the register state.
            lr = execution_tools.get_lr()
            gprs = execution_tools.get_gprs()
            print(f"        LR = 0x{lr:08x}")
            for r in ("r3", "r4", "r5", "r6", "r31"):
                print(f"        {r} = 0x{gprs[r]:08x}")
            # Resume for the next iteration
            execution_tools.resume()
    finally:
        print("\n[*] removing watchpoint + detaching ...")
        breakpoint_tools.remove(wp["id"])
        # Make sure CPU is running before we hang up (so Dolphin keeps going).
        # NOTE: do NOT send `D` — Dolphin stops listening for new connections
        # after detach, which forces a relaunch to test again.
        if session.state.value == "connected_paused":
            execution_tools.resume()
        session.disconnect(send_detach=False)

    print(f"\nVERDICT: {hits} hit(s) captured. Step 4 = {'GO' if hits > 0 else 'no fire'}")
    return 0 if hits > 0 else 2


if __name__ == "__main__":
    sys.exit(main())
