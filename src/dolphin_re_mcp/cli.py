"""
Command-line entry points for dolphin-re-mcp.

`dolphin-re-mcp` (no args)   → run the MCP server (stdio transport).
`dolphin-re-mcp doctor`      → run the per-session diagnostic checklist.

The doctor is read-only and never modifies stub state. Safe to run anytime.
"""
from __future__ import annotations

import os
import socket
import sys
from typing import Callable

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
DIM = "\033[2m"
RESET = "\033[0m"


def _ok(label: str, detail: str = "") -> None:
    print(f"  {GREEN}OK{RESET}    {label}{('  ' + DIM + detail + RESET) if detail else ''}")


def _fail(label: str, detail: str = "") -> None:
    print(f"  {RED}FAIL{RESET}  {label}{('  ' + DIM + detail + RESET) if detail else ''}")


def _warn(label: str, detail: str = "") -> None:
    print(f"  {YELLOW}WARN{RESET}  {label}{('  ' + DIM + detail + RESET) if detail else ''}")


def _section(title: str) -> None:
    print()
    print(f"\033[1m{title}\033[0m")


def doctor() -> int:
    """
    Per-session diagnostic checks. Returns 0 if everything passed, 1 otherwise.

    Checks (in order):
      1. Python deps importable (mcp, capstone, pymem, psutil).
      2. Dolphin process is running (psutil scan).
      3. GDB stub TCP port reachable.
      4. GDB stub responds to qSupported.
      5. Process-attach backend finds MEM1/MEM2 regions.
      6. Backends agree on a known address (0x80000000 should be "RMHE").
      7. Optional: MHTRI_DUMPS_DIR env var is set and exists.
    """
    host = os.environ.get("DOLPHIN_GDB_HOST", "localhost")
    port = int(os.environ.get("DOLPHIN_GDB_PORT", "55432"))
    dumps_dir = os.environ.get("MHTRI_DUMPS_DIR")

    fails = 0
    warns = 0

    print(f"dolphin-re-mcp doctor  —  probing {host}:{port}")

    _section("1. Python dependencies")
    for modname in ("mcp", "capstone", "psutil"):
        try:
            __import__(modname)
            _ok(modname)
        except ImportError as e:
            _fail(modname, str(e))
            fails += 1
    if sys.platform == "win32":
        try:
            import pymem  # noqa: F401

            _ok("pymem (Windows)")
        except ImportError as e:
            _fail("pymem", str(e))
            fails += 1

    _section("2. Dolphin process")
    pid = _find_dolphin_pid()
    if pid is None:
        _fail("Dolphin.exe not found", "is Dolphin running?")
        fails += 1
    else:
        _ok("Dolphin.exe found", f"PID={pid}")

    _section("3. GDB stub TCP port")
    if not _port_open(host, port):
        # Disambiguate: is Dolphin gone, or is another client (e.g. the MCP
        # server running in Claude) already holding the stub's single allowed
        # connection? Dolphin's listener is one-shot per launch.
        if pid is not None:
            _fail(
                f"{host}:{port} not reachable, but Dolphin (PID {pid}) is running",
                "another client likely holds the connection — close it (and the MCP server in Claude), then relaunch Dolphin",
            )
        else:
            _fail(
                f"{host}:{port} not reachable",
                "launch Dolphin with -d, panels closed, boot a game",
            )
        # No point continuing past this — return early.
        return 1
    _ok(f"{host}:{port} accepts connections")

    _section("4. GDB stub handshake")
    try:
        from .gdb.client import GDBStub

        stub = GDBStub(host=host, port=port)
        stub.connect()
    except Exception as e:
        _fail("connect()", str(e))
        return 1
    _ok("TCP connected")
    try:
        reply = stub.query_supported()
        _ok("qSupported", reply[:80])
    except Exception as e:
        _fail("qSupported", str(e))
        fails += 1
    try:
        why = stub.why_halted()
        _ok("? (why halted)", why[:80])
    except Exception as e:
        _fail("? (why halted)", str(e))
        fails += 1

    _section("5. Process-attach backend")
    if sys.platform != "win32":
        _warn("not on win32 — attach backend disabled", "GDB reads will be slower")
    elif pid is None:
        _warn("skipped: no Dolphin PID")
    else:
        try:
            from .memory.attach import WindowsAttachBackend

            attach = WindowsAttachBackend.find_dolphin()
            _ok("MEM1 region found", f"host base 0x{attach.mem1.base_addr:016x}")
            _ok("MEM2 region found", f"host base 0x{attach.mem2.base_addr:016x}")

            _section("6. Backend cross-check at 0x80000000")
            gdb_bytes = stub.read_mem(0x80000000, 4)
            att_bytes = attach.read(0x80000000, 4)
            game_id = gdb_bytes.decode("ascii", errors="replace")
            if gdb_bytes == att_bytes:
                _ok(
                    f"both backends read {gdb_bytes.hex()}",
                    f'"{game_id}"  (MH Tri = RMHE)',
                )
            else:
                _fail(
                    "backends disagree",
                    f"gdb={gdb_bytes.hex()} attach={att_bytes.hex()}",
                )
                fails += 1
            attach.close()
        except Exception as e:
            _fail("attach", str(e))
            fails += 1

    _section("7. Environment")
    if dumps_dir:
        if os.path.isdir(dumps_dir):
            _ok("MHTRI_DUMPS_DIR", dumps_dir)
        else:
            _warn("MHTRI_DUMPS_DIR set but path missing", dumps_dir)
            warns += 1
    else:
        _warn(
            "MHTRI_DUMPS_DIR not set",
            "snapshot_to_dump/diff_live_vs_dump tools will refuse to run",
        )
        warns += 1

    # Hang up cleanly — don't send D (kills Dolphin's listener).
    stub.close()

    print()
    if fails:
        print(f"{RED}{fails} failure(s){RESET}, {warns} warning(s)")
        return 1
    if warns:
        print(f"{YELLOW}{warns} warning(s){RESET}, all critical checks OK")
        return 0
    print(f"{GREEN}all checks passed{RESET}")
    return 0


def _find_dolphin_pid():
    try:
        import psutil
    except ImportError:
        return None
    for proc in psutil.process_iter(["name", "pid"]):
        try:
            if (proc.info.get("name") or "").lower() == "dolphin.exe":
                return proc.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def main(argv: list[str] | None = None) -> int:
    """Console-script entry point. Routes between `doctor` and the MCP server."""
    args = list(argv if argv is not None else sys.argv[1:])
    if args and args[0] == "doctor":
        return doctor()
    if args and args[0] in ("-h", "--help", "help"):
        print("usage: dolphin-re-mcp [doctor]")
        print()
        print("  (no args)  run the MCP server on stdio (for Claude Code etc.)")
        print("  doctor     run the per-session diagnostic checklist")
        return 0
    # Default: run the MCP server.
    from .server import main as run_server

    run_server()
    return 0


if __name__ == "__main__":
    sys.exit(main())
