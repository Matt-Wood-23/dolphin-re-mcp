"""
Watchpoint spike — go/no-go test for the Dolphin RE MCP plan.

Connects to Dolphin's built-in GDB stub, sets a hardware write watchpoint
on a known-mutating address, waits for it to fire, prints PC + GPRs.

If this works reliably, the rest of the MCP plan is real.
If it doesn't, we need a different approach (Lua fork, polling, etc.).

USAGE
-----
1. In Dolphin: Config → Interface → enable "Wait for GDB connection on Boot"
   AND set "GDB socket port" (default 55432).
   Some builds also expose this via View → Code/Memory panels — make sure
   those are CLOSED (the GDB stub is single-client).
2. Boot the MH Tri ISO. Dolphin will halt waiting for a GDB connection.
3. Run this script: python spike_watchpoint.py
4. The script connects, sets the watchpoint, and continues execution.
5. Throw an ammo shot in-game. The watchpoint should fire and print PC + GPRs.
"""

import socket
import sys
import time

HOST = "localhost"
PORT = 55432
WATCH_ADDR = 0x806ADAC4   # slot1+0x4C, ammo-shot address from cheatmine
WATCH_SIZE = 4
WAIT_SECONDS = 120        # how long to wait for the user to trigger the write


class GDBStub:
    """Minimal GDB Remote Serial Protocol client — only what the spike needs."""

    def __init__(self, host=HOST, port=PORT, timeout=5.0):
        print(f"[*] connecting to {host}:{port} ...")
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._recv_buf = b""
        print("[+] connected")

    @staticmethod
    def _checksum(payload: str) -> int:
        return sum(payload.encode()) & 0xFF

    def _send_packet(self, payload: str, expect_ack: bool = True) -> None:
        framed = f"${payload}#{self._checksum(payload):02x}"
        self.sock.sendall(framed.encode())
        if expect_ack:
            ack = self._read_exact(1)
            if ack != b"+":
                raise RuntimeError(f"expected ack, got {ack!r}")

    def _read_exact(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise RuntimeError("socket closed")
            out += chunk
        return out

    def _read_packet(self, timeout: float | None = None) -> str:
        """Read one $...#XX packet from the stub, ack it, return payload."""
        old_timeout = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            # find '$'
            while b"$" not in self._recv_buf:
                self._recv_buf += self.sock.recv(4096)
            start = self._recv_buf.index(b"$") + 1
            # find '#'
            while b"#" not in self._recv_buf[start:]:
                self._recv_buf += self.sock.recv(4096)
            end = self._recv_buf.index(b"#", start)
            # need 2 more bytes for checksum
            while len(self._recv_buf) < end + 3:
                self._recv_buf += self.sock.recv(4096)
            payload = self._recv_buf[start:end].decode(errors="replace")
            self._recv_buf = self._recv_buf[end + 3:]
            # ack
            self.sock.sendall(b"+")
            return payload
        finally:
            self.sock.settimeout(old_timeout)

    def cmd(self, payload: str) -> str:
        """Send a command, read one reply packet."""
        self._send_packet(payload)
        return self._read_packet()

    # ---- high-level ops ----

    def query_supported(self) -> str:
        return self.cmd("qSupported:multiprocess+;swbreak+;hwbreak+")

    def why_halted(self) -> str:
        return self.cmd("?")

    def add_write_watchpoint(self, addr: int, size: int) -> str:
        # Z2,addr,kind  →  OK / Enn / "" (unsupported)
        return self.cmd(f"Z2,{addr:x},{size}")

    def remove_write_watchpoint(self, addr: int, size: int) -> str:
        return self.cmd(f"z2,{addr:x},{size}")

    def continue_and_wait(self, timeout: float) -> str:
        """Send 'c' (continue), then block for a stop reply."""
        self._send_packet("c")
        return self._read_packet(timeout=timeout)

    def read_registers(self) -> bytes:
        """'g' returns a hex blob of all registers concatenated."""
        hex_blob = self.cmd("g")
        return bytes.fromhex(hex_blob)

    def read_register(self, regnum: int) -> int | None:
        """
        'p<regnum_hex>' returns a hex blob of one register, or 'E<errno>' on failure.
        Dolphin PPC layout: 0x00-0x1F = r0-r31, 0x20-0x3F = f0-f31,
        0x40 = PC, 0x41 = MSR, 0x42 = CR, 0x43 = LR, 0x44 = CTR, 0x45 = XER.
        """
        reply = self.cmd(f"p{regnum:x}")
        if not reply or reply.startswith("E") or reply == "":
            return None
        try:
            return int.from_bytes(bytes.fromhex(reply), "big")
        except ValueError:
            return None


def parse_dolphin_gprs(reg_blob: bytes) -> dict[str, int]:
    """
    Dolphin's 'g' packet returns 32 GPRs (4 bytes each, big-endian) = 128 bytes.
    Other registers (PC, LR, FPRs, etc.) require individual 'p' queries.
    """
    out = {}
    for i in range(32):
        off = i * 4
        if off + 4 > len(reg_blob):
            break
        out[f"r{i}"] = int.from_bytes(reg_blob[off:off + 4], "big")
    return out


def parse_stop_reply(reply: str) -> dict[str, int]:
    """
    Stop reply format: T<sig><regnum_hex>:<value_hex>;<regnum_hex>:<value_hex>;...
    Dolphin sends PC (reg 0x40 = 64) and SP (reg 1) in the stop reply.
    Returns {'signal': N, 'pc': addr, 'sp': addr, ...} — keys are register names where known.
    """
    out: dict[str, int] = {}
    if not reply.startswith("T"):
        return out
    out["signal"] = int(reply[1:3], 16)
    body = reply[3:].rstrip(";")
    if not body:
        return out
    REG_NAMES = {1: "sp", 0x40: "pc"}
    for kv in body.split(";"):
        if ":" not in kv:
            continue
        k, v = kv.split(":", 1)
        try:
            regnum = int(k, 16)
            value = int(v, 16)
        except ValueError:
            continue
        out[REG_NAMES.get(regnum, f"reg_0x{regnum:x}")] = value
    return out


def main() -> int:
    try:
        stub = GDBStub()
    except (ConnectionRefusedError, OSError) as e:
        print(f"[!] connection failed: {e}")
        print("    Is Dolphin running with the GDB stub enabled?")
        print("    Config → Interface → 'Wait for GDB connection on Boot'")
        print(f"    GDB socket port: {PORT}")
        return 1

    print("[*] qSupported handshake ...")
    print(f"    reply: {stub.query_supported()[:120]}")

    print("[*] '?' (why halted) ...")
    print(f"    reply: {stub.why_halted()}")

    print(f"[*] setting WRITE watchpoint at 0x{WATCH_ADDR:08x}, size {WATCH_SIZE} ...")
    reply = stub.add_write_watchpoint(WATCH_ADDR, WATCH_SIZE)
    print(f"    reply: {reply!r}")
    if reply == "":
        print("[!] empty reply = unsupported. Dolphin's GDB stub does not")
        print("    accept Z2 write watchpoints in this build. NO-GO.")
        return 2
    if reply.startswith("E"):
        print(f"[!] error response. NO-GO.")
        return 2
    if reply != "OK":
        print(f"[?] unexpected reply: {reply!r} — proceeding anyway")

    print(f"[*] continuing execution; throw an ammo shot within {WAIT_SECONDS}s ...")
    print("    (each watchpoint hit will print and auto-continue; Ctrl+C to stop)")
    hit_num = 0
    t0 = time.time()
    while True:
        try:
            stop = stub.continue_and_wait(timeout=WAIT_SECONDS)
        except socket.timeout:
            print(f"[!] no further hit in {WAIT_SECONDS}s — stopping.")
            break
        except KeyboardInterrupt:
            print("\n[!] stopped by user.")
            break
        hit_num += 1
        elapsed = time.time() - t0
        stop_info = parse_stop_reply(stop)
        pc = stop_info.get("pc")
        sp = stop_info.get("sp")
        lr = stub.read_register(0x43)   # LR — caller return address
        reg_blob = stub.read_registers()
        gprs = parse_dolphin_gprs(reg_blob)
        pc_str = f"0x{pc:08x}" if pc else "?"
        lr_str = f"0x{lr:08x}" if lr else "?"
        print(f"\n[hit #{hit_num}] +{elapsed:.1f}s  PC={pc_str}  LR={lr_str}")
        # Show only the GPRs likely to matter — r3-r6 (args), r31 (frame pointer)
        for r in ("r3", "r4", "r5", "r6", "r31"):
            v = gprs.get(r)
            if v is not None:
                print(f"          {r}=0x{v:08x}")

    print()
    print("=" * 60)
    print(f"VERDICT — {hit_num} watchpoint hit(s) captured")
    print("=" * 60)
    print("[GO] Hardware write watchpoint works. Stop replies arrive with PC.")
    print("     Cross-reference each PC against Ghidra to confirm writer site.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
