"""
Minimal GDB Remote Serial Protocol client for Dolphin.

Carried forward from spike/spike_watchpoint.py with production additions:
  - read_mem / write_mem (`m` / `M` packets)
  - software breakpoints (`Z0` / `z0`)
  - read & access watchpoints (`Z3` / `Z4`)
  - single-step (`s`)
  - interrupt (0x03)
  - heartbeat (`qC`)
  - split continue_async() / wait_for_stop() so a watcher task can own the wait

Wire-protocol facts that bit us in the spike (encoded here, not re-learned):
  * Every `$...#XX` packet from the stub must be acked with `+`.
  * `g` returns 32 GPRs concatenated (128 bytes) — NOT the full PPC layout.
  * Stop replies carry PC (0x40) and SP (0x01) only; LR via `p43`.
  * `p<n>` returns hex, or `E<errno>`, or empty == unsupported.
"""
from __future__ import annotations

import logging
import socket
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PacketRecord:
    """One entry in the GDBStub diagnostic ring buffer."""
    ts: float            # time.monotonic() at the event
    direction: str       # 'sent' | 'recv' | 'oob' | 'note'
    payload: str         # packet body or short note (no $...# framing)
    latency_ms: float    # for 'recv': time since matching 'sent'; else 0.0


class GDBProtocolError(RuntimeError):
    """The stub returned something we couldn't make sense of."""


class GDBStubError(RuntimeError):
    """The stub returned an explicit error reply (E<errno>) or empty == unsupported."""


class ConnectionLost(RuntimeError):
    """The TCP socket to Dolphin was closed unexpectedly."""


class StubWedged(RuntimeError):
    """
    Stub socket is open but no longer processes packets within the probe
    window. Usually means Dolphin was UI-paused (the stub's CPU-thread serve
    loop is frozen), or a previous race left it in a half-state. Reconnecting
    won't help — Dolphin must be relaunched (one-shot listener).
    """


class GDBStub:
    """Minimal RSP client. Single-threaded; one outstanding command at a time."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 55432,
        timeout: float = 5.0,
        diag_buf_size: int = 64,
    ):
        self.host = host
        self.port = port
        self.default_timeout = timeout
        self.sock: socket.socket | None = None
        self._recv_buf = b""
        # Out-of-band stop replies that arrived during another command's ack
        # read. Drained by _read_packet before going to the wire.
        self._pending_replies: list[str] = []
        # Diagnostic ring buffer: every send/receive/note is logged here, so
        # when the stub wedges we can dump the last ~N events and see the
        # exact packet sequence that preceded it. Lock-free single-thread
        # appends (stub access is serialized by session.gdb_lock).
        self._diag: deque[PacketRecord] = deque(maxlen=diag_buf_size)
        self._last_send_ts: float | None = None
        self._last_send_payload: str | None = None

    # ---- lifecycle ----

    def connect(self) -> None:
        if self.sock is not None:
            return
        log.info("connecting to %s:%d", self.host, self.port)
        self.sock = socket.create_connection(
            (self.host, self.port), timeout=self.default_timeout
        )
        self.sock.settimeout(self.default_timeout)
        self._recv_buf = b""
        log.info("connected")

    def close(self) -> None:
        if self.sock is None:
            return
        try:
            self.sock.close()
        finally:
            self.sock = None
            self._recv_buf = b""

    def detach(self) -> None:
        """Send `D` (detach) before closing. Stub resumes the CPU."""
        try:
            self.cmd("D")
        except (GDBProtocolError, ConnectionLost, OSError):
            pass
        self.close()

    def is_alive(self) -> bool:
        """Heartbeat — `qC` returns current thread id. Cheap, no side effects."""
        if self.sock is None:
            return False
        try:
            self.cmd("qC")
            return True
        except (ConnectionLost, OSError, GDBProtocolError):
            return False

    def probe_responsive(self, timeout: float = 0.5) -> bool:
        """
        Fast `qC` heartbeat with a short timeout. Safe to call while the CPU
        is running — stop replies that arrive during the probe are buffered
        into `_pending_replies` by `_consume_ack`.

        Returns False if the stub doesn't respond within `timeout` seconds.
        Use this before any modify-the-stub operation that would otherwise
        hang indefinitely on a wedged stub.
        """
        if self.sock is None:
            return False
        sock = self.sock
        old = sock.gettimeout()
        try:
            sock.settimeout(timeout)
            try:
                self._send_packet("qC")
                reply = self._read_packet_from_wire(timeout=timeout)
            except (socket.timeout, OSError, GDBProtocolError, ConnectionLost):
                return False
            # Expected: "QC<tid>" or empty. Any non-error reply means the
            # serve loop is pumping packets.
            return not reply.startswith("E")
        finally:
            try:
                sock.settimeout(old)
            except OSError:
                pass

    # ---- diagnostic ring buffer ----

    def _record_send(self, payload: str) -> None:
        ts = time.monotonic()
        self._diag.append(PacketRecord(ts=ts, direction="sent", payload=payload, latency_ms=0.0))
        self._last_send_ts = ts
        self._last_send_payload = payload

    def _record_recv(self, payload: str, kind: str = "recv") -> None:
        ts = time.monotonic()
        # For solicited replies, compute latency since the matching send.
        # OOB packets (stop replies arriving during another command's ack
        # read) are recorded with latency 0 — there's no meaningful match.
        if kind == "recv" and self._last_send_ts is not None:
            latency_ms = (ts - self._last_send_ts) * 1000.0
        else:
            latency_ms = 0.0
        self._diag.append(PacketRecord(ts=ts, direction=kind, payload=payload, latency_ms=latency_ms))

    def record_note(self, text: str) -> None:
        """Annotate the diag stream with a free-form note (e.g. 'pause_tool start')."""
        self._diag.append(
            PacketRecord(ts=time.monotonic(), direction="note", payload=text, latency_ms=0.0)
        )

    def diag_snapshot(self, last_n: int | None = None) -> list[dict]:
        """
        Return a snapshot of the diagnostic ring buffer as plain dicts.

        Timestamps are normalized: the most recent event is at relative time
        0 ms, earlier events are negative (ms ago). Easier to read than raw
        monotonic clock values.
        """
        items = list(self._diag)
        if last_n is not None and last_n > 0:
            items = items[-last_n:]
        if not items:
            return []
        now = time.monotonic()
        out = []
        for rec in items:
            out.append(
                {
                    "rel_ms": round((rec.ts - now) * 1000.0, 2),
                    "dir": rec.direction,
                    "payload": rec.payload[:200],
                    "latency_ms": round(rec.latency_ms, 2) if rec.latency_ms else 0.0,
                }
            )
        return out

    # ---- wire protocol ----

    @staticmethod
    def _checksum(payload: str) -> int:
        return sum(payload.encode()) & 0xFF

    def _require_sock(self) -> socket.socket:
        if self.sock is None:
            raise ConnectionLost("GDB socket is not connected")
        return self.sock

    def _send_packet(self, payload: str, expect_ack: bool = True) -> None:
        sock = self._require_sock()
        framed = f"${payload}#{self._checksum(payload):02x}"
        log.debug("send: %s", framed)
        self._record_send(payload)
        try:
            sock.sendall(framed.encode())
        except (OSError, BrokenPipeError) as e:
            self.close()
            raise ConnectionLost(f"send failed: {e}") from e
        if expect_ack:
            self._consume_ack()

    def _consume_ack(self) -> None:
        """
        Read the `+` ack for the packet we just sent, tolerating out-of-band
        stop replies. A `$...#XX` packet can arrive between commands when the
        stub queued a stop reply we haven't waited on yet (e.g. a SIGINT
        response after we already consumed an unrelated watchpoint hit). We
        buffer such packets so wait_for_stop() can return them later.
        """
        while True:
            ack = self._read_exact(1)
            if ack == b"+":
                return
            if ack == b"-":
                raise GDBProtocolError("stub sent NAK ('-'); retransmit unsupported")
            if ack == b"$":
                # OOB packet — push the leading '$' back and let _read_packet
                # parse it normally. The result goes onto _pending_replies for
                # the next wait_for_stop / _read_packet caller.
                self._recv_buf = b"$" + self._recv_buf
                packet = self._read_packet_from_wire(_record_kind="oob")
                self._pending_replies.append(packet)
                continue
            raise GDBProtocolError(f"expected ack, got {ack!r}")

    def _read_exact(self, n: int) -> bytes:
        """Read `n` bytes, draining _recv_buf first then pulling from socket."""
        out = b""
        if self._recv_buf:
            take = min(n, len(self._recv_buf))
            out = bytes(self._recv_buf[:take])
            self._recv_buf = self._recv_buf[take:]
        if len(out) >= n:
            return out
        sock = self._require_sock()
        while len(out) < n:
            try:
                chunk = sock.recv(n - len(out))
            except (OSError, socket.timeout):
                raise
            if not chunk:
                self.close()
                raise ConnectionLost("socket closed mid-read")
            out += chunk
        return out

    def _read_packet(self, timeout: float | None = None) -> str:
        """
        Return the next stop reply / response packet. Out-of-band packets that
        were buffered during another command's ack read come first; otherwise
        we pull a fresh packet from the wire.
        """
        if self._pending_replies:
            return self._pending_replies.pop(0)
        return self._read_packet_from_wire(timeout=timeout)

    def _read_packet_from_wire(
        self, timeout: float | None = None, _record_kind: str = "recv"
    ) -> str:
        sock = self._require_sock()
        old_timeout = sock.gettimeout()
        if timeout is not None:
            sock.settimeout(timeout)
        try:
            while b"$" not in self._recv_buf:
                chunk = sock.recv(4096)
                if not chunk:
                    self.close()
                    raise ConnectionLost("socket closed waiting for packet start")
                self._recv_buf += chunk
            start = self._recv_buf.index(b"$") + 1
            while b"#" not in self._recv_buf[start:]:
                chunk = sock.recv(4096)
                if not chunk:
                    self.close()
                    raise ConnectionLost("socket closed waiting for packet end")
                self._recv_buf += chunk
            end = self._recv_buf.index(b"#", start)
            while len(self._recv_buf) < end + 3:
                chunk = sock.recv(4096)
                if not chunk:
                    self.close()
                    raise ConnectionLost("socket closed waiting for checksum")
                self._recv_buf += chunk
            payload = self._recv_buf[start:end].decode(errors="replace")
            self._recv_buf = self._recv_buf[end + 3 :]
            try:
                sock.sendall(b"+")
            except OSError as e:
                self.close()
                raise ConnectionLost(f"ack send failed: {e}") from e
            log.debug("recv: %s", payload[:200])
            self._record_recv(payload, kind=_record_kind)
            return payload
        finally:
            try:
                sock.settimeout(old_timeout)
            except OSError:
                pass

    def cmd(self, payload: str, timeout: float | None = None) -> str:
        """
        Send a packet, return its response. Skips _pending_replies on purpose —
        those are out-of-band stop replies, not the response to *this* command.
        """
        self._send_packet(payload)
        return self._read_packet_from_wire(timeout=timeout)

    # ---- queries ----

    def query_supported(self) -> str:
        return self.cmd("qSupported:multiprocess+;swbreak+;hwbreak+")

    def why_halted(self) -> str:
        return self.cmd("?")

    # ---- registers ----

    def read_registers(self) -> bytes:
        """`g` packet — 128 bytes (32 GPRs concatenated)."""
        reply = self.cmd("g")
        _raise_if_error(reply, "g")
        return bytes.fromhex(reply)

    def read_register(self, regnum: int) -> Optional[int]:
        """`p<regnum_hex>`. Returns None on `E<errno>` or empty (unsupported)."""
        reply = self.cmd(f"p{regnum:x}")
        if reply == "" or reply.startswith("E"):
            return None
        try:
            return int.from_bytes(bytes.fromhex(reply), "big")
        except ValueError:
            return None

    def read_register_bytes(self, regnum: int) -> Optional[bytes]:
        """Raw bytes form of `p<regnum>`. For 8-byte FPRs we want the raw blob."""
        reply = self.cmd(f"p{regnum:x}")
        if reply == "" or reply.startswith("E"):
            return None
        try:
            return bytes.fromhex(reply)
        except ValueError:
            return None

    # ---- memory ----

    def read_mem(self, addr: int, size: int) -> bytes:
        """`m<addr>,<size>` — read memory. Stub returns hex or E<errno>."""
        reply = self.cmd(f"m{addr:x},{size:x}")
        _raise_if_error(reply, f"m{addr:x},{size:x}")
        return bytes.fromhex(reply)

    def write_mem(self, addr: int, data: bytes) -> None:
        """`M<addr>,<size>:<hex>` — write memory. Stub returns OK or E<errno>."""
        reply = self.cmd(f"M{addr:x},{len(data):x}:{data.hex()}")
        _raise_if_error(reply, f"M{addr:x},{len(data):x}")
        if reply != "OK":
            raise GDBProtocolError(f"unexpected write reply: {reply!r}")

    # ---- breakpoints & watchpoints ----
    # Z0 = sw bp,  Z1 = hw bp,  Z2 = write wp,  Z3 = read wp,  Z4 = access wp.

    def add_sw_breakpoint(self, addr: int) -> str:
        return self._set_break("Z0", addr, 4)

    def remove_sw_breakpoint(self, addr: int) -> str:
        return self._set_break("z0", addr, 4)

    def add_hw_breakpoint(self, addr: int) -> str:
        return self._set_break("Z1", addr, 4)

    def remove_hw_breakpoint(self, addr: int) -> str:
        return self._set_break("z1", addr, 4)

    def add_write_watchpoint(self, addr: int, size: int) -> str:
        return self._set_break("Z2", addr, size)

    def remove_write_watchpoint(self, addr: int, size: int) -> str:
        return self._set_break("z2", addr, size)

    def add_read_watchpoint(self, addr: int, size: int) -> str:
        return self._set_break("Z3", addr, size)

    def remove_read_watchpoint(self, addr: int, size: int) -> str:
        return self._set_break("z3", addr, size)

    def add_access_watchpoint(self, addr: int, size: int) -> str:
        return self._set_break("Z4", addr, size)

    def remove_access_watchpoint(self, addr: int, size: int) -> str:
        return self._set_break("z4", addr, size)

    def _set_break(self, op: str, addr: int, size: int) -> str:
        reply = self.cmd(f"{op},{addr:x},{size}")
        if reply == "":
            raise GDBStubError(f"{op} unsupported by stub")
        if reply.startswith("E"):
            raise GDBStubError(f"{op} failed: {reply}")
        return reply

    # ---- execution ----

    def continue_async(self) -> None:
        """Send `c` without waiting for the stop reply. Pair with wait_for_stop()."""
        self._send_packet("c")

    def wait_for_stop(self, timeout: float | None = None) -> str:
        """Block until the stub sends a stop reply. Raises socket.timeout on timeout."""
        return self._read_packet(timeout=timeout)

    def continue_and_wait(self, timeout: float | None = None) -> str:
        self.continue_async()
        return self.wait_for_stop(timeout=timeout)

    def step(self, timeout: float | None = None) -> str:
        """`s` — single instruction step. Returns the stop reply payload."""
        self._send_packet("s")
        return self._read_packet(timeout=timeout)

    def interrupt(self) -> None:
        """
        Send a Ctrl+C byte (0x03) to break a running target.
        Caller should follow up with wait_for_stop() to consume the SIGINT stop reply.
        """
        sock = self._require_sock()
        try:
            sock.sendall(b"\x03")
        except OSError as e:
            self.close()
            raise ConnectionLost(f"interrupt send failed: {e}") from e

    def drain_stop_replies(self, max_wait_s: float = 0.1) -> list[str]:
        """
        Consume every queued stop reply currently buffered (both _pending_replies
        and bytes sitting on the socket). Useful before/after an interrupt to
        make sure stale replies don't tangle the next command's ack read.

        Caller must hold any necessary locks. The CPU should be paused when this
        is called; if running, this could read forever.
        """
        out: list[str] = []
        # Pending queued packets first.
        out.extend(self._pending_replies)
        self._pending_replies.clear()
        # Then any unread bytes on the wire — try short reads until a timeout.
        end = time.monotonic() + max_wait_s
        while time.monotonic() < end:
            try:
                pkt = self._read_packet_from_wire(timeout=0.02)
            except socket.timeout:
                break
            except (ConnectionLost, OSError):
                break
            out.append(pkt)
        return out

    def drain_pending_replies(self) -> list[str]:
        """Discard any buffered out-of-band stop replies. Returns what was dropped."""
        dropped = list(self._pending_replies)
        self._pending_replies.clear()
        return dropped


def _raise_if_error(reply: str, context: str) -> None:
    if reply == "":
        raise GDBStubError(f"{context}: empty reply (unsupported)")
    if reply.startswith("E") and len(reply) >= 3 and all(c in "0123456789abcdefABCDEF" for c in reply[1:3]):
        raise GDBStubError(f"{context}: stub error {reply}")
