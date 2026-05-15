"""Shared test fixtures, including an in-memory mock GDB stub socket."""
from __future__ import annotations

import socket
from typing import Iterable

import pytest


class MockGDBSocket:
    """
    Minimal stand-in for socket.socket sufficient to drive GDBStub.

    Caller pre-loads a list of canned reply payloads (without $...# framing).
    Each `sendall` of a `$...#XX` packet consumes one reply, framed back to
    the client with proper `+` ack prefix.
    """

    def __init__(self, replies: Iterable[str]):
        self._replies = list(replies)
        self._send_log: list[bytes] = []
        # bytes the client will read next, in order
        self._rx = b""
        self._timeout: float | None = None
        self._closed = False

    # --- socket API surface used by GDBStub ---

    def settimeout(self, timeout: float | None) -> None:
        self._timeout = timeout

    def gettimeout(self) -> float | None:
        return self._timeout

    def sendall(self, data: bytes) -> None:
        if self._closed:
            raise OSError("socket closed")
        self._send_log.append(data)
        # client may send raw `+` acks for replies — no-op.
        if data == b"+":
            return
        # interrupt byte
        if data == b"\x03":
            return
        # Otherwise must be `$payload#XX` — pop one canned reply, frame it,
        # and prepend an ack so the next `_read_exact(1)` returns `+`.
        if not (data.startswith(b"$") and b"#" in data):
            raise AssertionError(f"unexpected bytes sent: {data!r}")
        # Always ack. If a canned reply is queued, frame it too. Otherwise
        # the test is expected to feed an unsolicited reply later
        # (used for `c`, where the stop reply comes after a run delay).
        self._rx += b"+"
        if self._replies:
            self._rx += _frame(self._replies.pop(0))

    def recv(self, n: int) -> bytes:
        if self._closed and not self._rx:
            return b""
        if not self._rx:
            raise socket.timeout("no data queued")
        chunk = self._rx[:n]
        self._rx = self._rx[n:]
        return chunk

    def close(self) -> None:
        self._closed = True

    # --- helpers for assertions ---

    @property
    def sent_payloads(self) -> list[str]:
        """Decoded `$...#XX` payloads, in send order (acks and raw bytes excluded)."""
        out = []
        for blob in self._send_log:
            if blob.startswith(b"$") and b"#" in blob:
                end = blob.index(b"#")
                out.append(blob[1:end].decode())
        return out

    def queue_reply(self, reply: str) -> None:
        """Add a reply that will be returned on the next packet send."""
        self._replies.append(reply)

    def queue_unsolicited(self, reply: str) -> None:
        """Push a stop reply that isn't tied to a command (e.g. for wait_for_stop)."""
        self._rx += _frame(reply)


def _frame(payload: str) -> bytes:
    cs = sum(payload.encode()) & 0xFF
    return f"${payload}#{cs:02x}".encode()


@pytest.fixture
def mock_socket():
    """Factory: pass a list of replies, get a MockGDBSocket."""
    def _make(replies: Iterable[str] | None = None) -> MockGDBSocket:
        return MockGDBSocket(replies or [])
    return _make


@pytest.fixture
def stub_with_socket(monkeypatch, mock_socket):
    """
    Yields (GDBStub, MockGDBSocket). GDBStub.connect() is patched to install
    the mock socket directly rather than opening a real TCP connection.
    """
    from dolphin_re_mcp.gdb.client import GDBStub

    def _make(replies=None):
        ms = mock_socket(replies)
        stub = GDBStub()

        def fake_connect(self=stub):
            self.sock = ms
            self._recv_buf = b""

        monkeypatch.setattr(stub, "connect", fake_connect)
        stub.connect()
        return stub, ms

    return _make
