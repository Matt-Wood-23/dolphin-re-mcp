"""
Session — single owner of the GDB connection + breakpoint registry + backends.

Every tool grabs the session from `get_session()`. Tools never open their own
GDB socket. Connection state transitions live here.
"""
from __future__ import annotations

import enum
import logging
import os
import sys
import threading
from dataclasses import dataclass, field
from typing import Optional

from .gdb.client import ConnectionLost, GDBStub
from .memory.attach import (
    AttachError,
    GDBMemoryBackend,
    MemoryBackend,
    WindowsAttachBackend,
)

log = logging.getLogger(__name__)


class SessionState(str, enum.Enum):
    DISCONNECTED = "disconnected"
    CONNECTED_PAUSED = "connected_paused"
    CONNECTED_RUNNING = "connected_running"
    ERROR = "error"


@dataclass
class BreakpointSpec:
    bp_id: int
    addr: int
    kind: str  # 'sw_bp' | 'write_wp' | 'read_wp' | 'access_wp' | 'hw_bp'
    size: int = 4
    condition: Optional[str] = None     # eval'd against capture dict on hit
    captures: list[str] = field(default_factory=list)
    auto_continue: bool = False
    log: list[dict] = field(default_factory=list)


class Session:
    """Holds the GDB connection, both memory backends, and the BP registry."""

    def __init__(self):
        self.host = os.environ.get("DOLPHIN_GDB_HOST", "localhost")
        self.port = int(os.environ.get("DOLPHIN_GDB_PORT", "55432"))
        self.dumps_dir = os.environ.get("MHTRI_DUMPS_DIR")

        self.stub = GDBStub(host=self.host, port=self.port)
        self.state: SessionState = SessionState.DISCONNECTED
        self.attach_backend: Optional[WindowsAttachBackend] = None
        self.gdb_mem_backend = GDBMemoryBackend(self.stub)

        self.breakpoints: dict[int, BreakpointSpec] = {}
        self._next_id = 1
        self._lock = threading.RLock()
        # Serializes ALL GDB stub access — only one thread reads/writes the
        # socket at a time. Watcher acquires for each iteration; tools acquire
        # per call. Reentrant so a tool can call other tools.
        self.gdb_lock = threading.RLock()
        # Set by StopWatcher when running. Tools can check this to refuse
        # operations that would race with the watcher.
        self.watcher = None  # type: ignore[assignment]

    # ---- connection lifecycle ----

    def ensure_connected(self) -> None:
        """Connect lazily on first tool call. Never silently retries forever."""
        with self._lock:
            if self.state in (SessionState.CONNECTED_PAUSED, SessionState.CONNECTED_RUNNING):
                return
            try:
                self.stub.connect()
                # After connect, the stub is paused (boot-wait, or just halted).
                # A `?` confirms this — it returns a stop reply (Txx...).
                self.stub.why_halted()
                self.state = SessionState.CONNECTED_PAUSED
            except (OSError, ConnectionLost) as e:
                self.state = SessionState.DISCONNECTED
                raise ConnectionLost(
                    f"Cannot reach Dolphin GDB stub at {self.host}:{self.port}: {e}"
                ) from e
            self._try_attach()
            # Auto-resume: GDB stubs halt the target on attach by convention,
            # but the user expects the game to keep running. Kick it back into
            # RUNNING so they can play. Skip if DOLPHIN_NO_AUTO_RESUME is set
            # (for sessions that explicitly want to debug from the boot halt).
            if not os.environ.get("DOLPHIN_NO_AUTO_RESUME"):
                try:
                    with self.gdb_lock:
                        self.stub.continue_async()
                    self.state = SessionState.CONNECTED_RUNNING
                    log.info("auto-resumed after connect (set DOLPHIN_NO_AUTO_RESUME=1 to skip)")
                except Exception as e:
                    log.warning("auto-resume after connect failed: %s", e)

    def mark_running(self) -> None:
        if self.state == SessionState.CONNECTED_PAUSED:
            self.state = SessionState.CONNECTED_RUNNING

    def mark_paused(self) -> None:
        if self.state == SessionState.CONNECTED_RUNNING:
            self.state = SessionState.CONNECTED_PAUSED

    def _try_attach(self) -> None:
        """Best-effort process attach. Failures degrade to GDB-only reads."""
        if sys.platform != "win32":
            log.info("non-win32 platform; skipping process attach")
            return
        try:
            self.attach_backend = WindowsAttachBackend.find_dolphin()
        except AttachError as e:
            log.warning("process attach failed; falling back to GDB reads: %s", e)
            self.attach_backend = None

    def disconnect(self, send_detach: bool = False) -> None:
        """
        Close the connection. By default we just hang up the socket — Dolphin's
        stub stops listening after a `D` packet (it shuts the listener, not
        just the active connection), so `D` is opt-in only.
        """
        with self._lock:
            if self.attach_backend:
                self.attach_backend.close()
                self.attach_backend = None
            if self.stub.sock is not None:
                if send_detach:
                    self.stub.detach()
                else:
                    self.stub.close()
            self.state = SessionState.DISCONNECTED
            # Watchpoints are stub-local; clearing the registry on disconnect
            # keeps us honest about what's actually armed.
            self.breakpoints.clear()

    def on_connection_lost(self) -> None:
        log.warning("connection lost; transitioning to DISCONNECTED")
        self.disconnect()

    # ---- memory backend selection ----

    @property
    def mem(self) -> MemoryBackend:
        """Preferred memory backend — attach if available, GDB otherwise."""
        if self.attach_backend and self.attach_backend.is_attached():
            return self.attach_backend
        return self.gdb_mem_backend

    # ---- breakpoint registry ----

    def alloc_bp_id(self) -> int:
        with self._lock:
            i = self._next_id
            self._next_id += 1
            return i

    def register_bp(self, spec: BreakpointSpec) -> None:
        with self._lock:
            self.breakpoints[spec.bp_id] = spec

    def unregister_bp(self, bp_id: int) -> Optional[BreakpointSpec]:
        with self._lock:
            return self.breakpoints.pop(bp_id, None)

    # ---- diagnostics ----

    def health(self, probe: bool = True) -> dict:
        """
        Report connection state + diagnostics. With probe=True (default),
        actively tries to verify the stub is alive (only if we have a socket)
        — issues a `qC` heartbeat and reports the result.

        Probe is read-only and cheap. It does NOT lazily connect; if we're
        DISCONNECTED, it just reports that.
        """
        out: dict = {
            "state": self.state.value,
            "host": self.host,
            "port": self.port,
            "watcher_running": self.watcher is not None and self.watcher.is_alive(),
            "dumps_dir": self.dumps_dir,
        }
        # Attach backend details
        if self.attach_backend is not None:
            out["attach"] = {
                "pid": self.attach_backend.pid,
                "mem1_host_base": f"0x{self.attach_backend.mem1.base_addr:016x}",
                "mem2_host_base": f"0x{self.attach_backend.mem2.base_addr:016x}",
            }
        else:
            out["attach"] = None

        # Probe the stub if we believe we're connected. Use the fast probe
        # so a wedged stub doesn't make `health()` itself hang for 5s.
        if probe and self.sock_open():
            with self.gdb_lock:
                alive = self.stub.probe_responsive(timeout=0.5)
            out["stub_responsive"] = alive
            if not alive:
                # Annotate so the agent knows this is the "relaunch Dolphin"
                # state, not just "running and busy".
                out["stub_status"] = "wedged_or_ui_paused"
            if alive and self.state == SessionState.CONNECTED_PAUSED:
                # Cheap query for current PC. Skip if running or watcher-owned,
                # since either condition makes this unsafe.
                if not (self.watcher is not None and self.watcher.is_alive()):
                    try:
                        with self.gdb_lock:
                            pc = self.stub.read_register(0x40)
                        if pc is not None:
                            out["pc"] = f"0x{pc:08x}"
                    except Exception:
                        pass
            out["pending_replies"] = len(self.stub._pending_replies)  # type: ignore[attr-defined]

        out["breakpoints"] = [
            {"id": b.bp_id, "addr": f"0x{b.addr:08x}", "kind": b.kind, "size": b.size,
             "auto_continue": b.auto_continue, "log_size": len(b.log)}
            for b in self.breakpoints.values()
        ]
        return out

    def sock_open(self) -> bool:
        """Whether the GDB socket appears to be open (does not probe)."""
        return self.stub.sock is not None

_session: Optional[Session] = None
_session_lock = threading.Lock()


def get_session() -> Session:
    global _session
    with _session_lock:
        if _session is None:
            _session = Session()
        return _session
