"""
Process-attach memory backend for Dolphin (Windows).

Reads emulated MEM1 / MEM2 directly out of the Dolphin process's address space
without pausing the JIT — the "no-pause path" mentioned in the build plan.

Discovery strategy (mirrors DolphinMemoryEngine):
  - Walk the target's memory regions with VirtualQueryEx.
  - First MEM_MAPPED region with RegionSize == 0x02000000 = MEM1 (24 MB usable,
    32 MB reserved with guard space).
  - First MEM_MAPPED region with RegionSize == 0x04000000 = MEM2 (64 MB).

Falls back to a GDBStub-based reader if attach fails — slower but always works
as long as the GDB socket is connected.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import sys
from dataclasses import dataclass
from typing import Optional, Protocol

from .routing import MEM1_BASE, MEM1_END, MEM2_BASE, MEM2_END, Region, route

log = logging.getLogger(__name__)

# Sizes Dolphin reserves for the mapped regions on Windows. The first matches
# both modern Dolphin (1-step VirtualAlloc) and 2603a (the user's build).
MEM1_RESERVED_SIZE = 0x02000000  # 32 MB reservation; 24 MB usable at offset 0
MEM2_RESERVED_SIZE = 0x04000000  # 64 MB reservation; 64 MB usable

# Windows constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008

MEM_COMMIT = 0x1000
MEM_MAPPED = 0x40000
PAGE_READWRITE = 0x04
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100


class MemoryBackend(Protocol):
    """Anything that can serve memory reads at MH Tri virtual addresses."""

    def read(self, addr: int, size: int) -> bytes: ...
    def write(self, addr: int, data: bytes) -> None: ...
    def is_attached(self) -> bool: ...
    def close(self) -> None: ...


class AttachError(RuntimeError):
    """Couldn't attach to Dolphin's process or find MEM regions."""


@dataclass
class _Region:
    base_addr: int  # host-process virtual address of region start
    size: int


class WindowsAttachBackend:
    """
    Fast path: VirtualQueryEx + ReadProcessMemory against Dolphin.exe.

    Construct with `WindowsAttachBackend.find_dolphin()` for the usual case.
    """

    def __init__(self, pid: int, mem1: _Region, mem2: _Region):
        self.pid = pid
        self.mem1 = mem1
        self.mem2 = mem2
        self.handle: int | None = None
        self._open_handle()

    # ---- discovery ----

    @classmethod
    def find_dolphin(cls, process_name: str = "Dolphin.exe") -> "WindowsAttachBackend":
        if sys.platform != "win32":
            raise AttachError("WindowsAttachBackend only supports win32")
        pid = _find_pid(process_name)
        if pid is None:
            raise AttachError(f"process {process_name!r} not found")
        regions = _walk_mem_regions(pid)
        mem1 = _pick_first(regions, MEM1_RESERVED_SIZE)
        mem2 = _pick_first(regions, MEM2_RESERVED_SIZE)
        if mem1 is None:
            raise AttachError(
                f"could not find MEM1 region (size 0x{MEM1_RESERVED_SIZE:x}) in PID {pid}"
            )
        if mem2 is None:
            raise AttachError(
                f"could not find MEM2 region (size 0x{MEM2_RESERVED_SIZE:x}) in PID {pid}"
            )
        log.info(
            "attached PID=%d MEM1=0x%x MEM2=0x%x", pid, mem1.base_addr, mem2.base_addr
        )
        return cls(pid, mem1, mem2)

    # ---- lifecycle ----

    def _open_handle(self) -> None:
        rights = (
            PROCESS_QUERY_INFORMATION
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE
            | PROCESS_VM_OPERATION
        )
        handle = ctypes.windll.kernel32.OpenProcess(rights, False, self.pid)
        if not handle:
            err = ctypes.get_last_error()
            raise AttachError(f"OpenProcess(PID={self.pid}) failed (err={err})")
        self.handle = handle

    def close(self) -> None:
        if self.handle:
            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None

    def is_attached(self) -> bool:
        return self.handle is not None

    # ---- I/O ----

    def read(self, addr: int, size: int) -> bytes:
        host_addr = self._host_addr(addr, size)
        buf = (ctypes.c_ubyte * size)()
        bytes_read = ctypes.c_size_t(0)
        ok = ctypes.windll.kernel32.ReadProcessMemory(
            self.handle,
            ctypes.c_void_p(host_addr),
            buf,
            size,
            ctypes.byref(bytes_read),
        )
        if not ok or bytes_read.value != size:
            err = ctypes.get_last_error()
            raise OSError(
                f"ReadProcessMemory(0x{addr:x}+{size}) read {bytes_read.value}/{size} (err={err})"
            )
        return bytes(buf)

    def write(self, addr: int, data: bytes) -> None:
        host_addr = self._host_addr(addr, len(data))
        bytes_written = ctypes.c_size_t(0)
        ok = ctypes.windll.kernel32.WriteProcessMemory(
            self.handle,
            ctypes.c_void_p(host_addr),
            data,
            len(data),
            ctypes.byref(bytes_written),
        )
        if not ok or bytes_written.value != len(data):
            err = ctypes.get_last_error()
            raise OSError(
                f"WriteProcessMemory(0x{addr:x}+{len(data)}) wrote "
                f"{bytes_written.value}/{len(data)} (err={err})"
            )

    def _host_addr(self, addr: int, size: int) -> int:
        routed = route(addr, size)
        if routed.region is Region.MEM1:
            return self.mem1.base_addr + routed.offset
        return self.mem2.base_addr + routed.offset


class GDBMemoryBackend:
    """
    Fallback backend that reads/writes via the GDB stub's `m`/`M` packets.

    Slower than the attach backend (each call pauses the JIT briefly) but always
    works while the socket is open.
    """

    def __init__(self, stub):  # GDBStub — kept untyped to avoid import cycle
        self.stub = stub

    def read(self, addr: int, size: int) -> bytes:
        route(addr, size)  # range-check; raises AddressOutOfRange if bad
        return self.stub.read_mem(addr, size)

    def write(self, addr: int, data: bytes) -> None:
        route(addr, len(data))
        self.stub.write_mem(addr, data)

    def is_attached(self) -> bool:
        return self.stub.sock is not None

    def close(self) -> None:
        pass


# ----------------- internal helpers ------------------


def _find_pid(name: str) -> Optional[int]:
    """Return PID for first process matching `name`, or None."""
    import psutil

    target = name.lower()
    for proc in psutil.process_iter(["name", "pid"]):
        try:
            pname = (proc.info.get("name") or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if pname == target:
            return proc.info["pid"]
    return None


class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("__alignment1", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
        ("__alignment2", wt.DWORD),
    ]


def _walk_mem_regions(pid: int) -> list[_Region]:
    """Walk a process's address space, return all MEM_MAPPED RW regions."""
    rights = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    handle = ctypes.windll.kernel32.OpenProcess(rights, False, pid)
    if not handle:
        err = ctypes.get_last_error()
        raise AttachError(f"OpenProcess(PID={pid}) for region walk failed (err={err})")
    try:
        out: list[_Region] = []
        addr = 0
        mbi = _MEMORY_BASIC_INFORMATION()
        size = ctypes.sizeof(mbi)
        while True:
            ret = ctypes.windll.kernel32.VirtualQueryEx(
                handle, ctypes.c_void_p(addr), ctypes.byref(mbi), size
            )
            if ret == 0:
                break
            if (
                mbi.State == MEM_COMMIT
                and mbi.Type == MEM_MAPPED
                and mbi.Protect == PAGE_READWRITE
                and mbi.BaseAddress is not None
            ):
                out.append(_Region(base_addr=mbi.BaseAddress, size=mbi.RegionSize))
            next_addr = (mbi.BaseAddress or 0) + mbi.RegionSize
            if next_addr <= addr:
                break
            addr = next_addr
        return out
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _pick_first(regions: list[_Region], wanted_size: int) -> Optional[_Region]:
    for r in regions:
        if r.size == wanted_size:
            return r
    return None
