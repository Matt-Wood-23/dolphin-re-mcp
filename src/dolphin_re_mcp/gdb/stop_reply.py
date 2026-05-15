"""
Parse GDB stop-reply packets.

T-packet format: T<sig><regnum_hex>:<value_hex>;<regnum_hex>:<value_hex>;...
Dolphin populates PC (0x40) and SP (0x01) in stop replies. Other registers
must be queried with `p<n>`.

Other replies the stub can send after a continue/step:
  S<sig>  — signal received, no register payload
  W<exit> — process exited (not seen on Dolphin in practice)
  X<sig>  — terminated by signal
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .registers import REG_NAMES


@dataclass
class StopReply:
    raw: str
    signal: int | None = None
    registers: dict[str, int] = field(default_factory=dict)
    # 'watch' / 'rwatch' / 'awatch' if the stub annotates the watchpoint address
    watch_kind: str | None = None
    watch_addr: int | None = None
    # `library:` / `replaylog:` / etc., kept verbatim
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def pc(self) -> int | None:
        return self.registers.get("pc")

    @property
    def sp(self) -> int | None:
        return self.registers.get("sp")


def parse_stop_reply(reply: str) -> StopReply:
    """Parse a stop reply. Tolerates the S/T/W/X forms; never raises on bad input."""
    out = StopReply(raw=reply)
    if not reply:
        return out

    head = reply[0]
    if head in ("S", "T", "X"):
        try:
            out.signal = int(reply[1:3], 16)
        except ValueError:
            return out
    elif head == "W":
        try:
            out.signal = int(reply[1:3], 16)
        except ValueError:
            pass
        return out
    else:
        return out

    if head != "T":
        return out

    body = reply[3:].rstrip(";")
    if not body:
        return out

    for kv in body.split(";"):
        if ":" not in kv:
            continue
        k, v = kv.split(":", 1)
        # numeric regnum → register value
        try:
            regnum = int(k, 16)
        except ValueError:
            # named field — watch/rwatch/awatch/library/etc.
            if k in ("watch", "rwatch", "awatch"):
                out.watch_kind = k
                try:
                    out.watch_addr = int(v, 16)
                except ValueError:
                    pass
            else:
                out.extra[k] = v
            continue
        try:
            value = int(v, 16)
        except ValueError:
            continue
        name = REG_NAMES.get(regnum, f"reg_0x{regnum:x}")
        out.registers[name] = value
    return out
