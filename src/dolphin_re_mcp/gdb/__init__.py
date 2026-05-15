"""GDB Remote Serial Protocol client for Dolphin's built-in stub."""

from .client import GDBStub
from .registers import parse_dolphin_gprs, REG_NAMES, REG_NUMS
from .stop_reply import parse_stop_reply, StopReply

__all__ = [
    "GDBStub",
    "parse_dolphin_gprs",
    "parse_stop_reply",
    "StopReply",
    "REG_NAMES",
    "REG_NUMS",
]
