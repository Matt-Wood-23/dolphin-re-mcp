"""Process-attach memory backend + MEM1/MEM2 address routing."""

from .routing import (
    MEM1_BASE,
    MEM1_END,
    MEM1_SIZE,
    MEM2_BASE,
    MEM2_END,
    MEM2_SIZE,
    AddressOutOfRange,
    Region,
    route,
)

__all__ = [
    "MEM1_BASE",
    "MEM1_END",
    "MEM1_SIZE",
    "MEM2_BASE",
    "MEM2_END",
    "MEM2_SIZE",
    "AddressOutOfRange",
    "Region",
    "route",
]
