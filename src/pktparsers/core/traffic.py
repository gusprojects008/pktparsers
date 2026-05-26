# pktparsers/core/traffic.py

import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Optional

def make_device_entry() -> dict:
    return {
        "first_seen": time.time(),
        "last_seen":  time.time(),
        "protocols_data": {},
        "annotations": {},
    }

def make_traffic_summary() -> dict:
    return {
        "devices": {},
        "annotations": {},
    }


"""
Context manager traffic analysis.
TrafficContext: accumulates traffic statistics across dissected packets
"""

_traffic_context = ContextVar("_traffic_context")

class TrafficContext:
    def __init__(self):
        self.summary = make_traffic_summary()

    def __enter__(self):
        self._token = _traffic_context.set(self)
        return self

    def __exit__(self, *args):
        _traffic_context.reset(self._token)

    @classmethod
    def current(cls) -> "TrafficContext | None":
        return _traffic_context.get(None)
