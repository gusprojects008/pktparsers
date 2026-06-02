# pktparsers/core/traffic.py

import time
from contextvars import ContextVar
from .defintions import ANNOTATIONS, DEVICES, FIRST_SEEN, LAST_SEEN, PROTOCOLS_DATA

def make_device_entry() -> dict:
    return {
        FIRST_SEEN: time.time(),
        LAST_SEEN:  time.time(),
        PROTOCOLS_DATA: {},
        ANNOTATIONS: {},
    }

def make_traffic_summary() -> dict:
    return {
        DEVICES: {},
        ANNOTATIONS: {},
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
