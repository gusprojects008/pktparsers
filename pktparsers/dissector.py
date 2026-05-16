from pktparsers.common.definitions import (DissectContext, DissectionResult, TrafficContext)
from contextvars import ContextVar
from dataclasses import dataclass, field

_dissect_context = ContextVar("_dissect_context")

@dataclass
class DissectContext:
    summaries: dict[str, list] = field(default_factory=dict)
    """
    summaries structure e.g:
    {
        "l2": {
            "dot11": {"frame": {}},
            "dot3": {"frame": {}},
        },
        "l3": {
            "ip": {"packet": {}},
            "arp": {"packet": {}},
        },
        "l4": {
            "tcp": {"segment": {}},
            "udp: {"datagram": {}}
        },
        "l7": {
            "http": {"data": {}},
        },
    }
    """
    result: dict | None = None

    def __enter__(self):
        self._token = _dissect_context.set(self)
        return self

    def __exit__(self, *args):
        _dissect_context.reset(self._token)

    def add_summary(self, protocol: str, summary):
        self.summaries.setdefault(protocol, []).append(summary)

    @classmethod
    def current(cls):
        return _dissect_context.get(None)

@dataclass
class DissectionResult:
    parsed: dict
    summaries: dict,
    traffic: TrafficSummary

class Dissector:
    def __init__(self, dlt: str | int): 
        self.dlt = dlt 
        self.traffic_ctx = TrafficContext(dlt=dlt) 
        self.parser = get_parser(dlt)

    def dissect(self, packet: bytes, offset: int = 0):
        with DissectContext() as dissect_ctx:

            parsed = self.parser(packet, offset)

            dissect_ctx.result = parsed

            traffic_summary = self.traffic_ctx.update(
                dissect_ctx.summaries
            )

            return DissectionResult(
                parsed=parsed,
                summaries=dissect_ctx.summaries,
                traffic=traffic_summary
            )
