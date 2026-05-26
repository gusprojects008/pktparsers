# pktparsers/core/dissector.py

"""
Core dissector: Dissector, DissectConfig, AnalysisConfig

Exemplo:
    with Dissector("DLT_IEEE802_11_RADIO") as dissector:
        result = dissector.dissect(raw_packet_bytes)
        print(result[PARSED])
        print(result[TRAFFIC_SUMMARY])
"""

import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any
from logging import getLogger
from pktparsers.core.parsing import insert_item
from pktparsers.core.registry import get_dlt_parser
from pktparsers.core.context import TrafficContext
from pktparsers.core.definitions import TIMESTAMP, PARSED, RAW, COUNTER, TRAFFIC_SUMMARY

logger = getLogger(__name__)

_dissector_context = ContextVar("_dissector_context")
class Dissector:
    """
    Main packet dissector.
    
    Usage:
        # Context manager (recommended)
        with Dissector("DLT_IEEE802_11_RADIO", config=cfg) as dissector:
            result = dissector.dissect(packet_bytes)
        
        # Or explicit stack management
        dissector = Dissector("DLT_IEEE802_11_RADIO")
        dissector.__enter__()
        try:
            result = dissector.dissect(packet_bytes)
        finally:
            dissector.__exit__()
    """
    
    def __init__(self, dlt: str | int, config: DissectConfig = None):
        """
        Args:
            dlt: DLT type as string ("DLT_IEEE802_11_RADIO") or int (127)
            config: DissectConfig instance (default: empty config)
        """
        self.dlt = dlt
        self.config = config or DissectConfig()
        self.parser = get_dlt_parser(dlt)
        self.traffic_ctx = TrafficContext()
        self.counter = 0
        self._token = None

    def __enter__(self):
        """Set this dissector as current in context var"""
        self._token = _dissector_context.set(self)
        return self

    def __exit__(self, *args):
        """Reset context var"""
        if self._token:
            _dissector_context.reset(self._token)

    @staticmethod
    def current():
        """Get current Dissector from context"""
        return _dissector_context.get(None)

    @classmethod
    def get_credentials(cls, protocol: str, key: str = None) -> dict | None:
        ctx = cls.current()
        if not ctx:
            return None
        creds = ctx.config.credentials.get(protocol, {})
        return creds.get(key) if key else creds

    def dissect(self, packet: bytes, offset: int = 0) -> dict:
        """
        Dissect a single packet.
        
        Args:
            packet: raw packet bytes
            offset: offset to start parsing (default: 0)
            
        Returns:
            dict with keys:
                - PARSED: parsed packet tree
                - RAW: original packet bytes (hex)
                - COUNTER: packet sequence number
                - TIMESTAMP: dissection timestamp
                - "traffic_summary": traffic context summary (if analysis enabled)
        """
        
        with self.traffic_ctx:
            parsed = self.parser(packet, offset)
            
            # Enrich result
            insert_item(parsed, RAW, packet.hex())
            insert_item(parsed, COUNTER, self.counter)
            insert_item(parsed, TIMESTAMP, time.time())
            
            result = {
                PARSED: parsed,
            }
            
            if self.config.analysis.traffic_summary:
                result[TRAFFIC_SUMMARY] = self.traffic_ctx.summary
                
            self.counter += 1
            return result


# ---------------------------------------------------------------------------
# Auto-build from registry (no manual credential input)
# ---------------------------------------------------------------------------

def make_config():
    """
    Build a dissect config using only the defaults baked into the DLT/PROTOCOL

    Useful for:
      - Passive capture analysis (no decryption needed)
      - Tooling that derives config programmatically from pcapng metadata

    The result has empty credentials and default parse/analysis options.
    """
