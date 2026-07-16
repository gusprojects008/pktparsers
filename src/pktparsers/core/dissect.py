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
from logging import getLogger
from pktparser.app.app import make_config as make_app_config
from pktparsers.core.parsing import insert_item
from pktparsers.core.registry import get_dissector_parser
from pktparsers.core.traffic import TrafficContext
from pktparsers.core.dissectors import registry
from pktparsers.core import (analysis, crypt)
from pktparsers.core.definitions.result import TIMESTAMP
from pktparsers.core.definitions.parsing import (PARSED, RAW, COUNTER)
from pktparsers.core.definitions.entries import (PROTOCOL, ANALYSIS, CRYPT, DLT, PARSE, TRAFFIC_SUMMARY, VALUE, CACHED, TIMESTAMP)

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
    
    def __init__(self, dissector_id str | int = DLT_IEEE802_11_RADIO, config: AppConfig = make_app_config()):
        """
        Args:
            dissector_id: protocol name or DLT type as string ("DLT_IEEE802_11_RADIO") or int (127)
            config: DissectConfig instance (default: empty config)
        """
        self.dissector_id = dissector_id
        self.dissectors_config = config.dissect
        self.parser = get_dissector_parser(self.dissector_id)
        self.traffic_ctx = TrafficContext()
        self.counter = 0
        self._token = None
        self._key_cache: dict[str, dict[str, bytes]] = {}

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

    def cache_key(self, device_id: str, dissector_id: int | str, key: bytes) -> None:
        self._key_cache.setdefault(device_id, {})[dissector_id] = key

    def get_cached_key(self, device_id: str, dissector_id: int | str) -> bytes | None:
        return self._key_cache.get(device_id, {}).get(dissector_id)

    @classmethod
    def get_credentials(cls, dissector_id: int | str, address: str = None) -> list[dict]:
        """
        Retorna lista de keys configuradas para o protocolo.
        `address` é hint — se o engine já tem cache para aquele device, retorna
        direto sem tentativa e erro.
        """
        ctx = cls.current()
        if not ctx:
            return []
    
        # 1. Verifica cache primeiro
        if address:
            cached = ctx.get_cached_key(address, dissector_id)
            if cached:
                return [{TYPE: CACHED, VALUE: cached}]
    
        # 2. Retorna lista de credentials configuradas (tentativa e erro)
        proto_config = ctx.config.get(dissector_id, {})
        return proto_config.get(CRYPT, {}).get(CREDENTIALS, {}).get(KEYS, [])


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
            with ParseContext(packet, offset, dissector_id = self.dissector_id) as ctx:
                self.parser()
                parsed = ctx.result
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

def make_config() -> dict:
    """
    structure:
    {
        "global": {
            "crypt":    {},   # make_config() de core/crypt.py  (vazio agora)
            "parse":    {},   # make_config() de core/parsing.py (generate_parse_config)
            "analysis": {"traffic_summary": True}  # make_config() de core/analysis.py
        },
        "dissectors": {
            "DLT_IEEE802_11_RADIO": {
                "crypt": {"credentials": {"bssid": {}}, "config": {}},   # dot11_radio/crypt.py make_config()
                "parse": {"assume_fcs": False},        # dot11_radio/parse.py make_config()
                "analysis": {},
            },
            "DLT_EN10MB": {
                "crypt": {"credentials": {"bssid": {}}, "config": {}},
                "parse": {"assume_fcs": False},
                "analysis": {},
            },
            ...
            "ieee802_eap": {"parse": {}, "crypt": {"credentials": {}, "config": {}}, "analysis": {}},
            "ieee802_eapol": {"parse": {}, "crypt": {"credentials": {}, "config": {}}, "analysis": {}},
            ...
        }
    }
    """

    configs = {
        name: entry.config
        for name, entry in registry.DISSECTORS.items()
        if entry.config
    }
    return configs

