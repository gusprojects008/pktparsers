from contextvars import ContextVar
from dataclasses import dataclass, field

_dissect_context = ContextVar("_dissect_context")

@dataclass
class DissectContext:
    summaries: dict[str, list] = field(default_factory=dict)
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

@dataclass 
class TrafficSummary: 
    devices: dict[str, DeviceEntry] 
    entries: set | list | dict

@dataclass
class DeviceEntry:
    device_id: str | int = None
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    protocol_data: dict[str, Any] = field(default_factory=dict) # {"dot11": {"mac": {"device": Dot11Device, "others_entries": Dot11SpecificEntry}}, "dot3": {"mac": {"device": Dot3Device, "others_entries": Dot3SpecificEntry}}, "ip": {"ip": {"device": IpDevice, "others_entries": IpSpecificEntry}}, "tcp": {"ip": {"device": TcpDevice, "others_entries": TcpSpecificEntry}}}

    """
    # relationships: dict[str, dict[str, dict]] = None # essa variável evitaria ter que definir "relationships" para cada estrutura de Device de um padrão ou protocolo específico, como Dot11Device. Ficando assim exemplo: {"dot11": {"mac": {"recv": int, "sent": int, "retry": int}, "mac": {"recv": int, "sent": int, "retry": int}}, "dot3": {"mac": {"recv": int, "sent": int, "retry": int}, "mac": {"recv": int, "sent": int, "retry": int}}}
    """

"""
A interface vai ficar algo como:
TrafficSummary:
    Devices:
        [id/endereço interno (provavelmente usando a função hash() do python)] [mac, ip ou outro endereço específico relacionado à PDU da DLT principal de captura escolhida pelo usuário]: [DeviceEntry]
    Others Entries:
"""
