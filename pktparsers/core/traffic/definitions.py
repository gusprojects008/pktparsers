@dataclass 
class TrafficSummary: 
    devices: set[str, DeviceEntry]
    entries: Any

@dataclass
class DeviceEntry:
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    protocol_data: dict[str, [str | int, Any]] = field(default_factory=dict)
    """
    protocol_data structure:
    {
        "l2": {
            "dot11": {"device": {}, "outras entries": {}},
            "dot3": {"device": {}, "outras entries": {}},
        },
        "l3": {
            "ip": {"device": {}, "outras entries": {}},
            "arp": {"device": {}, "outras entries": {}},
        },
        "l4": {
            "tcp": {"device": {}, "outras entries": {}},
            "udp: {"device": {}, "outras entries": {}},
        },
    }
    """
   entries: Any
