@dataclass 
class TrafficSummary: 
    devices: dict[str, DeviceEntry] 
    entries: set | list

@dataclass
class DeviceEntry:
    ids: set[str] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    protocol_data: dict[str, Any] = field(default_factory=dict)
