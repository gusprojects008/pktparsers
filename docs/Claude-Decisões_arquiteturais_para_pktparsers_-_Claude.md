# Decisões arquiteturais para pktparsers - Claude

**Source:** Claude  
**Date:** 5/9/2026, 9:27:33 PM  
**Link:** https://claude.ai/chat/11607433-9bb4-41b1-9a30-69e8c5452bf1  
**Model:** Claude  

## Response:
Você está numa fase de decisões arquiteturais importantes para o `pktparsers`. Vou analisar o que você já tem e dar uma recomendação clara sobre as principais questões em aberto.

* * *

### Análise do estado atual

Seu parse já é bem estruturado: `ParseContext` com ContextVar, `unpack()` como primitiva, dispatch tables por tipo de frame. O que você quer adicionar é uma camada de **abstração semântica** em cima do parse bruto.

* * *

### Recomendações diretas

#### 1\. Geração de FrameSummary

**Recomendação: pós-parse, não inline.**

Não faça os parsers escreverem diretamente em `ParseContext.frame_summary`. Isso acopla a lógica de parse com a lógica de resumo, tornando os parsers mais difíceis de testar e reutilizar. Mantenha os parsers puros — eles retornam dados estruturados, ponto.

Em vez disso, crie uma função separada que analisa o frame parseado e gera o `FrameSummary`:

python

```python
# pktparsers/summary/ieee802/dot11/summary.py

from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Dot11FrameSummary:
    frame_type: str       # "Management", "Control", "Data"
    subtype: str          # "Beacon", "Probe Request", etc
    channel: Optional[int] = None
    ssid: Optional[str] = None
    bssid: Optional[str] = None
    sa: Optional[str] = None
    da: Optional[str] = None
    signal_dbm: Optional[int] = None
    security: dict = field(default_factory=dict)
    eapol: Optional[dict] = None  # {message: 1|2|3|4, flags: [...]}
    
def summarize_dot11(parsed_frame: dict) -> Dot11FrameSummary:
    rt_hdr = parsed_frame.get("rt_hdr", {}).get("parsed", {})
    mac_hdr = parsed_frame.get("mac_hdr", {}).get("parsed", {})
    body = parsed_frame.get("body", {})
    
    fc = mac_hdr.get("fc", {})
    channel = rt_hdr.get("channel")
    
    eapol_summary = None
    llc = body.get("llc", {})
    if isinstance(llc, dict):
        payload = llc.get("payload", {})
        if isinstance(payload, dict) and "parsed" in payload:
            eapol_summary = _summarize_eapol(payload["parsed"])
    
    return Dot11FrameSummary(
        frame_type=fc.get("type_name", ""),
        subtype=fc.get("subtype_name", ""),
        channel=channel.get("channel") if channel else None,
        signal_dbm=rt_hdr.get("dbm_antenna_signal"),
        bssid=_extract_addr(mac_hdr.get("bssid")),
        sa=_extract_addr(mac_hdr.get("sa")),
        da=_extract_addr(mac_hdr.get("da")),
        ssid=_extract_ssid(body),
        eapol=eapol_summary,
    )

def _summarize_eapol(eapol: dict) -> dict:
    ki = eapol.get("key_information", {})
    ack = ki.get("key_ack", False)
    mic = ki.get("key_mic", False)
    inst = ki.get("install", False)
    sec = ki.get("secure", False)
    
    if ack and not mic and not sec:
        msg = 1
    elif not ack and mic and not sec:
        msg = 2
    elif ack and mic and inst:
        msg = 3
    elif not ack and mic and sec:
        msg = 4
    else:
        msg = 0
    
    flags = []
    if msg in (1, 2):
        flags.append("HANDSHAKE_CAPTURABLE")
    if not mic and msg == 1:
        flags.append("NO_MIC")
    
    return {"message": msg, "flags": flags}
```

Isso mantém `describe_eapol` que você já tem em `eapol.py` — mas move para um lugar separado e reutilizável.

* * *

#### 2\. DeviceEntry e TrafficSummary

**Recomendação: layers como dataclasses, não dicionário livre.**

python

```python
# pktparsers/traffic/models.py

from dataclasses import dataclass, field
from typing import Optional, Set
import time

@dataclass
class L2Stats:
    """Estatísticas de camada 2 (IEEE 802.11)"""
    channels_seen: Set[int] = field(default_factory=set)
    ssid: Optional[str] = None
    frames_sent: int = 0
    frames_received: int = 0
    retry_count: int = 0
    probe_requests: int = 0
    probe_responses: int = 0
    beacons: int = 0
    auths: int = 0
    deauths: int = 0
    total_frames: int = 0
    vendor: Optional[str] = None
    
    @property
    def percent_retry(self) -> float:
        if not self.total_frames:
            return 0.0
        return (self.retry_count / self.total_frames) * 100

@dataclass 
class SecurityInfo:
    eapol_messages_seen: Set[int] = field(default_factory=set)  # {1,2} = handshake capturável
    handshake_complete: bool = False
    pmkid_seen: bool = False
    encryption: Optional[str] = None   # "WPA2/RSN", "WPA3", etc
    akm_suites: list = field(default_factory=list)

@dataclass
class DeviceEntry:
    addr: str                          # MAC, IP, ou endereço principal
    role: str = "unknown"              # "ap", "sta", "unknown"
    associated_bssid: Optional[str] = None
    l2: L2Stats = field(default_factory=L2Stats)
    security: SecurityInfo = field(default_factory=SecurityInfo)
    last_seen: float = field(default_factory=time.time)
    first_seen: float = field(default_factory=time.time)
    
    def __hash__(self):
        return hash(self.addr)
    
    def __eq__(self, other):
        return isinstance(other, DeviceEntry) and self.addr == other.addr

@dataclass
class TrafficSummary:
    interface: str
    dlt: str
    start_time: float = field(default_factory=time.time)
    devices: dict = field(default_factory=dict)  # addr -> DeviceEntry
    total_frames: int = 0
    
    def get_or_create(self, addr: str) -> DeviceEntry:
        if addr not in self.devices:
            self.devices[addr] = DeviceEntry(addr=addr)
        return self.devices[addr]
```

* * *

#### 3\. TrafficContext — fluxo recomendado

python

```python
# pktparsers/traffic/context.py

from pktparsers.traffic.models import TrafficSummary, DeviceEntry
from pktparsers.summary.ieee802.dot11.summary import Dot11FrameSummary

class TrafficContext:
    def __init__(self, interface: str, dlt: str):
        self.summary = TrafficSummary(interface=interface, dlt=dlt)
    
    def consume_dot11(self, parsed_frame: dict, frame_summary: Dot11FrameSummary):
        self.summary.total_frames += 1
        
        # Atualiza ou cria entradas para SA e BSSID
        if frame_summary.sa:
            entry = self.summary.get_or_create(frame_summary.sa)
            self._update_from_summary(entry, frame_summary, sent=True)
        
        if frame_summary.bssid and frame_summary.bssid != frame_summary.sa:
            ap_entry = self.summary.get_or_create(frame_summary.bssid)
            ap_entry.role = "ap"
            self._update_from_summary(ap_entry, frame_summary, sent=False)
        
        if frame_summary.eapol:
            self._handle_eapol(frame_summary)
    
    def _update_from_summary(self, entry: DeviceEntry, fs: Dot11FrameSummary, sent: bool):
        entry.last_seen = __import__('time').time()
        if fs.channel:
            entry.l2.channels_seen.add(fs.channel)
        if fs.ssid and not entry.l2.ssid:
            entry.l2.ssid = fs.ssid
        if sent:
            entry.l2.frames_sent += 1
        else:
            entry.l2.frames_received += 1
        entry.l2.total_frames += 1
        
        # tipo de frame
        if fs.subtype == "Beacon":
            entry.l2.beacons += 1
            entry.role = "ap"
        elif fs.subtype == "Probe Request":
            entry.l2.probe_requests += 1
        elif fs.subtype == "Probe Response":
            entry.l2.probe_responses += 1
        elif fs.subtype == "Authentication":
            entry.l2.auths += 1
        elif fs.subtype == "Deauthentication":
            entry.l2.deauths += 1
    
    def _handle_eapol(self, fs: Dot11FrameSummary):
        if not fs.bssid or not fs.sa:
            return
        
        ap = self.summary.get_or_create(fs.bssid)
        sta = self.summary.get_or_create(fs.sa)
        
        msg = fs.eapol.get("message", 0)
        if msg:
            ap.security.eapol_messages_seen.add(msg)
            sta.security.eapol_messages_seen.add(msg)
        
        if {1, 2}.issubset(ap.security.eapol_messages_seen):
            ap.security.handshake_complete = True
```

* * *

#### 4\. Integração com o Dissector

python

```python
# pktparsers/dissector.py

from pktparsers.layers.registry import get_parser
from pktparsers.summary.ieee802.dot11.summary import summarize_dot11
from pktparsers.traffic.context import TrafficContext

def dissect(dlt: str, packet: bytes, traffic_ctx: TrafficContext = None, offset: int = 0) -> dict:
    parser = get_parser(dlt)
    parsed = parser(packet, offset)
    
    if traffic_ctx is not None:
        # gera summary e alimenta o contexto
        if dlt == "DLT_IEEE802_11_RADIO":
            frame_summary = summarize_dot11(parsed)
            traffic_ctx.consume_dot11(parsed, frame_summary)
    
    return parsed
```

No `framesniff`, ficaria assim:

python

```python
traffic_ctx = TrafficContext(ifname, dlt)

def store_callback(parsed_frame):
    dissect(dlt, raw_bytes, traffic_ctx=traffic_ctx)

# ou dentro de _process_frame, após o parse:
frame_summary = summarize_dot11(parsed_frame)
traffic_ctx.consume_dot11(parsed_frame, frame_summary)
```

* * *

#### 5\. Resposta às suas dúvidas

**TrafficSummary global ou por camada?** Global (como `TrafficSummary`), mas com campos de dados **por camada** separados em dataclasses (`L2Stats`, etc). Você não sabe de antemão qual camada cada interface captura, e uma estrutura unificada facilita o TUI.

**DeviceEntry universal ou por camada?** `DeviceEntry` universal com `l2: L2Stats` opcionais. Quando adicionar L3, adicione `l3: Optional[L3Stats] = None`. Não crie tipos separados de `DeviceEntry` por camada — o TUI precisa de um objeto por dispositivo, não um por camada.

**`layers` como dict ou dataclass?** Dataclass. Dict livre não tem autocomplete, é difícil de documentar e errores passam silenciosamente. `entry.l2.beacons` é muito mais seguro que `entry["layers"]["l2"]["beacons"]`.

* * *

#### Estrutura de diretórios sugerida

```
pktparsers/
├── layers/          # parsers existentes (não mudam)
├── summary/
│   ├── ieee802/
│   │   └── dot11/
│   │       └── summary.py   # Dot11FrameSummary + summarize_dot11()
│   └── ethernet/            # futuro
└── traffic/
    ├── models.py            # DeviceEntry, TrafficSummary, L2Stats, etc
    └── context.py           # TrafficContext
```

Essa separação mantém os parsers reutilizáveis e independentes — o `wnlpy` pode importar só `pktparsers.layers`, o `framesniff` usa `pktparsers.traffic` também.

## Response:
pktparsers

