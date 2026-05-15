# Arquitetura de separação de responsabilidades em projeto de rede - Claude

**Source:** Claude  
**Date:** 5/12/2026, 2:34:12 PM  
**Link:** https://claude.ai/chat/cda3cee6-914e-465b-9fe8-27cf6189daf9  
**Model:** Claude  

## Response:
Que projeto denso e bem pensado! Você está no ponto certo de maturidade arquitetural — percebeu que precisa separar responsabilidades antes de escalar. Vou te dar uma visão estruturada.

* * *

### Diagnóstico dos problemas centrais

Você tem **três tensões arquiteturais** que precisam ser resolvidas antes de implementar os summaries:

**1\. Parse ≠ Summary ≠ Traffic** — são três responsabilidades distintas que estão sendo misturadas.

**2\. Stateless vs Stateful** — `parser()` é puro/stateless, mas `TrafficSummary` precisa de estado acumulado entre frames. Misturar isso causa os problemas que você já percebeu.

**3\. DLT-specific vs Protocol-specific** — EAPOL não está ligado a uma DLT, HTTP também não. O registry precisa lidar com protocolos independentes de DLT.

* * *

### Proposta arquitetural

```
Dissector (stateful, mantém TrafficSummary)
    │
    ├── get_parser(dlt) → ParseContext → parsed: dict
    │
    ├── get_summarizer(dlt) → FrameSummary / PacketSummary / etc
    │       └── percorre parsed de forma lógica por protocolo
    │
    └── TrafficContext.update(summary) → DeviceEntry em entries
```

#### Separação de camadas

```
pktparsers/
├── layers/           # parse puro — stateless, retorna dict
│   └── registry.py  # get_parser(dlt|protocol)
├── summaries/        # extração semântica — recebe parsed, retorna dataclass
│   ├── registry.py   # get_summarizer(dlt|protocol)  
│   ├── frame.py      # FrameSummary, EapolSummary, etc
│   ├── packet.py     # PacketSummary
│   └── dot11.py      # summarize_dot11(parsed) → FrameSummary
└── traffic/          # estado acumulado — stateful
    ├── context.py    # TrafficContext, DeviceEntry
    └── dissector.py  # Dissector (orquestra tudo)
```

* * *

### As estruturas

#### Summaries — extraem semântica do parsed

python

```python
# pktparsers/summaries/frame.py
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class EapolSummary:
    message: int           # 1, 2, 3, 4
    has_mic: bool
    has_anonce: bool
    flags: list[str] = field(default_factory=list)

@dataclass
class AuthSummary:
    protocol: str          # "eapol", "eap", "radius"
    eapol: Optional[EapolSummary] = None

@dataclass
class FrameSummary:
    # Identidade
    frame_type: int
    frame_subtype: int
    # L2 dot11
    bssid: Optional[str] = None
    sa: Optional[str] = None
    da: Optional[str] = None
    ta: Optional[str] = None
    ra: Optional[str] = None
    # Rádio
    channel: Optional[int] = None
    signal_dbm: Optional[int] = None
    # Aplicação
    ssid: Optional[str] = None
    auth: Optional[AuthSummary] = None  # genérico, não "eapol" direto
    # Flags de comportamento
    is_retry: bool = False
    is_broadcast: bool = False
```

#### Summarizer — lógica de extração por protocolo

python

```python
# pktparsers/summaries/dot11.py
from pktparsers.common.filter_engine import get_nested
from pktparsers.summaries.frame import FrameSummary, AuthSummary, EapolSummary

def summarize(parsed: dict) -> FrameSummary:
    """
    Percorre parsed de dot11 de forma lógica e constrói FrameSummary.
    Não assume presença de sub-estruturas — verifica antes de acessar.
    """
    fc = get_nested("mac_hdr.fc", parsed) or {}
    frame_type    = fc.get("frame_type")
    frame_subtype = fc.get("frame_subtype")

    summary = FrameSummary(
        frame_type=frame_type,
        frame_subtype=frame_subtype,
        bssid=get_nested("mac_hdr.bssid.value", parsed),
        sa=get_nested("mac_hdr.sa.value", parsed),
        da=get_nested("mac_hdr.da.value", parsed),
        ta=get_nested("mac_hdr.ta.value", parsed),
        ra=get_nested("mac_hdr.ra.value", parsed),
        channel=get_nested("rt_hdr.channel.channel", parsed),
        signal_dbm=get_nested("rt_hdr.dbm_antenna_signal", parsed),
        is_retry=bool(get_nested("mac_hdr.fc.retry", parsed)),
        is_broadcast=_is_broadcast(get_nested("mac_hdr.da.value", parsed)),
    )

    # SSID só existe em management frames específicos
    if frame_type == 0:  # Management
        summary.ssid = get_nested("body.tagged_parameters.ssid.parsed.ssid", parsed)

    # Auth só existe em data frames com LLC/EAPOL
    if frame_type == 2:  # Data
        eapol_parsed = get_nested("body.llc.payload.parsed", parsed)
        if eapol_parsed and _is_eapol(eapol_parsed):
            summary.auth = AuthSummary(
                protocol="eapol",
                eapol=_summarize_eapol(eapol_parsed)
            )

    return summary

def _is_broadcast(mac) -> bool:
    if mac is None:
        return False
    if isinstance(mac, bytes):
        return mac == b'\xff\xff\xff\xff\xff\xff'
    return str(mac).lower() == "ff:ff:ff:ff:ff:ff"

def _is_eapol(payload: dict) -> bool:
    # EAPOL tem campos específicos que indicam sua presença
    return "key_information" in payload or "key_nonce" in payload

def _summarize_eapol(eapol: dict) -> EapolSummary:
    ki = eapol.get("key_information", {})
    if isinstance(ki, dict) and "parsed" in ki:
        ki = ki["parsed"]

    ack  = bool(ki.get("key_ack"))
    mic  = bool(ki.get("key_mic"))
    inst = bool(ki.get("install"))
    sec  = bool(ki.get("secure"))

    if   ack and not mic and not sec:          msg = 1
    elif not ack and mic and not sec:          msg = 2
    elif ack and mic and inst:                 msg = 3
    elif not ack and mic and sec:              msg = 4
    else:                                      msg = 0

    flags = []
    if msg in (1, 2):
        flags.append("HANDSHAKE_CAPTURABLE")

    return EapolSummary(
        message=msg,
        has_mic=mic,
        has_anonce=bool(eapol.get("key_nonce")),
        flags=flags
    )
```

#### Registry de summarizers

python

```python
# pktparsers/summaries/registry.py
from pktparsers.summaries import dot11  # futuramente: arp, ip, tcp, http...

SUMMARY_DISPATCH = {
    "DLT_IEEE802_11_RADIO": dot11.summarize,
    "DLT_IEEE802_11":       dot11.summarize,
    # "DLT_EN10MB":         ethernet.summarize,
    # "DLT_RAW":            ip.summarize,
    # "http":               http.summarize,   # protocol-specific, sem DLT
}

def get_summarizer(dlt_or_protocol: str):
    fn = SUMMARY_DISPATCH.get(dlt_or_protocol)
    if not fn:
        raise ValueError(f"No summarizer for: {dlt_or_protocol}")
    return fn
```

#### TrafficContext — estado acumulado

python

```python
# pktparsers/traffic/context.py
from dataclasses import dataclass, field
from typing import Optional
import time

@dataclass
class DeviceEntry:
    addr: str                          # MAC, IP, ou o endereço principal da camada capturada
    role: str = "unknown"              # "ap", "sta", "unknown"
    ssid: Optional[str] = None
    associated_bssid: Optional[str] = None
    vendor: Optional[str] = None
    channels_seen: set = field(default_factory=set)
    signal_dbm_samples: list = field(default_factory=list)
    frames_sent: int = 0
    frames_received: int = 0
    probe_reqs: int = 0
    probe_resps: int = 0
    auths: int = 0
    deauths: int = 0
    retries: int = 0
    handshakes: dict = field(default_factory=dict)  # {bssid: {msg1, msg2, msg3, msg4}}
    last_seen: float = field(default_factory=time.time)

@dataclass
class TrafficSummary:
    dlt: str
    interface: Optional[str] = None
    start_time: float = field(default_factory=time.time)
    total_frames: int = 0
    entries: dict[str, DeviceEntry] = field(default_factory=dict)  # addr → DeviceEntry

    def get_or_create(self, addr: str) -> DeviceEntry:
        if addr not in self.entries:
            self.entries[addr] = DeviceEntry(addr=addr)
        return self.entries[addr]
```

#### TrafficContext — lógica de atualização por DLT

python

```python
# pktparsers/traffic/dot11.py
from pktparsers.summaries.frame import FrameSummary
from pktparsers.traffic.context import TrafficSummary
import time

# Subtype constants
PROBE_REQUEST  = (0, 4)
PROBE_RESPONSE = (0, 5)
AUTH_FRAME     = (0, 11)
DEAUTH_FRAME   = (0, 12)
BEACON         = (0, 8)

def update_traffic(summary: FrameSummary, traffic: TrafficSummary):
    """
    Atualiza TrafficSummary com base em um FrameSummary dot11.
    Toda lógica de domínio 802.11 fica aqui.
    """
    traffic.total_frames += 1
    now = time.time()

    ft  = summary.frame_type
    fst = summary.frame_subtype

    # --- Dispositivo de origem ---
    if summary.sa:
        src = traffic.get_or_create(summary.sa)
        src.frames_sent += 1
        src.last_seen = now
        if summary.is_retry:
            src.retries += 1
        if summary.channel:
            src.channels_seen.add(summary.channel)
        if summary.signal_dbm is not None:
            src.signal_dbm_samples.append(summary.signal_dbm)

    # --- Dispositivo de destino ---
    if summary.da and not summary.is_broadcast:
        dst = traffic.get_or_create(summary.da)
        dst.frames_received += 1
        dst.last_seen = now

    # --- Lógica específica por frame type/subtype ---
    if (ft, fst) == BEACON or (ft, fst) == PROBE_RESPONSE:
        if summary.bssid:
            ap = traffic.get_or_create(summary.bssid)
            ap.role = "ap"
            if summary.ssid:
                ap.ssid = summary.ssid
            if (ft, fst) == PROBE_RESPONSE and summary.sa:
                src.probe_resps = getattr(src, 'probe_resps', 0) + 1

    elif (ft, fst) == PROBE_REQUEST:
        if summary.sa:
            src.probe_reqs = getattr(src, 'probe_reqs', 0) + 1

    elif (ft, fst) == AUTH_FRAME:
        if summary.sa:
            src.auths = getattr(src, 'auths', 0) + 1

    elif (ft, fst) == DEAUTH_FRAME:
        if summary.sa:
            src.deauths = getattr(src, 'deauths', 0) + 1

    # --- EAPOL / handshake ---
    if summary.auth and summary.auth.protocol == "eapol":
        eapol = summary.auth.eapol
        bssid = summary.bssid or "unknown"
        if summary.sa:
            hs = src.handshakes.setdefault(bssid, set())
            hs.add(eapol.message)
```

#### Dissector — orquestrador stateful

python

```python
# pktparsers/traffic/dissector.py
from pktparsers.layers.registry import get_parser
from pktparsers.summaries.registry import get_summarizer
from pktparsers.traffic.context import TrafficSummary
from pktparsers.traffic import dot11 as dot11_traffic  # futuramente: registry por DLT
from dataclasses import dataclass
from typing import Optional, Any

TRAFFIC_UPDATERS = {
    "DLT_IEEE802_11_RADIO": dot11_traffic.update_traffic,
    "DLT_IEEE802_11":       dot11_traffic.update_traffic,
}

@dataclass
class DissectionResult:
    parsed: dict
    summary: Any               # FrameSummary, PacketSummary, etc
    traffic: TrafficSummary    # referência ao estado global acumulado

class Dissector:
    """
    Stateful. Mantém TrafficSummary entre chamadas.
    Um Dissector por sessão de captura (por interface/arquivo).
    """
    def __init__(self, dlt: str, interface: Optional[str] = None):
        self.dlt = dlt
        self._parser = get_parser(dlt)
        self._summarizer = get_summarizer(dlt)
        self._traffic_updater = TRAFFIC_UPDATERS.get(dlt)
        self.traffic = TrafficSummary(dlt=dlt, interface=interface)

    def dissect(self, packet: bytes, offset: int = 0) -> DissectionResult:
        parsed  = self._parser(packet, offset)
        summary = self._summarizer(parsed)

        if self._traffic_updater:
            self._traffic_updater(summary, self.traffic)

        return DissectionResult(
            parsed=parsed,
            summary=summary,
            traffic=self.traffic
        )
```

* * *

### Como framesniff usaria isso

python

```python
# framesniff/core/app.py
from pktparsers.traffic.dissector import Dissector

def sniff(self, dlt="DLT_IEEE802_11_RADIO", ifname=None, ...):
    dissector = Dissector(dlt=dlt, interface=ifname)

    def _process_frame(frame: bytes, output_file):
        result = dissector.dissect(frame)

        # result.parsed   → dict completo para salvar em JSON
        # result.summary  → FrameSummary para display rápido
        # result.traffic  → TrafficSummary atualizado (referência)

        if store_result:
            output_file.write(json.dumps(result.parsed, ...))

        if display_callback:
            display_callback(result.summary, result.traffic)
```

#### Como Hashcat usaria

python

```python
# Sem precisar navegar no parsed manualmente:
result = dissector.dissect(eapol_frame)

if result.summary.auth and result.summary.auth.eapol:
    eapol = result.summary.auth.eapol
    # eapol.message, eapol.has_mic, etc
```

#### Como wnlpy usaria (sem DLT, acesso direto ao summarizer)

python

```python
# wnlpy não captura frames — recebe blobs do kernel
# Pode chamar os parsers de IE diretamente, sem passar por Dissector
from pktparsers.layers.l2.ieee802.dot11.parsers.ies import tagged_parameters

ies = tagged_parameters(bss_value)
ssid = get_nested("ssid.parsed.ssid", ies)
```

* * *

### Decisões que você precisa tomar agora

**1\. `TrafficSummary` por DLT ou universal?** Recomendo: **universal com `dlt` como campo**. A estrutura `DeviceEntry` e `TrafficSummary` são genéricas; o que varia é o `update_traffic()` por DLT. O registry `TRAFFIC_UPDATERS` já resolve isso.

**2\. `summaries/` dentro de cada DLT ou centralizado?** Recomendo: **centralizado em `pktparsers/summaries/`** com um arquivo por protocolo (`dot11.py`, `ip.py`, `tcp.py`). Mover para dentro de cada DLT cria acoplamento desnecessário e dificulta que um summarizer de TCP seja reutilizado independente de DLT.

**3\. Quando chamar o summarizer?** Não dentro do parser — o parser é stateless e retorna `dict`. O `Dissector` chama parser + summarizer em sequência. Isso mantém a separação limpa.

**4\. `FrameSummary` por DLT ou único?** Um `FrameSummary` base com campos opcionais serve bem. Se dot11 e Ethernet tiverem campos muito divergentes, herança simples resolve sem complicar.

## Response:
pktparsers

