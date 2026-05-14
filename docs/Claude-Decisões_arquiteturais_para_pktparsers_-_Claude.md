# Decisões arquiteturais para pktparsers - Claude

**Source:** Claude  
**Date:** 5/12/2026, 2:28:36 PM  
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

## Prompt:
Antes vou passar toda a estrutura e os principais arquivos e funções relacionadas aos meus projetos que, irão utilizar o módulo pktparsers que estou desenvolvendo. Vou passar as funções estruturas de arquivos e diretórios, para você ter uma maior contexto sobre o problema. pktparsers atualmente: \[gus@voidlinux ~/Documents/pktparsers (development)\]$ find . -path '\*/.git' -prune -o -name '.gitignore' -prune -o -path '\*/\_\_pycache\_\_' -prune -o -path '\*/docs' -prune -o -print . ./pyproject.toml ./pktparsers ./pktparsers/tests ./pktparsers/tests/wiphy\_results.txt ./pktparsers/tests/netlink\_route.py ./pktparsers/tests/mac\_oui\_vendors.py ./pktparsers/tests/socket\_function.py ./pktparsers/tests/struct\_test.py ./pktparsers/tests/interface\_network\_socket\_test.py ./pktparsers/tests/verify\_interface\_mode.py ./pktparsers/tests/getlinks\_results.txt ./pktparsers/tests/nl80211\_scan\_test.py ./pktparsers/tests/iw\_scan\_debugged.txt ./pktparsers/tests/debugging\_mainPy.txt ./pktparsers/tests/test\_pmkid.json ./pktparsers/tests/get\_ifaces\_iproute2.py ./pktparsers/tests/bitmap\_key\_information.py ./pktparsers/tests/slice\_python.py ./pktparsers/tests/frames.json ./pktparsers/tests/random\_mac.py ./pktparsers/tests/set\_interface\_monitor\_iw.py ./pktparsers/tests/channel\_hopping.py ./pktparsers/tests/netlink\_dictionary.txt ./pktparsers/tests/get\_ifaces\_psutil.py ./pktparsers/tests/netlink\_nl80211\_basic\_example.py ./pktparsers/tests/nl80211\_values.cpp ./pktparsers/tests/mac\_converter.py ./pktparsers/\_\_main\_\_.py ./pktparsers/\_\_init\_\_.py ./pktparsers/common ./pktparsers/common/filter\_engine.py ./pktparsers/common/parser.py ./pktparsers/common/builder.py ./pktparsers/common/validation.py ./pktparsers/common/sockets.py ./pktparsers/common/mac-vendors-export.json ./pktparsers/common/\_\_init\_\_.py ./pktparsers/common/constants ./pktparsers/common/constants/parsers.py ./pktparsers/common/constants/hashcat.py ./pktparsers/common/constants/\_\_init\_\_.py ./pktparsers/layers ./pktparsers/layers/l7 ./pktparsers/layers/l7/\_\_init\_\_.py ./pktparsers/layers/l1 ./pktparsers/layers/l1/\_\_init\_\_.py ./pktparsers/layers/l3 ./pktparsers/layers/l3/parsers.py ./pktparsers/layers/l3/\_\_init\_\_.py ./pktparsers/layers/\_\_init\_\_.py ./pktparsers/layers/registry.py ./pktparsers/layers/l4 ./pktparsers/layers/l4/\_\_init\_\_.py ./pktparsers/layers/l2 ./pktparsers/layers/l2/ieee802 ./pktparsers/layers/l2/ieee802/dot11 ./pktparsers/layers/l2/ieee802/dot11/builders ./pktparsers/layers/l2/ieee802/dot11/parsers ./pktparsers/layers/l2/ieee802/dot11/parsers/ies.py ./pktparsers/layers/l2/ieee802/dot11/parsers/radiotap\_header.py ./pktparsers/layers/l2/ieee802/dot11/parsers/common.py ./pktparsers/layers/l2/ieee802/dot11/parsers/mac\_header.py ./pktparsers/layers/l2/ieee802/dot11/parsers/control.py ./pktparsers/layers/l2/ieee802/dot11/parsers/body.py ./pktparsers/layers/l2/ieee802/dot11/parsers/management.py ./pktparsers/layers/l2/ieee802/dot11/parsers/data.py ./pktparsers/layers/l2/ieee802/dot11/build.py ./pktparsers/layers/l2/ieee802/dot11/constants.py ./pktparsers/layers/l2/ieee802/dot11/parse.py ./pktparsers/layers/l2/ieee802/dot11/\_\_init\_\_.py ./pktparsers/layers/l2/ieee802/dot3 ./pktparsers/layers/l2/ieee802/dot3/constants.py ./pktparsers/layers/l2/ieee802/\_\_main\_\_.py ./pktparsers/layers/l2/ieee802/dot1x ./pktparsers/layers/l2/ieee802/dot1x/parsers ./pktparsers/layers/l2/ieee802/dot1x/parsers/radius.py ./pktparsers/layers/l2/ieee802/dot1x/parsers/eapol.py ./pktparsers/layers/l2/ieee802/dot1x/parsers/eap.py ./pktparsers/layers/l2/ieee802/dot1x/constants.py ./pktparsers/layers/l2/ieee802/dot1x/\_\_init\_\_.py ./pktparsers/layers/l2/ieee802/llc ./pktparsers/layers/l2/ieee802/llc/parser.py ./pktparsers/layers/l2/ieee802/llc/constants.py ./pktparsers/layers/l2/ieee802/\_\_init\_\_.py ./pktparsers/layers/l2/constants.py ./pktparsers/layers/l2/bluetooth ./pktparsers/layers/l2/bluetooth/att ./pktparsers/layers/l2/bluetooth/gatt ./pktparsers/layers/l2/bluetooth/hci ./pktparsers/layers/l2/bluetooth/hci/parser.py ./pktparsers/layers/l2/bluetooth/hci/transports ./pktparsers/layers/l2/bluetooth/hci/transports/h4.py ./pktparsers/layers/l2/bluetooth/hci/registry.py ./pktparsers/layers/l2/bluetooth/l2cap ./pktparsers/layers/l2/bluetooth/\_\_init\_\_.py ./README.md ./LICENSE Função get\_nested dentro de pktparsers/pktparsers/common/filter\_engine.py: def get\_nested(path: str, dct: dict, default=None): keys = path.split(".") current = dct i = 0 if isinstance(current, dict) and "parsed" in current: current = current\["parsed"\] while i < len(keys): if not isinstance(current, dict): return default key = keys\[i\] key\_lower = str(key).lower() found = False for dct\_key, dct\_value in current.items(): if str(dct\_key).lower() == key\_lower: current = dct\_value found = True break if not found and \_is\_numeric\_dict(current): result = \_search\_in\_numeric\_dict(current, keys\[i:\]) return result if result is not None else default if not found: return default if isinstance(current, dict) and "parsed" in current: next\_key = keys\[i + 1\] if i + 1 < len(keys) else None if next\_key is None or str(next\_key).lower() not in ("parsed", "value", "\_metadata\_"): current = current\["parsed"\] i += 1 if isinstance(current, bytes): return current.hex() if isinstance(current, dict) and "parsed" in current: if all(k in ('parsed', 'value', '\_metadata\_') for k in current.keys()): return current.get('parsed', default) return current if current is not None else default Função de parse principal relacionada à DLT\_IEEE802\_11\_RADIO: pktparsers/pktparsers/layers/l2/ieee802/dot11/parse.py: from logging import getLogger from core.common.parser import (ParseContext, unpack, run\_dispatch, detect\_fcs) from core.layers.l2.ieee802.dot11.parsers import (radiotap\_header, mac\_header, body) from core.layers.l2.ieee802.dot11.constants import \* logger = getLogger(\_\_name\_\_) def parse(frame: bytes, offset: int = 0) -> dict: logger.debug("Frame parse") try: with ParseContext(frame, offset) as ctx: ctx.set("rt\_hdr", radiotap\_header.parser()) rt\_hdr = ctx.get("rt\_hdr") if rt\_hdr is None or {}: logger.debug("Unexpected radiotap header error") return ctx.result rt\_flags = rt\_hdr.get("parsed", {}).get("flags", {}) bad\_fcs = rt\_flags.get("bad\_fcs") if bad\_fcs: logger.debug("Dropping frame: bad\_fcs indicated by radiotap") return ctx.result ctx.set("fcs", detect\_fcs()) if ctx.offset >= len(ctx.frame): logger.debug("Empty 802.11 frame after radiotap, skipping") return ctx.result ctx.set("mac\_hdr", mac\_header.parser()) ctx.set("body", body.parser()) except Exception as e: logger.debug(f"Frames parser error: {e}") return ctx.result Funções de parsers de dot11: pktparsers/pktparsers/layers/l2/ieee802/dot11/parsers/: common.py: def fixed\_parameters(\*\*kwargs) -> dict: def \_parser(value: tuple, \*\*k) -> dict: ts, interval, cap\_raw = value

cap\_list = \[ "ess\_capabilities", "ibss\_status", "reserved1", "reserved2", "privacy", "short\_preamble", "critical\_update\_flag", "nontransmitted\_bssid\_critical\_update\_flag", "spectrum\_management", "qos", "short\_slot\_time", "automatic\_power\_save\_delivery", "radio\_measurement", "epd", "reserved3", "reserved4", \]

capabilities = bitmap\_value\_for\_dict(cap\_raw, cap\_list)

return { "timestamp": ts, "beacon\_interval": interval, "capabilities\_information": capabilities } result = {} try: result = unpack("<QHH", parser=\_parser) except Exception as e: logger.debug(f"Parser fixed parameters error: {e}") return result def tagged\_parameters(value: bytes = None, \*\*kwargs) -> dict: logger.debug(f"Tagged parameters parser{' (callback mode)' if value is not None else ''}") ies\_container = {} ctx = ParseContext.current()

if value is not None: limit = ctx.offset ctx.offset -= len(value) else: max\_length = kwargs.get('max\_length', 0) limit = (ctx.offset + max\_length) if max\_length else len(ctx.frame) while ctx.offset + MIN\_IE\_LEN <= limit: try: ie\_entry = unpack("<BB", parser=ie\_dispatch, \*\*kwargs)

parsed\_data = ie\_entry.get("parsed", {}) tag\_name = parsed\_data.get("name") or parsed\_data.get("tag\_number")

insert\_item(ies\_container, tag\_name, ie\_entry) except Exception as e: logger.error(f"Error parsing IE at offset {ctx.offset}: {e}") break ctx.offset = limit return ies\_container pktparsers/pktparsers/layers/l2/ieee802/dot11/parsers/: ie.py: def ie\_dispatch(value: tuple, \*\*kwargs) -> dict: def \_fallback(tag\_length: int, \*\*k): return unpack(f"{tag\_length}s") ie\_result = {} tag\_number, tag\_length = value ctx = ParseContext.current() start\_offset = ctx.offset expected\_end = start\_offset + tag\_length try: entry = IE\_DISPATCH.get(tag\_number, {}) ie\_result = { "tag\_number": tag\_number, "tag\_length": tag\_length, "name": entry.get("name"), "description": entry.get("description") } ie\_result\["data"\] = run\_dispatch( IE\_DISPATCH, tag\_number, fallback=\_fallback, tag\_length=tag\_length ) except Exception as e: logger.debug(f"IE parser error for tag {tag\_number} value={value} entry={entry} : {e}") finally: if ctx.offset != expected\_end: logger.debug( f"IE tag {tag\_number} offset drift: expected={expected\_end} got={ctx.offset} " f"(drift={ctx.offset - expected\_end:+d})" ) ctx.offset = min(expected\_end, len(ctx.frame)) return ie\_result registry.py: \[gus@voidlinux ~/Documents/pktparsers/pktparsers (development)\]$ cat layers/registry.py from pktparsers.layers.l2.ieee802.dot11 import parse, parse\_radio from pktparsers.common.constants.parsers import \* DLT\_DISPATCH = { "DLT\_EN10MB": { "value": DLT\_EN10MB, "parser": None }, "DLT\_IEEE802\_11": { "value": DLT\_IEEE802\_11, "parser": dot11.parse }, "DLT\_IEEE802\_11\_RADIO": { "value": DLT\_IEEE802\_11\_RADIO, "parser": dot11.parse\_radio }, "DLT\_BLUETOOTH\_HCI\_H4": { "value": DLT\_BLUETOOTH\_HCI\_H4, "parser": None }, "DLT\_BLUETOOTH\_HCI\_H4\_PHDR": { "value": DLT\_BLUETOOTH\_HCI\_H4\_PHDR, "parser": None }, "DLT\_RAW": { "value": DLT\_RAW, "parser": None }, } def get\_parser(dlt: str | int): config = DLT\_DISPATCH.get(dlt if isinstance(str, dlt) else next((k for k, v in DLT\_DISPATCH.items()) if v.get("value") == dlt)) if not config or not config\["parser"\]: raise ValueError(f"Parser not available or not implemented for: {dlt\_name}") return config\["parser"\] def get\_dlt\_value(dlt\_name: str): config = DLT\_DISPATCH.get(dlt\_name) if not config: raise ValueError(f"Unknown DLT: {dlt\_name}") return config\["value"\] def list\_supported\_dlts(): return \[k for k, v in DLT\_DISPATCH.items() if v\["parser"\] is not None\] framesniff atualmente: /core/app.py: função sniff: def sniff( self, dlt: str = "DLT\_IEEE802\_11\_RADIO", ifname: str = None, store\_filter: str = None, display\_filter: str = None, count: int = None, timeout: float = None, display\_interval: float = 0.0, store\_callback: callable = None, display\_callback: callable = None, stop\_event: threading.Event = None, simple\_output: bool = False, output\_fullpath: str = None, test: bool = False, input\_fullpath: str = None, ): if not test: check\_root() check\_interface\_mode(ifname, "monitor") try: parser = get\_parser(dlt) except ValueError as e: logger.error(e) return output\_fullpath = new\_file\_path(output\_fullpath, "framesniff-capture.json") frame\_processed\_counter = 0 frames\_stored\_counter = 0 frames\_displayed\_counter = 0 last\_display\_time = 0.0 start\_time = time.time() def \_process\_frame(frame: bytes, output\_file) -> bool: nonlocal frame\_processed\_counter, frames\_stored\_counter, frames\_displayed\_counter, last\_display\_time try: parsed\_frame = parser(frame) except Exception as e: logger.debug(f"Parser error: {e}", exc\_info=True) return False frame\_processed\_counter += 1 parsed\_frame\["counter"\] = frame\_processed\_counter parsed\_frame\["raw"\] = frame.hex() store\_result, display\_result = apply\_filters(store\_filter, display\_filter, parsed\_frame) if store\_result: if simple\_output: dump = json.dumps(parsed\_frame, default=bytes\_encoder, separators=(",", ":")) else: dump = json.dumps(parsed\_frame, default=bytes\_encoder, indent=2) output\_file.write(dump + "\\n") if frames\_stored\_counter % 100 == 0: output\_file.flush() frames\_stored\_counter += 1 if store\_callback: store\_callback(parsed\_frame) if display\_result: frames\_displayed\_counter += 1 if display\_callback: display\_callback(display\_result) else: current\_time = time.time() if current\_time - last\_display\_time >= display\_interval: try: log\_out = json.dumps(display\_result, default=bytes\_encoder, ensure\_ascii=False) logger.info(f"\[{frame\_processed\_counter}\] {log\_out}") except Exception: logger.warning(f"\[{frame\_processed\_counter}\] {display\_result}") last\_display\_time = current\_time return True def \_should\_stop() -> bool: if stop\_event and stop\_event.is\_set(): logger.info("Stop event received, finishing...") return True if timeout and (time.time() - start\_time) >= timeout: logger.info(f"Timeout of {timeout}s reached.") return True if count is not None and frames\_stored\_counter >= count: return True return False def \_log\_summary(): elapsed = time.time() - start\_time logger.info( f"Capture finished.\\n" f" Elapsed time : {elapsed:.2f}s\\n" f" Frames processed : {frame\_processed\_counter}\\n" f" Frames stored : {frames\_stored\_counter}\\n" f" Frames displayed : {frames\_displayed\_counter}" ) if test: if not input\_fullpath: raise ValueError("Input file path (input\_fullpath) is required when test=True.") logger.info( f"Starting OFFLINE processing...\\n" f"Input : {input\_fullpath}\\n" f"Store filter : {store\_filter}\\n" f"Display filter: {display\_filter}\\n" f"Output : {output\_fullpath}" ) try: with open(output\_fullpath, "a") as output\_file: for \_cleaned\_hex, frame in iter\_from\_json(input\_fullpath, raw\_packet\_extractor()): if \_should\_stop(): break \_process\_frame(frame, output\_file) except Exception as e: logger.critical(f"Unexpected error in offline sniff: {e}", exc\_info=True) finally: \_log\_summary() return sock = create\_raw\_socket(ifname) try: logger.info( f"Starting capture on {ifname}... (Press Ctrl+C to stop)\\n" f"Store filter : {store\_filter}\\n" f"Display filter: {display\_filter}\\n" f"Output path : {output\_fullpath}\\n" f"Timeout : {timeout} seconds" ) with open(output\_fullpath, "a") as output\_file: while True: if \_should\_stop(): break try: frame, \_ = sock.recvfrom(65535) \_process\_frame(frame, output\_file) except KeyboardInterrupt: logger.info("Capture interrupted by user.") break except Exception as e: logger.error(f"Error processing frame: {e}") continue except Exception as e: logger.critical(f"Unexpected error in sniff: {e}", exc\_info=True) finally: \_log\_summary() sock.close() if stop\_event: stop\_event.set() funções relacionadas à hashcat: @staticmethod def \_generate\_22000(htype: int, ssid: str, input\_fullpath: str, hformat: str = None, output\_fullpath: str = None): def \_build\_eapol\_line(ssid: str, input\_fullpath: str): eapol\_msg1 = None eapol\_msg2 = None

for i, (\_, fbytes) in enumerate(iter\_from\_json(input\_fullpath, raw\_packet\_extractor())): if i == 0: eapol\_msg1 = fbytes elif i == 1: eapol\_msg2 = fbytes break

if not eapol\_msg1 or not eapol\_msg2: raise ValueError("Need at least 2 EAPOL frames")

parser = get\_parser("DLT\_IEEE802\_11\_RADIO")

msg1 = parser(eapol\_msg1) msg2 = parser(eapol\_msg2)

msg2\_mac = get\_nested("mac\_hdr", msg2)

ap\_mac = msg2\_mac\["bssid"\]\["value"\].hex() sta\_mac = (msg2\_mac\["sa"\]\["value"\] or msg2\_mac\["ta"\]\["value"\]).hex()

msg1\_eapol = get\_nested("body.llc.payload", msg1) msg2\_eapol = get\_nested("body.llc.payload", msg2)

logger.warning(f"{msg1\_eapol}\\n{msg2\_eapol}") anonce = get\_nested("key\_nonce", msg1\_eapol) mic = get\_nested("key\_mic", msg2\_eapol) key\_data = get\_nested("key\_data.\_metadata\_.raw", msg2\_eapol) payload\_meta = get\_nested("body.llc.payload.\_metadata\_", msg2) fields = list(msg2\_eapol.keys()) try: mic\_index = fields.index("key\_mic") except ValueError: raise ValueError("'key\_mic' not found in EAPOL")

tokens = payload\_meta\["tokens"\] eapol\_len = calc\_offset\_from\_fmt(tokens, len(tokens)) full\_eapol = bytes.fromhex(payload\_meta\["raw"\] + key\_data)

eapol\_zero\_mic\_bytes = clear\_field(full\_eapol, payload\_meta, mic\_index, EAPOL\_KEY\_MIC\_LENGTH) return f"WPA\*02\*{mic}\*{ap\_mac}\*{sta\_mac}\*{ssid}\*{anonce}\*{eapol\_zero\_mic\_bytes.hex()}\*00" def \_build\_pmkid\_line(ssid: str, input\_fullpath: str): with open(input\_fullpath, "r", encoding="utf-8") as f: data = json.load(f) pmkid = clean\_hex\_string(data.get("pmkid")) ap\_mac = clean\_hex\_string(data.get("ap\_mac")) sta\_mac = clean\_hex\_string(data.get("sta\_mac")) if not all(\[pmkid, ap\_mac, sta\_mac\]): raise ValueError("Missing PMKID data") return f"WPA\*01\*{pmkid}\*{ap\_mac}\*{sta\_mac}\*{ssid}\*\*\*00" HTYPE\_GENERATORS = { HC22000\_PMKID: \_build\_pmkid\_line, HC22000\_EAPOL: \_build\_eapol\_line }

if not input\_fullpath: raise ValueError("Input file must be provided.")

if not ssid: raise ValueError("SSID must be provided.")

ssid = ssid.encode().hex()

try: line = HTYPE\_GENERATORS\[htype\](ssid, input\_fullpath) logger.info(line) if output\_fullpath: with open(new\_file\_path(output\_fullpath, f"hashcat\_{hformat}\_{htype}"), "w") as output\_file: output\_file.write(line) return line except Exception as e: logger.error(f"Exception: {e}") wnlpy atualmente: nl80211/parse.py: def show\_ap\_info(kernel\_response\_scan, NL80211\_FAMILY\_ID): AP\_LIST = \[\] try: kernel\_response = kernel\_response\_parser(kernel\_response\_scan, NL80211\_FAMILY\_ID) for nlmsg\_ap in kernel\_response: genlcmd = nlmsg\_ap\["genlmsg"\]\[0\] #if genlcmd != NL80211\_CMD\_NEW\_SCAN\_RESULTS: #continue for (nla\_len, nla\_type, nla\_data) in nlmsg\_ap\["nlattrs"\]: # attribute from nlmsg\_ap if nla\_type == NL80211\_ATTR\_BSS: AP\_INFO = {} AP\_INFO\['Vendor specific'\] = \[\] for bss\_attr in parser\_nl80211\_bss(nla\_data): bss\_tag, bss\_type, bss\_value = bss\_attr if bss\_type == 1: # NL80211\_BSS\_BSSID bss attribute bssid = mac\_converter(bss\_value) AP\_INFO\['Bssid'\] = bssid, mac\_oui\_vendors\_identify(bssid) if bss\_type == 2: # NL80211\_BSS\_FREQUENCY bss attribute AP\_INFO\['Frequency'\] = struct.unpack("<I", bss\_value)\[0\] if bss\_type == 3: AP\_INFO\['TSF'\] = struct.unpack("<Q", bss\_value)\[0\] # NL80211\_BSS\_TSF if bss\_type == 4: # NL80211\_BSS\_BEACON\_INTERVAL AP\_INFO\['Beacon interval'\] = struct.unpack("<H", bss\_value)\[0\] if bss\_type == 5: # NL80211\_BSS\_CAPABILITY bss attribute capability = struct.unpack("<H", bss\_value)\[0\] # bitmap informations capabilities = { "ESS is AP": bool(capability & 0x0001), "IBSS is ad-hoc": bool(capability & 0x0002), "Data confidentiality required": bool(capability & 0x0005), "Privacy (WEP Enabled)": bool(capability & 0x0010) } AP\_INFO\['Capabilities'\] = capabilities if bss\_type == 6: # NL80211\_BSS\_INFORMATION\_ELEMENTS bss attribute for ie in parser\_IEs(bss\_value): # loop for IEs attributes per eid if isinstance(ie, tuple): if ie\[0\] == 0: # WLAN\_EID\_SSID eid attribute AP\_INFO\['Ssid'\] = ie\[2\].decode('utf-8', errors='ignore') if ie\[2\].decode('utf-8', errors='ignore') != '' else 'Hidden SSID' if ie\[0\] == 1: # WLAN\_EID\_RATES eid attribute AP\_INFO\['Supported rates'\] = calc\_rates(ie\[2\]) if ie\[0\] == 3: # WLAN\_EID\_DS\_PARAMS eid attribute AP\_INFO\['Channel'\] = struct.unpack('<B', ie\[2\])\[0\] if ie\[0\] == 7: # WLAN\_EID\_COUNTRY eid attribute country\_code = ie\[2\]\[:3\].decode('utf-8', errors='ignore').strip() channels\_info = \[\] for info in range(3, len(ie\[2\]), 3): if len(ie\[2\]\[info:info+3\]) == 3: # take a info full first\_channel, num\_channel, max\_power = struct.unpack('<BBb', ie\[2\]\[info:info+3\]) channels\_info.append((first\_channel, num\_channel, max\_power)) AP\_INFO\['Country'\] = country\_code, channels\_info # WLAN \_EID\_QBSS\_LOAD if ie\[0\] == 35: # WLAN\_EID\_TPC\_REPORT eid attribute tx power signal from device AP\_INFO\['TPC report'\] = struct.unpack('bb', ie\[2\])\[0\]

if ie\[0\] == 48: # WLAN\_EID\_RSN eid attribute rsn\_info = {} offset = 0 version, GCS, PCSC = struct.unpack\_from('H4sH', ie\[2\], offset) rsn\_info\['Group cipher suite multicast/broadcast'\] = GCS\_OUI\_identify(GCS) offset += struct.calcsize("HIH") rsn\_info\['Pairwise cipher suites unicast'\] = \[\] for \_ in range(PCSC): cipher\_suite = struct.unpack\_from("4s", ie\[2\], offset - struct.calcsize('H'))\[0\] rsn\_info\['Pairwise cipher suites unicast'\].append(GCS\_OUI\_identify(cipher\_suite)) offset += struct.calcsize("I") offset -= struct.calcsize("H") # because of the for loop the offset is misaligned AKM\_count = struct.unpack\_from("H", ie\[2\], offset)\[0\] offset += struct.calcsize("H") rsn\_info\['AKM list'\] = \[\] for \_ in range(AKM\_count): AKM = struct.unpack\_from("<4s", ie\[2\], offset)\[0\] rsn\_info\['AKM list'\].append(AKM\_OUI\_identify(AKM)) offset += struct.calcsize("<I") capability\_rsn = struct.unpack\_from("<H", ie\[2\], offset)\[0\] rsn\_capabilities = { 'Pre-Auth': bool(capability\_rsn & 1), 'No pairwise': bool(capability\_rsn & 2), 'PTK replay counters': (capability\_rsn & 12) >> 2, 'GTK replay counters': (capability\_rsn & 48) >> 4, 'Management frame protection required MFPR': bool(capability\_rsn & 64), 'Management frame protection capable MFPC': bool(capability\_rsn & 128), 'Joint Multi-Band RSNA': bool(capability\_rsn & 256), 'PeerKey enable': bool(capability\_rsn & 512), 'Extended key ID': bool(capability\_rsn & 0x4000), 'OCVC': bool(capability\_rsn & 0x8000) } rsn\_info\['RSN capabilities'\] = rsn\_capabilities AP\_INFO\['RSN'\] = rsn\_info if ie\[0\] == 195: # WLAN\_EID\_TX\_POWER\_ENVELOPE eid attribute offset = 0 AP\_INFO\['Tx power enveloped'\] = \[\] for \_ in range(ie\[1\]): tx\_power = struct.unpack\_from("b", ie\[2\], offset)\[0\] AP\_INFO\['Tx power enveloped'\].append(tx\_power) offset += struct.calcsize("b") if ie\[0\] == 221: # WLAN\_EID\_VENDOR\_SPECIFIC eid attribute vendor\_format = f"3sB{ie\[1\] - struct.calcsize('3sB')}s" OUI\_vendor, OUI\_type, vendor\_data = struct.unpack(vendor\_format, ie\[2\]) OUI\_vendor\_mac = mac\_converter(OUI\_vendor) AP\_INFO\['Vendor specific'\].append((OUI\_vendor\_mac, mac\_oui\_vendors\_identify(OUI\_vendor\_mac), OUI\_type, vendor\_data)) if bss\_type == 7: # NL80211\_BSS\_SIGNAL\_MBM bss attribute AP\_INFO\['Signal mBm'\] = struct.unpack("<i", bss\_value)\[0\] signals = {} try: signals\["Signal mBm Pr"\] = AP\_INFO.get("Signal mBm") signals\["TPC report Pt"\] = AP\_INFO.get("TPC report") signals\["Tx power enveloped Pt"\] = AP\_INFO.get("Tx power enveloped")\[3\] if AP\_INFO.get("Tx power enveloped") and len(AP\_INFO.get("Tx power enveloped")) > 3 else None signals\["Country Pt"\] = AP\_INFO.get("Country")\[1\]\[0\]\[2\] if AP\_INFO.get("Country") and len(AP\_INFO.get("Country")) == 2 else None signals\["TSF"\] = AP\_INFO.get("TSF") signals\["Beacon interval"\] = AP\_INFO.get("Beacon interval") signals\["Frequency"\] = AP\_INFO.get("Frequency") # NL80211\_BSS\_SIGNAL\_UNSPEC # NL80211\_BSS\_BEACON\_TSF signal\_results = signal\_analyser(signals) AP\_INFO\["Signal analysis"\] = signal\_results except Exception as error: AP\_INFO\["Signal analysis"\] = f"Error: {str(error)}"

AP\_LIST.append(AP\_INFO) return AP\_LIST except Exception as error: print(error)

Atualmente estou começando a desenvolver o pktparsers, o módulo de parsers de frames, pacotes e campos de rede, de diferentes padrões de comunicação diferentes. Ele será utilizado por programas como o framesniff, e por outros módulos como o wnlpy (Wrapper/Wireless Netlink Python) para parsear os blobs retornados por uma mensagem nl80211 de operação de scan. Logo logo vou adaptar o framesniff para utilizar ele. O que básicamente estou fazendo agora, é mover toda a estrutura de parse criada para o framesniff, para "core" de pktparsers. Para assim, torna-lo reutilizavel em outros projetos. Mas estou começando a pensar em como posso implementar algumas funcionalidades que vou utilizar no meu framesniff, essas funcionalidades dependem diretamente da funcionalidade/capacidade de parse que o módulo pktparsers oferece. Percebi que tenho que tomar algumas decisões arquiteturais, pois notei que todo o meu parse é idealmente voltado para a ideia que tive no começo do meu projeto framenisff, mas que estou percebendo que provavelmente irei ter que mudar. A ideia era de que todo o meu parse e o próprio framesniff irá funcionar apenas para a captura e analise do trafégo de rede e partir da camada 2 (Data Link) em diante (teoricamente descriptografando os payloads sub-sequentes). Mas percebi que como agora estou modularizando o sistema de parse, movendo ele para um módulo separado (pktparsers), então meus parsers não devem depender desse padrão de parse, ou seja, do padrão baseado na ideia de receber um frame da menor camada, e ir parseando ele e os seus payloads em diante. Acredito que a melhor solução seja justamente seguir com a ideia do registry, registrar parse de acordo com a DLT (Data Link Type) específica, pois assim, poderei por exemplo, em frames DLT\_IEEE802\_11\_RADIO, obter parsers para interpretar payloads LLC da camada 3, 4, através de uma função como get\_parser passando a DLT\_EN10MB com string ou como valor. Atualmente minha ideia com esse módulo "pktparsers" é: Um programa como framenisff poderá criar uma função de sniff que abre um socket de captura de frames DLT\_IEEE802\_11\_RADIO, e assim pode utilizar pktparsers para parsear cada frame capturado. Mas outros módulos como wnlpy poderão acessar acessar funções de módulos específicos de parse do pktparsers, como as funções de parse ie ou tagged\_parameters. Acho que é necessário revisarmos o principal objetivo com a ideia de implementar: Resumo do frame. Resumo de tráfego. Os principais objetivos são: Poder criar uma estrutura DeviceEntry que conterá vários dados sobre um dispositivo com base nas estruturas de summary coletadas pela função de traffic\_summarize. Facilitar módulos como scan\_monitor.py ou funções utilitárias dentro da classe Hashcat, obterem as informações relevantes das estruturas de summary, para exibir realizar operaçòes com elas, como: exibir na interface TUI no caso de scan\_monitor.py; Ou se for uma função utilitária de Hashcat, que irá obter facilmente os dados eapol do summary do frame, para poder gerar a linha hash para o brute force. Esses Summary(s) resolves o principal problema de funções que consome o resultado do frame ou pacote parseado, essas função ainda precisam navegar de forma lógica e de acordo com o protocolo, por todo o conteúdo parseado e obter cada dado parseado, para interpretar e assim chegar à conclusão de algumas informações. Quero implementar: Traffic Summary que será semelhante à WLAN Traffic no wireshark, mas com diferenças. Estrutura que o wireshark fornece: =============================================================================================================================================== Wireless LAN Statistics - wlp0s20f3: Address Channel SSID Percent Packets Percent Retry Retry Pkts Sent Pkts Received Probe Reqs Probe Resp Auths Deauths Other Comment ----------------------------------------------------------------------------------------------------------------------------------------------- 28:87:2e:9f:f6:85 0 <Broadcast> 0.061805 0.000000 0 0 1 0 0 0 0 0 Unknown 28:87:ba:9f:f6:85 1 404wi-fi indisponível 98.269468 0.125786 2 1360 188 0 42 0 0 0 Unknown 48:22:54:7e:69:48 1 Gisele Matos 0.185414 0.000000 0 3 0 0 0 0 0 0 4a:22:54:4e:69:48 1 <Broadcast> 0.432633 0.000000 0 7 0 0 0 0 0 0 4a:22:54:5e:69:48 1 <Broadcast> 0.309023 0.000000 0 5 0 0 0 0 0 0 80:1f:65:5a:67:95 0 <Broadcast> 0.061805 0.000000 0 0 1 0 0 0 0 0 Unknown ee:81:9c:85:b0:dc 0 <Broadcast> 0.185414 0.000000 0 0 3 0 0 0 0 0 Unknown ee:81:9c:85:b0:df 0 <Broadcast> 0.309023 0.000000 0 0 5 0 0 0 0 0 Unknown ff:ff:ff:ff:ff:ff 1 <Broadcast> 0.185414 0.000000 0 0 0 3 0 0 0 0 ----------------------------------------------------------------------------------------------------------------------------------------------- O que estou desenvolvendo para poder implementar o traffic summary: Como traffic summary irá ser: TrafficSummary terá vários DeviceEntry, que provavelmente estarão dentro de um set: {DeviceEntry}, {DeviceEntry}, {DeviceEntry} ... Pois poderá haver um dispositivo com o mesmo MAC na rede, podendo assim, sobrescrever ou gerar conflito no momento da criação de novos DeviceEntry(s). DeviceEntry: ainda estou em dúvida sobre como irei estruturar ele, pois não sei se crio uma estrutura DeviceEntry universal, que irá estruturar todos os dados relevantes através de qualquer função utilizada em TrafficContext para criar DeviceEntry através das estruturas de Summary que ela está preparada para lidar dentro do pacote parseado. Ou seja, TrafficSummary irá conter uma variável "entries" que geralmente irá conter várias entradas DeviceEntry, visualmente seria: Mas visualmente: Traffic Summary - wlp0s20f3: "ip, mac address, ou qualquer outro endereço principal relacionado ao dispositivo de acordo com a camada/padrão de comunicação principal sendo capturado através da interface, ou seja, mac address se o sniff for a partir da camada L2, ip se o sniff for a partir da camada L3 ou L4": DeviceEntry Tecnicamente vai ser algo como: dissector (classe ou função) recebe (dlt, pacote, offset), dlt pois será necessária para poder obter o parse principal relacionada à DLT do pacote, usei o termo "pacote" pois quero me referir de forma geral às PDUs (pois dissector não sabe se é frame, pacote, segmento ou dado). Então e se a função ou classe dissector retornar constantemente o pacote parseado e a variável traffic\_summary com os dados do summary de trafégo? dessa forma, funções cmo sniff recebem essa duas variável retornadas pela classe ou função dissector, e utiliza elas para escrever no arquivo .json de captura ou outra operação. Mantendo assim a responsabilidade de pktparsers de parsear um pacote e retorna o pacote parseado com seus summaries, e o traffic\_summary. Mas como isso seria feito? pois traffic\_summary precisará ser mantida para ser atualizada constantemente com os novos dados obtidos dos summaries do pacote parseado. Então dissector não poderá ser simplesmente uma função, pois precisará manter o estado de traffic\_summary para atualizar constantemente. Não sei, mas preciso que sugira algo profissional, uma solução para esse problema. Estou pensando em algo como: Estou pensando nessa estrutura TrafficSummary como global/universal, mas talvez seja necessário que ela seja por DLT ou procolo, não sei, tenho que decidir. @dataclass class TrafficSummary: start\_time: float = field(default\_factory=time.time) entries: dict = field(default\_factory=dict) total\_frames: int = 0

def traffic\_summarizer(dlt: str | int, parsed: dict) -> TrafficSummary: result = pktparsers.layers.registry.build\_traffic\_summary(dlt)(parsed) # retorna DeviceEntry ou estrutura parecida, ela será adicionada em "entries". Ou seja, uma função global de traffic summarizer vai obter dados para manter a estrutura geral de TrafficSummary, e a função de traffic\_summary relacionada à DLT ou protocolo específico, irá gerar a entry que será alocada em "entries" em traffic\_summary, essa entry poderá e geralmente será DeviceEntry. A questão é que agora estou pensando em implementar: As estruturas de Summary que acho que vou ter que implementar (através de dataclass): FrameSummary (l2) PacketSummary (l3) SegmentSummary (l4) DataSummary (l5, l6, l7) TrafficSummary DeviceEntry Provavelmente irei criar um diretório "summaries" para agrupar os módulos que irão definir essas estruturas de Summary, mas acho que o correto vai ser criar o diretório "summaries" dentro de cada padrão de comunicação relacionado a uma DLT de captura possível. Ou seja, irei por exemplo, criar o diretório "summaries" ou "summary" dentro de ieee802/dot11/ pois dot11 é o padrão de comunicação relacionado a DLT de captura "DLT\_IEEE802\_11\_RADIO". Pensei no fluxo: Função sniff de framesniff (por exemplo), ou a classe Dissector ou função dissector de pktparsers, cria TrafficContext. TrafficContext obtem e usa uma função que busca e consome os summaries do conteúdo do pacote parseado, para assim, criar entry(s) que serão alocadas no dicionário "entries" de TrafficSummary, essa entry geralmente será DeviceEntry. Cada função de parse principal relacionada a uma DLT de captura específica, ou protocolo específico, irá ter uma função de summary, que irá gerar um summary de acordo com o seu conteúdo parseado. Dúvidas em relação a FrameSummary: A grande é questão é que por exemplo, frames contém payloads, e esse próprios payloads são pacotes que, podem conter segmentos que, podem conter dados. Dessa forma, irei ter uma função única para percorrer todo o frame parseado e gerar esse summaries de acordo com uma analise lógica e conceitual da estrutura do frame ou pacote (a partir de uma DLT inicial passada)? acho que assim seria muito complexo. Então estou pensando mais na forma: chamar a função de geração Summariy dentro de cada parse principal relacionado a uma DLT ou protocolo específico, digo protocolo específico pois quero futuramente dar suporte à DLT\_RAW que utiliza parse de ip diretamente sem cabeçalho ethernet, e pelo o que sei, o parse ou protocolo ip não está relacionado a uma DLT ou padrão de comunicação específico, assim como o parse dados http, http não está relacionado a nenhuma DLT específica. Então cada função principal de parse relacionada a uma DLT ou protocolo específico, terá uma função para gerar seu summary, exemplo: Função de parse da DLT\_IEEE802\_11\_RADIO cria seu FrameSummary, função de parse da DLT\_EN10MB cria seu FrameSummary, função de parse da camada 3 cria PacketSummary, função de parse da camada 4 cria SegmentSummary, e função de parse da camada 5 em diante criar DataSummary para cada payload carregado. Será que pktparsers poderá/irá ter funcionar assim?: Dissector (classe ou função) -> TrafficContext (classe) -> ParseContext (classe) Dessa forma, uma função como sniff do framesniff, irá importar a classe ou função dissector de pktparsers, a função dissector teria a assinatura: (dlt: str, packet: bytes, offset: int = 0) "packet" pois dissector não sabe realmente se é frame, pacote, ou segmento, apenas irá chamar o parse completo de acordo com a DLT passada. As estruturas que andei pensando: Padrão de summary.py para cada DLT de captura: # pktparsers/layers/l2/ieee802/dot11/summary/summary.py from dataclasses import dataclass, field from typing import Optional @dataclass class FrameSummary: frame\_type: int # "Management", "Control", "Data" frame\_subtype: int # "Beacon", "Probe Request", etc channel: int = None ssid: str = None bssid: dict = None sa: dict = None da: dict = None signal\_dbm: Optional\[int\] = None wps: dict = None eapol: dict = None # {message: 1|2|3|4, flags: {}}

def summarize\_dot11(parsed\_frame: dict) -> FrameSummary: rt\_hdr = parsed\_frame.get("rt\_hdr", {}).get("parsed", {}) mac\_hdr = parsed\_frame.get("mac\_hdr", {}).get("parsed", {}) body = parsed\_frame.get("body", {})

fc = mac\_hdr.get("fc", {}) channel = rt\_hdr.get("channel")

eapol\_summary = None llc = body.get("llc", {}) if isinstance(llc, dict): payload = llc.get("payload", {}) if isinstance(payload, dict) and "parsed" in payload: eapol\_summary = \_summarize\_eapol(payload\["parsed"\])

return FrameSummary( frame\_type=fc.get("frame\_type"), subtype=fc.get("frame\_subtype"), channel=channel.get("channel"), signal\_dbm=rt\_hdr.get("dbm\_antenna\_signal"), bssid=mac\_hdr.get("bssid"), sa=mac\_hdr.get("sa"), da=mac\_hdr.get("da"), ssid=body, eapol=eapol\_summary, ) def \_summarize\_eapol(eapol: dict) -> dict: ki = eapol.get("key\_information", {}) ack = ki.get("key\_ack", False) mic = ki.get("key\_mic", False) inst = ki.get("install", False) sec = ki.get("secure", False)

if ack and not mic and not sec: msg = 1 elif not ack and mic and not sec: msg = 2 elif ack and mic and inst: msg = 3 elif not ack and mic and sec: msg = 4 else: msg = 0

flags = \[\] if msg in (1, 2): flags.append("HANDSHAKE\_CAPTURABLE") if not mic and msg == 1: flags.append("NO\_MIC")

return {"message": msg, "flags": flags} Esse é só um exemplo, pois existem alguns problemas: A função summarize\_dot11 assume que existe dicionários como "eapol" sem verificar os dados do conteúdo parseado, que indicam a presença de certos dicionários como "eapol", essa é a questão, a função de "summarize" do parse principal de alguma DLT como: DLT\_IEEE802\_11\_RADIO, deve ser responsável por percorrer o conteúdo do frame parseado de forma lógica de acordo com o protocolo, e buscar dicionários como "eapol" de acordo com os dados do resultado do frame parseado, como frame\_type e frame\_subtype. Outro problema é a própria variável eapol definida na estrutura de Summary de frames dot11, acho que seria melhor um nome mais geral, pois se for assim, irei ter definir as variáveis: eap e radius, indicando que armazena o resumo da parte de autênticação desse frames. Essas funções não estou utilizando a função auxiliar "get\_nested". Provavelmente a melhor forma será ter uma função como traffic\_summarize disponível para cada DLT de captura, ela irá receber a dlt principal do pacote (pacote em termo geral) parseado, essa DLT será usada para obter a função responsável por analisar todo o pacote (no termo geral) parseado, e percorrer profundamente ele em busca dos dicionários de summary gerados por outros parsers principais (principais baseando-se no critério: DLT de captura e procolo específico (como http)), para assim, centralizar temporariamente eles de forma lógica e correta, para facilitar o acesso a eles, e a obtenção de dados necessários para a criação de estruturas como DeviceEntry, que irão ser populadas em "entries" de TrafficSummary. Talvez TrafficSummary precise ser apenas uma estrutura que agrupe varias entry(s) diretamente, sem a necessidade de ter uma variável "entries" para armazenar as entry(s). forma 1: Percorrer todo frame parseado de forma lógica, proucurando estruturas de Summary, obter elas, centralizar temporariamente todas as estruturas de Summary em um único dicionário de uma forma lógica e conceitualmente correta. E começar a obter os dados relevantes para criar ou atualizar as entry(s) de TrafficSummary. Facilitando assim, a função de traffic\_summarize ou create entry da DLT específica, obter as estruturas de Summary do pacote parseado, centralizar elas, e então extrair os dados relevantes e necessários para criar ou atualizar as entry(s) em TrafficSummary. Provavelmente ficando em alguma dessas formas: forma 1: summaries = { "frame": { "DLT\_IEEE802\_11\_RADIO": FrameSummary, "DLT\_EN10MB": FrameSummary, }, "packet": { "arp": PacketSummary, "ip": PacketSummary, }, "segment": { "tcp": SegmentSummary, "udp": SegmentSummary }, "data": { "http": DataSummary, } } Observação: no caso da parte de "segment", eu pensei sobre os termos técnicos específicos como "datagram" ou "message" mas não sei como poderia utilizar eles, pois eles não parecem ser realmente necessários nesse caso. DeviceEntry: from dataclasses import dataclass, field from collections import defaultdict @dataclass class DeviceEntry: addr: str layers: dict = {"l2": {"channel": , "ssid": , "percent\_frames": , "percent\_retry": , "retry": , "frames\_sent" Pkts Received Probe Reqs Probe Resp Auths Deauths Other Comment, "channels\_seen": = field(default\_factory=set), "vendor": None, role: str = "unknown" # "ap", "sta", "unknown" ssid: str | None = None # se for AP associated\_bssid: str | None = None # se for STA relationships: dict\[str, dict\] = {frames} security: dict = None last\_seen: float = 0.0 sessions: list = field(default\_factory=list)

Em "layers: dict = {"l2": {}}" "l2" não irá ser um dicionário, irá ser um dataclass de FrameSummary da DLT\_IEEE802\_11\_RADIO por exemplo. Acho interessante essas estruturas: class Dissector: def \_\_init\_\_(self): self.traffic = TrafficContext() def dissect(self, dlt, packet): parser = get\_parser(dlt) parse\_ctx = ParseContext(packet) summary\_ctx = SummaryContext() parsed = parser( packet, parse\_ctx=parse\_ctx, summary\_ctx=summary\_ctx ) self.\_update\_traffic(summary\_ctx) return DissectionResult( parsed=parsed, summaries=summary\_ctx, traffic=self.traffic )

## Response:
Vou analisar tudo que você passou e dar uma resposta arquitetural direta e completa.

### Análise do problema central

Você tem três problemas distintos que precisam de soluções separadas:

1.  **Parse** — já funciona bem, não mexa
2.  **Summary** — resumo semântico de um único pacote parseado
3.  **Traffic** — estado acumulado ao longo do tempo (múltiplos pacotes)

O erro conceitual que você está evitando corretamente: misturar esses três em um único fluxo. A solução do `Dissector` que você mencionou no final está na direção certa.

* * *

### Decisões arquiteturais — respostas diretas

**TrafficSummary global ou por DLT?** Global. A DLT determina *como extrair* os dados, mas `TrafficSummary` é sempre a mesma estrutura. Um dispositivo é um dispositivo independente da camada.

**FrameSummary por DLT ou por protocolo?** Por DLT de captura para o nível L2, por protocolo para L3+. Você já pensou certo: `dot11` tem seu `FrameSummary`, `en10mb` tem o seu, `ip` tem `PacketSummary` independente de qual DLT o encapsulou.

**`layers` em `DeviceEntry` — dict ou dataclass?** Dataclass, com campos opcionais. Dict livre não tem garantia de estrutura.

**`summaries` como dicionário centralizado?** Sim, mas não como você desenhou. Veja abaixo.

* * *

### Arquitetura proposta

#### Estrutura de diretórios

```
pktparsers/
├── layers/                          # parsers puros — não mudam
│   ├── registry.py
│   ├── l2/
│   │   └── ieee802/
│   │       ├── dot11/
│   │       │   ├── parse.py
│   │       │   ├── parsers/
│   │       │   └── summary.py       # FrameSummary + summarize_dot11()
│   │       └── dot3/
│   │           └── summary.py       # FrameSummary + summarize_en10mb()
│   ├── l3/
│   │   ├── parsers.py
│   │   └── summary.py               # PacketSummary + summarize_ip(), summarize_arp()
│   └── l4/
│       └── summary.py               # SegmentSummary
├── traffic/
│   ├── __init__.py
│   ├── models.py                    # DeviceEntry, TrafficSummary, L2Stats, etc
│   ├── context.py                   # TrafficContext
│   └── registry.py                  # mapeia DLT -> função de update de traffic
├── dissector.py                     # Dissector class + DissectionResult
└── common/
    ├── parser.py
    ├── filter_engine.py
    └── ...
```

* * *

#### 1\. Estruturas de Summary — `layers/l2/ieee802/dot11/summary.py`

python

```python
from dataclasses import dataclass, field
from typing import Optional
from pktparsers.common.filter_engine import get_nested

@dataclass
class EapolSummary:
    message: int           # 1, 2, 3, 4 ou 0 (desconhecido)
    security_protocol: str # "WPA2/RSN", "WPA3", "WEP", "Open"
    pmf_required: bool = False
    pmf_capable: bool = False
    key_nonce: Optional[str] = None
    key_mic: Optional[str] = None
    encryption: Optional[str] = None      # 
    akm_suites: list = field(default_factory=list)
    group_cipher: Optional[str] = None
    encrypted_key_data: bool = False

@dataclass
class WpsSummary:
    version: Optional[str] = None
    state: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    model_number: Optional[str] = None
    device_name: Optional[str] = None
    config_methods: Optional[str] = None
    uuid: Optional[str] = None

@dataclass
class SecuritySummary:
    wps: Optional[WpsSummary] = None

@dataclass 
class FrameSummary:
    """Summary semântico de um frame IEEE 802.11 com radiotap."""
    # obrigatórios — sempre presentes se o parse funcionou
    frame_type: int
    frame_subtype: int
    frame_type_name: str
    frame_subtype_name: str

    # endereços — podem ser None dependendo do tipo de frame
    bssid: Optional[str] = None
    sa: Optional[str] = None
    da: Optional[str] = None
    ra: Optional[str] = None
    ta: Optional[str] = None

    # radiotap
    channel: Optional[int] = None
    channel_freq: Optional[int] = None
    signal_dbm: Optional[int] = None

    # conteúdo semântico
    ssid: Optional[str] = None
    security: Optional[SecuritySummary] = None
    eapol: Optional[EapolSummary] = None

    # flags rápidos para filtragem sem navegar na estrutura
    is_beacon: bool = False
    is_probe_req: bool = False
    is_probe_resp: bool = False
    is_auth: bool = False
    is_deauth: bool = False
    is_assoc: bool = False
    is_data: bool = False
    is_management: bool = False
    is_control: bool = False
    has_eapol: bool = False
    has_wps: bool = False
    has_rsn: bool = False


def summarize_dot11(parsed: dict) -> Optional[FrameSummary]:
    """
    Gera um FrameSummary a partir do resultado de parse da DLT_IEEE802_11_RADIO.
    Navega o parsed de forma lógica de acordo com o protocolo.
    """
    mac_hdr_parsed = get_nested("mac_hdr.parsed", parsed)
    if not mac_hdr_parsed:
        return None

    fc = mac_hdr_parsed.get("fc", {})
    frame_type = fc.get("type")
    frame_subtype = fc.get("subtype")

    if frame_type is None:
        return None

    rt_hdr_parsed = get_nested("rt_hdr.parsed", parsed) or {}
    channel_info = rt_hdr_parsed.get("channel") or {}

    summary = FrameSummary(
        frame_type=frame_type,
        frame_subtype=frame_subtype,
        frame_type_name=fc.get("type_name", ""),
        frame_subtype_name=fc.get("subtype_name", ""),
        bssid=_extract_addr(mac_hdr_parsed.get("bssid")),
        sa=_extract_addr(mac_hdr_parsed.get("sa")),
        da=_extract_addr(mac_hdr_parsed.get("da")),
        ra=_extract_addr(mac_hdr_parsed.get("ra")),
        ta=_extract_addr(mac_hdr_parsed.get("ta")),
        channel=channel_info.get("channel"),
        channel_freq=channel_info.get("channel_freq"),
        signal_dbm=rt_hdr_parsed.get("dbm_antenna_signal"),
        is_management=(frame_type == 0),
        is_control=(frame_type == 1),
        is_data=(frame_type == 2),
    )

    # flags de subtype — só faz sentido se management
    if frame_type == 0:
        summary.is_beacon = (frame_subtype == 8)
        summary.is_probe_req = (frame_subtype == 4)
        summary.is_probe_resp = (frame_subtype == 5)
        summary.is_auth = (frame_subtype == 11)
        summary.is_deauth = (frame_subtype == 12)
        summary.is_assoc = (frame_subtype in (0, 2))

        # beacon e probe_response têm tagged parameters
        if summary.is_beacon or summary.is_probe_resp:
            _extract_mgmt_content(summary, parsed)

    # data frames podem ter LLC/EAPOL
    elif frame_type == 2:
        _extract_data_content(summary, parsed)

    return summary


def _extract_addr(addr_dict) -> Optional[str]:
    if not addr_dict:
        return None
    if isinstance(addr_dict, dict):
        parsed = addr_dict.get("parsed")
        if isinstance(parsed, dict):
            return parsed.get("addr")
        value = addr_dict.get("value")
        if isinstance(value, bytes):
            return value.hex(":")
    return None


def _extract_mgmt_content(summary: FrameSummary, parsed: dict):
    """Extrai SSID, RSN, WPS de frames management."""
    # SSID — tag 0 dentro de body.fp.tp ou body.tp
    ssid_data = (
        get_nested("body.parsed.tp.ssid.parsed.data", parsed)
        or get_nested("body.parsed.fp.tp.ssid.parsed.data", parsed)  
    )
    if ssid_data:
        summary.ssid = ssid_data if isinstance(ssid_data, str) else None

    # RSN — tag 48
    rsn = (
        get_nested("body.parsed.tp.rsn_information.parsed", parsed)
        or get_nested("body.parsed.fp.tp.rsn_information.parsed", parsed)
    )
    if rsn:
        summary.has_rsn = True
        summary.security = _extract_security(rsn)

    # WPS — vendor specific com OUI Microsoft tipo 4
    _extract_wps(summary, parsed)


def _extract_data_content(summary: FrameSummary, parsed: dict):
    """Extrai EAPOL de frames data."""
    llc_name = get_nested("body.parsed.llc.parsed.name", parsed)
    if llc_name != "eapol":
        return

    eapol_parsed = get_nested("body.parsed.llc.parsed.payload.parsed", parsed)
    if not eapol_parsed:
        return

    summary.has_eapol = True
    summary.eapol = _extract_eapol(eapol_parsed)


def _extract_eapol(eapol: dict) -> EapolSummary:
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

    key_nonce = eapol.get("key_nonce")
    if isinstance(key_nonce, bytes):
        key_nonce = key_nonce.hex()

    key_mic = eapol.get("key_mic")
    if isinstance(key_mic, bytes):
        key_mic = key_mic.hex()

    return EapolSummary(
        message=msg,
        handshake_capturable=(msg in (1, 2)),
        key_nonce=key_nonce,
        key_mic=key_mic,
        encrypted_key_data=ki.get("encrypted_key_data", False),
    )


def _extract_security(rsn: dict) -> SecuritySummary:
    akm_list = []
    akm_suites = rsn.get("akm_suites", {})
    if isinstance(akm_suites, dict):
        for _, suite in akm_suites.items():
            if isinstance(suite, dict):
                parsed = suite.get("parsed", {})
                akm_type = parsed.get("akm_type")
                if akm_type is not None:
                    akm_list.append(akm_type)

    caps = rsn.get("capabilities", {}).get("parsed", {})

    group = rsn.get("group_cipher", {}).get("parsed", {})
    group_cipher = None
    if group:
        group_cipher = f"{group.get('oui', '')}-{group.get('cipher_type', '')}"

    # determina nome da criptografia pelos AKM suites
    # 8 = SAE (WPA3), 2 = PSK (WPA2), 1 = EAP
    encryption = "WPA2/RSN"
    if 8 in akm_list or 9 in akm_list:
        encryption = "WPA3"
    elif not akm_list:
        encryption = "Unknown"

    return SecuritySummary(
        encryption=encryption,
        akm_suites=akm_list,
        group_cipher=group_cipher,
        pmf_required=caps.get("mgmt_frame_protection_required", False),
        pmf_capable=caps.get("mgmt_frame_protection_capable", False),
    )


def _extract_wps(summary: FrameSummary, parsed: dict):
    """Procura WPS em vendor_specific tags."""
    # vendor_specific pode aparecer múltiplas vezes — insert_item cria dicts numéricos
    vs_root = (
        get_nested("body.parsed.tp.vendor_specific", parsed)
        or get_nested("body.parsed.fp.tp.vendor_specific", parsed)
    )
    if not vs_root:
        return

    # pode ser uma entrada única ou um dict numérico de entradas
    candidates = []
    if isinstance(vs_root, dict):
        if all(str(k).isdigit() for k in vs_root):
            candidates = list(vs_root.values())
        else:
            candidates = [vs_root]

    for entry in candidates:
        parsed_vs = entry.get("parsed", {})
        oui = parsed_vs.get("oui", "")
        vendor_type = parsed_vs.get("vendor_type")

        # Microsoft OUI + tipo 4 = WPS
        if oui == "00:50:f2" and vendor_type == 4:
            summary.has_wps = True
            wps_data = parsed_vs.get("data", {}).get("parsed", {})
            if wps_data:
                summary.security = summary.security or SecuritySummary()
                summary.security.wps = _extract_wps_attrs(wps_data)
            break


def _extract_wps_attrs(wps_data: dict) -> WpsSummary:
    wps = WpsSummary()
    for _, attr_entry in wps_data.items():
        if not isinstance(attr_entry, dict):
            continue
        fields = attr_entry.get("parsed", {}).get("fields", {})
        wps.version = fields.get("version") or wps.version
        wps.state = fields.get("wps_state") or wps.state
        wps.manufacturer = fields.get("manufacturer") or wps.manufacturer
        wps.model = fields.get("model") or wps.model
        wps.model_number = fields.get("model_number") or wps.model_number
        wps.device_name = fields.get("device_name") or wps.device_name
        wps.config_methods = fields.get("config_methods") or wps.config_methods
        wps.uuid = fields.get("uuid") or wps.uuid
    return wps
```

* * *

#### 2\. Modelos de Traffic — `traffic/models.py`

python

```python
from dataclasses import dataclass, field
from typing import Optional, Set
import time

@dataclass
class L2Dot11Stats:
    """Estatísticas IEEE 802.11 por dispositivo."""
    frames_sent: int = 0
    frames_received: int = 0
    frames_total: int = 0
    retry_count: int = 0
    beacons: int = 0
    probe_requests: int = 0
    probe_responses: int = 0
    auths: int = 0
    deauths: int = 0
    assocs: int = 0
    other: int = 0
    channels_seen: Set[int] = field(default_factory=set)
    ssid: Optional[str] = None
    vendor: Optional[str] = None

    @property
    def percent_retry(self) -> float:
        if not self.frames_total:
            return 0.0
        return (self.retry_count / self.frames_total) * 100

@dataclass
class SecurityState:
    """Estado de segurança observado para um dispositivo."""
    encryption: Optional[str] = None
    akm_suites: list = field(default_factory=list)
    pmf_required: bool = False
    pmf_capable: bool = False
    wps_enabled: bool = False
    wps_info: Optional[dict] = None
    # EAPOL handshake tracking
    eapol_messages_seen: Set[int] = field(default_factory=set)
    handshake_capturable: bool = False
    pmkid_seen: bool = False
    last_anonce: Optional[str] = None
    last_mic: Optional[str] = None

@dataclass
class DeviceEntry:
    addr: str                              # endereço primário (MAC para L2, IP para L3)
    role: str = "unknown"                  # "ap", "sta", "unknown"
    associated_bssid: Optional[str] = None
    ssid: Optional[str] = None             # se for AP
    l2: Optional[L2Dot11Stats] = None
    security: SecurityState = field(default_factory=SecurityState)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def __hash__(self):
        return hash(self.addr)

    def __eq__(self, other):
        return isinstance(other, DeviceEntry) and self.addr == other.addr

    def touch(self):
        self.last_seen = time.time()

@dataclass
class TrafficSummary:
    """Resumo de tráfego acumulado para uma sessão de captura."""
    interface: str
    dlt: str
    start_time: float = field(default_factory=time.time)
    total_frames: int = 0
    # addr -> DeviceEntry
    entries: dict = field(default_factory=dict)

    def get_or_create(self, addr: str) -> DeviceEntry:
        if addr not in self.entries:
            self.entries[addr] = DeviceEntry(addr=addr)
        return self.entries[addr]

    def get_ap_list(self) -> list:
        return [e for e in self.entries.values() if e.role == "ap"]

    def get_sta_list(self) -> list:
        return [e for e in self.entries.values() if e.role == "sta"]

    def get_capturable_handshakes(self) -> list:
        """Retorna dispositivos com handshake EAPOL capturável."""
        return [
            e for e in self.entries.values()
            if e.security.handshake_capturable
        ]
```

* * *

#### 3\. TrafficContext — `traffic/context.py`

python

```python
from typing import Optional
from pktparsers.traffic.models import TrafficSummary, DeviceEntry, L2Dot11Stats
from pktparsers.layers.l2.ieee802.dot11.summary import FrameSummary

class TrafficContext:
    """
    Mantém o estado do TrafficSummary entre chamadas.
    Recebe FrameSummary(s) e atualiza as entradas de dispositivos.
    """
    def __init__(self, interface: str, dlt: str):
        self.summary = TrafficSummary(interface=interface, dlt=dlt)

    def update(self, frame_summary: FrameSummary):
        """Ponto de entrada principal. Recebe qualquer FrameSummary e roteia."""
        self.summary.total_frames += 1
        self._update_dot11(frame_summary)

    def _update_dot11(self, fs: FrameSummary):
        # determina os endereços relevantes para criar/atualizar entradas
        addrs_to_update = set()
        if fs.sa:
            addrs_to_update.add(fs.sa)
        if fs.bssid and fs.bssid != fs.sa:
            addrs_to_update.add(fs.bssid)

        for addr in addrs_to_update:
            entry = self.summary.get_or_create(addr)
            entry.touch()

            # inicializa L2Dot11Stats se necessário
            if entry.l2 is None:
                entry.l2 = L2Dot11Stats()

            is_sender = (addr == fs.sa)
            self._update_l2_stats(entry.l2, fs, is_sender)
            self._update_role(entry, fs, addr)
            self._update_security(entry, fs)

    def _update_l2_stats(self, stats: L2Dot11Stats, fs: FrameSummary, is_sender: bool):
        stats.frames_total += 1

        if is_sender:
            stats.frames_sent += 1
        else:
            stats.frames_received += 1

        if fs.channel:
            stats.channel_seen = fs.channel
            stats.channels_seen.add(fs.channel)

        if fs.ssid and not stats.ssid:
            stats.ssid = fs.ssid

        # contadores por subtipo
        if fs.is_beacon:
            stats.beacons += 1
        elif fs.is_probe_req:
            stats.probe_requests += 1
        elif fs.is_probe_resp:
            stats.probe_responses += 1
        elif fs.is_auth:
            stats.auths += 1
        elif fs.is_deauth:
            stats.deauths += 1
        elif fs.is_assoc:
            stats.assocs += 1
        elif fs.is_management or fs.is_control:
            stats.other += 1

    def _update_role(self, entry: DeviceEntry, fs: FrameSummary, addr: str):
        if fs.is_beacon and addr == fs.bssid:
            entry.role = "ap"
            if fs.ssid:
                entry.ssid = fs.ssid
        elif fs.is_probe_req and addr == fs.sa:
            if entry.role == "unknown":
                entry.role = "sta"
        elif fs.bssid and addr == fs.sa and addr != fs.bssid:
            if entry.role == "unknown":
                entry.role = "sta"
            entry.associated_bssid = fs.bssid

    def _update_security(self, entry: DeviceEntry, fs: FrameSummary):
        # RSN/WPA info vem de beacons e probe responses
        if fs.security and (fs.is_beacon or fs.is_probe_resp):
            sec = fs.security
            entry.security.encryption = sec.encryption
            entry.security.akm_suites = sec.akm_suites
            entry.security.pmf_required = sec.pmf_required
            entry.security.pmf_capable = sec.pmf_capable
            if sec.wps:
                entry.security.wps_enabled = True
                entry.security.wps_info = {
                    "version": sec.wps.version,
                    "state": sec.wps.state,
                    "manufacturer": sec.wps.manufacturer,
                    "model": sec.wps.model,
                    "config_methods": sec.wps.config_methods,
                    "uuid": sec.wps.uuid,
                }

        # EAPOL tracking
        if fs.has_eapol and fs.eapol:
            eapol = fs.eapol
            msg = eapol.message
            if msg:
                entry.security.eapol_messages_seen.add(msg)

            if msg == 1 and eapol.key_nonce:
                entry.security.last_anonce = eapol.key_nonce
            if msg == 2 and eapol.key_mic:
                entry.security.last_mic = eapol.key_mic

            if eapol.handshake_capturable:
                entry.security.handshake_capturable = True
```

* * *

#### 4\. O Dissector — `dissector.py`

Aqui está a resposta para o problema de manter estado de `traffic_summary`:

python

```python
from dataclasses import dataclass
from typing import Optional, Any
from pktparsers.layers.registry import get_parser
from pktparsers.traffic.models import TrafficSummary
from pktparsers.traffic.context import TrafficContext

# registry de funções de summary por DLT
_SUMMARY_REGISTRY = {}

def register_summarizer(dlt: str):
    """Decorator para registrar funções de summary por DLT."""
    def decorator(fn):
        _SUMMARY_REGISTRY[dlt] = fn
        return fn
    return decorator

@dataclass
class DissectionResult:
    parsed: dict
    frame_summary: Any          # FrameSummary, PacketSummary, etc — depende da DLT
    traffic: TrafficSummary     # referência ao estado acumulado

class Dissector:
    """
    Mantém estado entre chamadas (TrafficContext).
    Responsável por: parse -> summary -> atualização de traffic.
    """
    def __init__(self, interface: str, dlt: str):
        self.dlt = dlt
        self.traffic_ctx = TrafficContext(interface=interface, dlt=dlt)
        self._parser = get_parser(dlt)
        self._summarizer = _SUMMARY_REGISTRY.get(dlt)

    def dissect(self, packet: bytes, offset: int = 0) -> DissectionResult:
        # 1. parse puro
        parsed = self._parser(packet, offset)

        # 2. gera summary semântico (se houver summarizer registrado)
        frame_summary = None
        if self._summarizer:
            frame_summary = self._summarizer(parsed)

        # 3. atualiza traffic state
        if frame_summary is not None:
            self.traffic_ctx.update(frame_summary)

        return DissectionResult(
            parsed=parsed,
            frame_summary=frame_summary,
            traffic=self.traffic_ctx.summary,
        )

    @property
    def traffic(self) -> TrafficSummary:
        return self.traffic_ctx.summary


# registra summarizers conhecidos
from pktparsers.layers.l2.ieee802.dot11.summary import summarize_dot11
register_summarizer("DLT_IEEE802_11_RADIO")(summarize_dot11)
```

* * *

#### 5\. Como fica o framesniff

A mudança em `sniff` é mínima — você substitui `parser(frame)` por `dissector.dissect(frame)`:

python

```python
from pktparsers.dissector import Dissector

def sniff(self, dlt, ifname, ...):
    dissector = Dissector(interface=ifname, dlt=dlt)

    def _process_frame(frame: bytes, output_file):
        result = dissector.dissect(frame)

        parsed_frame = result.parsed
        frame_summary = result.frame_summary  # disponível para display_callback
        traffic = result.traffic              # estado acumulado

        # filtragem e escrita — igual ao que você já tem
        store_result, display_result = apply_filters(
            store_filter, display_filter, parsed_frame
        )
        if store_result:
            output_file.write(json.dumps(parsed_frame, default=bytes_encoder) + "\n")
            if store_callback:
                store_callback(parsed_frame, frame_summary)  # summary disponível

        if display_callback:
            display_callback(display_result, frame_summary, traffic)
```

* * *

#### 6\. Como fica o Hashcat

O `generate-hashcat` não precisa de `TrafficContext`. Ele usa o `parsed` diretamente via `get_nested`, o que já funciona. Mas se quiser simplificar com o summary:

python

```python
def _build_eapol_line(ssid, input_fullpath):
    frames = []
    for _, fbytes in iter_from_json(input_fullpath, raw_packet_extractor()):
        dissector = Dissector("offline", "DLT_IEEE802_11_RADIO")
        result = dissector.dissect(fbytes)
        frames.append(result)
        if len(frames) == 2:
            break

    if len(frames) < 2:
        raise ValueError("Need at least 2 EAPOL frames")

    msg1_summary = frames[0].frame_summary
    msg2_summary = frames[1].frame_summary

    # validação semântica agora é trivial
    if not msg1_summary or not msg1_summary.has_eapol:
        raise ValueError("Frame 1 is not EAPOL")
    if msg1_summary.eapol.message != 1:
        raise ValueError("Frame 1 is not EAPOL message 1")

    # extração dos campos brutos ainda via get_nested
    # (o summary não precisa carregar tudo, só o que é semântico)
    msg1_parsed = frames[0].parsed
    msg2_parsed = frames[1].parsed
    # ... resto igual ao que você já tem
```

* * *

#### 7\. Como fica o wnlpy

O `wnlpy` não usa `Dissector` — ele usa parsers específicos diretamente:

python

```python
# wnlpy usa tagged_parameters e ie_dispatch do pktparsers
from pktparsers.layers.l2.ieee802.dot11.parsers.common import tagged_parameters
from pktparsers.layers.l2.ieee802.dot11.summary import summarize_dot11

# parse dos IEs do blob nl80211
ies = tagged_parameters(blob_from_nl80211)

# se quiser summary dos IEs parseados, monta um parsed fake e chama summarize
# ou cria uma função específica para o contexto nl80211
```

* * *

### Respondendo suas dúvidas finais

**A função de summarize deve percorrer o frame parseado de forma lógica?** Sim, e é exatamente o que `summarize_dot11` faz — ela verifica `frame_type` antes de tentar extrair EAPOL (que só existe em data frames) ou SSID (que só existe em management frames). Não assume nada.

**Nomes genéricos vs. específicos (`eapol` vs. `auth`)?** Mantenha `eapol: Optional[EapolSummary]` no `FrameSummary`. EAPOL é o protocolo, não "autenticação genérica". Se quiser adicionar EAP puro no futuro, adicione `eap: Optional[EapSummary]`. Nomes específicos são mais claros.

**`TrafficSummary` precisa de variável `entries`?** Sim, precisa. É um dict `addr -> DeviceEntry` e não um set, porque você precisa acesso por chave (o MAC) para atualização incremental eficiente.

**Como `Dissector` resolve o problema de manter estado?** Ele é instanciado uma vez por sessão de captura e mantém internamente o `TrafficContext`. A função `sniff` cria um `Dissector` no início e chama `dissector.dissect(frame)` em loop. O estado de `TrafficSummary` cresce automaticamente a cada chamada.

## Response:
pktparsers

