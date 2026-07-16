# Pktparsers Architecture Documentation

## 1. Overview

**pktparsers** is a modular library for parsing frames/packets of communication protocols (layers L1 to L7).

### Philosophy

* **Modular**: independent and reusable parsers
* **Semantic**: results describe the protocol meaning, not raw bytes
* **Dissect DLT-oriented**: dissection initiated via Data Link Type registration
* **Context**: `ContextVar` for thread-safe state

### Responsibilities

1. Parsing frames from different DLTs
2. Generation of semantic summaries for analysis
3. Reusable parsers for independent use
4. Expression filters
5. Traffic analysis and device tracking

---

## 2. Core Concepts

| Concept | Purpose |
| --- | --- |
| **DLT** | Identifies the link layer type (e.g., `DLT_IEEE802_11_RADIO = 127`) |
| **ParseContext** | Parsing state (frame, offset, result) via `ContextVar` |
| **DissectConfig** | Parsing configurations, credentials, and analysis |
| **TrafficContext** | Tracks devices and statistics between packets |
| **Dissector** | Orchestrator: parsing + traffic analysis |
| **Filter Engine** | Expression filters (`ieee802_11.mac_hdr.sa.addr == "aa:bb:cc:dd:ee:ff"`) |

### Quick Structures

```python
# Dissector
dissector = Dissector("DLT_IEEE802_11_RADIO")
resultado = dissector.dissect(frame_raw)  # -> {"parsed": {...}, "traffic": {...}}

# ParseContext (standalone)
with ParseContext(frame, offset=0) as ctx:
    resultado = parser()

# TrafficContext (automatic via Dissector)
traffic_ctx = TrafficContext.current()

```

---

### Directory Organization

```
pktparsers/core/layers/
├── l2/ieee802/
│   ├── dot11/            # 802.11 WiFi (complete)
│   ├── dot3/             # 802.3 Ethernet (partial)
│   ├── dot2/llc/         # 802.2 LLC (dispatch by ethertype)
│   └── dot1x/eapol/      # 4-way handshake
├── l3/
│   ├── ip/parse.py
│   └── arp/parse.py
└── l4,l7/                # Future

```

---

## 4. Functional Flow

```
Raw Packet
    ↓
Dissector.dissect()
    ├─ TrafficContext (tracks devices)
    └─ DLT Parser (e.g., ieee802_11_radio.parse)
        ├─ ParseContext (state)
        ├─ Radiotap → MAC 802.11 → Body
        │   └─ Dispatch: Management/Control/Data → LLC → EAPOL/IP/ARP
        ├─ summarizer() → readable summary
        └─ analyzer() → updates TrafficContext
    ↓
Returns {"parsed": {...}, "traffic": {...}}

```

### Parser Pattern (`unpack` function)

```python
def parse(**kwargs) -> dict:
    def _parser(valor: tuple, **kwargs) -> dict:
        # semantic interpretation
        return {"campo": valor_interpretado}
    return unpack("<FORMATO", parser=_parser, summarizer=_summarizer)

```

---

## 5. Data Structures

### ParseContext.result (hierarchical with metadata)

```python

```

### TrafficSummary

```python
{
    "devices": {
        "aa:bb:cc:dd:ee:ff": {
            "first_seen": 1234567890.123,
            "protocols_data": {"ieee802_11": {"role": "STA", "frames_sent": 542}},
            "annotations": {"security": "WPA2/PSK"}
        }
    }
}

```

---

## 7. Design Patterns

| Pattern | Implementation |
| --- | --- |
| **Parser with Callback** | `unpack(fmt, parser=_parser)` separates binary extraction from interpretation |
| **Dispatch Table** | `run_dispatch(TABELA, id, fallback=unpack)` with name/description |
| **Context Manager** | `ParseContext`, `TrafficContext`, `Dissector` with `ContextVar` |
| **Lazy Singleton** | `MacVendorResolver` loads vendor DB once |
| **Analyzer Callback** | DLT or protocol calls `summarizer()` → `analyzer()` → updates `TrafficContext` |

---

## 8. Design Decisions

| Decision | Reason |
| --- | --- |
| **ParseContext as ContextVar** | Thread-safe; avoids passing context through every function |
| **Separate DLT vs protocol parsers** | The same protocol (802.11) appears in different DLTs |
| **Data structures related to parsing and analysis use functions (not dataclasses)** | Flexible; user can access any nested data |
| **`get_nested()` for field access** | Case-insensitive; automatically drills down into "parsed" |
| **`insert_item()` helper** | Converts duplicate keys into numbered dicts |
| **`fail()` only for critical errors** | Minor errors (unknown tags) do not abort the parsing |
| **Dispatch by ethertype** | Natural evolution of SNAP/DSAP/PID |

---

## 10. Usage Examples

### Basic Dissector

```python
from pktparsers.dissector import Dissector

with Dissector("DLT_IEEE802_11_RADIO") as dissector:
    resultado = dissector.dissect(frame_raw)
    src_mac = resultado["parsed"]["ieee802_11"]["mac_hdr"]["parsed"]["addr2"]["addr"]
    traffic = resultado["traffic"]
```

### Isolated Protocol Parser

```python
from pktparsers.core.parsing import ParseContext
from pktparsers.core.layers.l2.ieee802.dot11.parsers.mac_header.parse import parse

with ParseContext(frame_bytes, 0) as ctx:
    mac_hdr = parse()
    bssid = mac_hdr["parsed"]["bssid"]["addr"]

```

### Filters

```python
from pktparsers.core.filter_engine import apply_filters

store_ok, display = apply_filters(
    store_filter="ieee802_11.mac_hdr.fc.type == 2 and ieee802_11.body.llc.pid == 0x888e",
    display_filter="ieee802_11.mac_hdr.sa.addr, ieee802_11.body.llc.payload.key_information.key_ack",
    parsed_frame=resultado["parsed"]
)

```

### Traffic Analysis Across Packets

```python
with Dissector("DLT_IEEE802_11_RADIO") as dissector:
    for pacote in pacotes:
        dissector.dissect(pacote)
    aps = {
        mac: dev for mac, dev in dissector.traffic_ctx.summary["devices"].items()
        if dev.get("protocols_data", {}).get("ieee802_11", {}).get("role") == "AP"
    }
    print(aps)

```

---

## 11. Filter Engine Reference

| Syntax | Example |
| --- | --- |
| Comparison | `campo == valor`, `campo > 10` |
| Logic | `cond1 and cond2`, `cond1 or cond2`, `not cond` |
| Membership | `campo in (1,2,3)`, `campo not in ("a","b")` |
| Path | `ieee802_11.mac_hdr.sa.addr` (case-insensitive, enters "parsed") |
| Types | Auto-detection: int, float, bool, string (quoted) |

---

## Standards to be followed:

* Analyze the attached pktparsers-repomix.md file to obtain the full project context.
* Do not hardcode key names in dicts; define them first in a specific definitions.py file for that protocol or DLT, if they do not already exist in a previous definitions.py file.
* Follow the file structure I defined; only complete/develop the incomplete functions according to the idea I provided.
* Use `get_nested()` for dictionary access
* Never use inline logic inside dictionary literals (use variables)
* Follow the `unpack(callback=_parser)` pattern
* Use `insert_item()` for duplicate keys
* Use `fail()` only for critical errors
* Only protocol or dlt parsing functions modify ParseContext.result.
* The "summarizer" function does not add the generated summary to the ParseContext.result variable because it is the main parser of the protocol or DLT that should decide whether the summary goes to ParseContext.result or not.
* Only the "analyzer" function feeds TrafficContext.summary.
* Avoid unnecessary coupling
* Protocol parsing functions create their result dicts in ParseContext.result, using their own key related to their protocol to identify the result dict.

## Explanation and Clarifications

* Ethertypes are an evolution of snap, dsap, or pid. Therefore, I will use only ethertypes for protocol mapping.
* bitwise e endians são detalhes de parsers, não precisam ser constantizados em definitions.
* In parsers/, create a directory for each parse module if it uses its own key names and sizes.
* The correct criterion for managing modules is understanding what the module is and which domain/subsystem it belongs to, not who uses/imports it.
* Parse/parser/parsers means binary extraction and analysis to generate a result with a syntactic structure that represents the original raw (binary) value that was passed as input.

## 13. Contribution Guidelines

### Adding a New Protocol

#### analyzers/ directory structure
```bash
analyzers/
   definitions.py
   summary.py
```
Or it could be:
```bash
analyzers/
   definitions.py
   analyzer.py
   summarizer.py
```

```bash
protocol/
   parse.py          # def parse(**kwargs): return unpack(fmt, parser=_parser)
   definitions.py    # constants
   analyzers/
   parsers/          # sub-parsers as needed
   crypt.py
```

### Adding a New DLT for an Existing Protocol

```bash
protocolo/dlt/<nome>/
   parse.py
   crypt.py # if necessary
   definitions.py # if necessary
   analyzers/
   parsers/
```

---

## 14. Conclusion

**pktparsers** offers a clean and extensible architecture for network protocol parsing. The combination of DLT-based entry, thread-safe context management, and hierarchical parsing provides modularity and ease of use. The separation between protocol logic and DLT handling ensures reusability across different capture sources.

The design prioritizes semantic clarity (what protocols mean) over raw binary details, allowing higher-level applications to perform intelligent traffic analysis, filtering, and visualization.
