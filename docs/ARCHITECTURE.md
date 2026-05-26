# Pktparsers Architecture Documentation

## 1. Overview

**pktparsers** is a modular library for parsing frames/packets of communication protocols (layers L1 to L7).

### Philosophy

* **Modular**: independent and reusable parsers
* **Semantic**: results describe the protocol meaning, not raw bytes
* **DLT-oriented**: parsing initiated via Data Link Type registration
* **Context**: `ContextVar` for thread-safe state
* **Separation**: DLT parsers modify `ParseContext.result`; protocol parsers are read-only

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
| **Filter Engine** | Expression filters (`dot11.mac_hdr.sa.addr == "aa:bb:cc:dd:ee:ff"`) |

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

## 3. Layered Architecture

```
L7 ──► (Future: HTTP, DNS, TLS)
L4 ──► (Future: TCP, UDP)
L3 ──► IP + ARP
L2 ──► IEEE 802: dot11 (WiFi) | dot3 (Ethernet) | dot2 (LLC) | dot1x (EAPOL)
L1 ──► (no parsing)

```

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
{
    "rt_hdr": {
        "_metadata_": {"start": 0, "end": 26, "raw": "00001b64..."},
        "parsed": {"version": 0, "flags": {"bad_fcs": False}, "channel": 6}
    },
    "dot11": {
        "mac_hdr": {"parsed": {"addr2": {"addr": "aa:bb:cc:dd:ee:ff"}}},
        "body": {"llc": {"parsed": {"protocol_type": 0x888e, "name": "eapol"}}}
    }
}

```

### TrafficSummary

```python
{
    "devices": {
        "aa:bb:cc:dd:ee:ff": {
            "first_seen": 1234567890.123,
            "protocols_data": {"dot11": {"role": "STA", "frames_sent": 542}},
            "annotations": {"security": "WPA2/PSK"}
        }
    }
}

```

---

## 6. Module Organization

| File | Function |
| --- | --- |
| `parsing.py` | `unpack()`, `run_dispatch()`, `ParseContext`, `insert_item()` |
| `filter_engine.py` | `get_nested()`, `apply_filters()` |
| `definitions.py` | Constants: `PARSED`, `SUMMARY`, `VALUE`, `METADATA` |

### Standard Protocol Structure

```
protocolo/
├── parse.py              # main entry point
├── definitions.py        # constants of dict keys and struct formats
├── analyzers/summary.py  # summarizer() + analyzer()
├── parsers/              # header.py, body.py, ies.py , creates a directory for a specific parser, in case it uses many hardcoded strings of dictionary keys or struct formats
└── dlt/<nome_dlt>/       # DLT-specific override

```

**Rule:** Only DLT parsers modify `ParseContext.result`. Protocol parsers are read-only.

---

## 7. Design Patterns

| Pattern | Implementation |
| --- | --- |
| **Parser with Callback** | `unpack(fmt, parser=_parser)` separates binary extraction from interpretation |
| **Dispatch Table** | `run_dispatch(TABELA, id, fallback=unpack)` with name/description |
| **Context Manager** | `ParseContext`, `TrafficContext`, `Dissector` with `ContextVar` |
| **Lazy Singleton** | `MacVendorResolver` loads vendor DB once |
| **Analyzer Callback** | DLT calls `summarizer()` → `analyzer()` → updates `TrafficContext` |

---

## 8. Design Decisions

| Decision | Reason |
| --- | --- |
| **Entry via DLT** | Single interface for libpcap, tcpdump, nl80211 |
| **ParseContext as ContextVar** | Thread-safe; avoids passing context through every function |
| **Separate DLT vs protocol parsers** | The same protocol (802.11) appears in different DLTs |
| **Only DLT modifies ParseContext.result** | Consistency; protocol parsers are pure functions |
| **Analyzers as functions (not dataclasses)** | Flexible; user can access any nested data |
| **`get_nested()` for field access** | Case-insensitive; automatically drills down into "parsed" |
| **`insert_item()` helper** | Converts duplicate keys into numbered dicts |
| **`fail()` only for critical errors** | Minor errors (unknown tags) do not abort the parsing |
| **Dispatch by ethertype** | Natural evolution of SNAP/DSAP/PID |

---

## 9. Implementation Status

### Fully Implemented

* Radiotap header (all fields: flags, channel, MCS, VHT, HE, timestamp)
* MAC header 802.11, Management/Control/Data frames
* 75+ Information Elements (SSID, Rates, RSN, HT, VHT, HE, WPS, WMM)
* LLC → EAPOL (4-way handshake)
* ARP, IPv4 header
* Filter engine (comparisons, logic, `in`/`not in`, path)
* ParseContext, TrafficContext, Dissector

### Partial

| Component | Dependency / Pending |
| --- | --- |
| Ethernet (dot3) | DLT_EN10MB parser, analyzers |
| IP | fragment reassembly, options |
| EAP/RADIUS | structure ready |
| Bluetooth HCI | structure ready |

### Future

* L4/L7: TCP, UDP, HTTP, DNS, DHCP, TLS
* Decryption: WPA2/WPA3 handshake, TLS key log
* I/O: pcap/pcapng/JSON read/write
* TUI, graphs, hashcat 22000

---

## 10. Usage Examples

### Basic Dissector

```python
from pktparsers.dissector import Dissector

with Dissector("DLT_IEEE802_11_RADIO") as dissector:
    resultado = dissector.dissect(frame_raw)
    src_mac = resultado["parsed"]["dot11"]["mac_hdr"]["parsed"]["addr2"]["addr"]
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
from pktparsers.corefilter_engine import apply_filters

store_ok, display = apply_filters(
    store_filter="dot11.mac_hdr.fc.type == 2 and dot11.body.llc.pid == 0x888e",
    display_filter="dot11.mac_hdr.sa.addr, dot11.body.llc.payload.key_information.key_ack",
    parsed_frame=resultado["parsed"]
)

```

### Traffic Analysis Across Packets

```python
dissector = Dissector("DLT_IEEE802_11_RADIO")
for pacote in pacotes:
    dissector.dissect(pacote)

aps = {
    mac: dev for mac, dev in dissector.traffic_ctx.summary["devices"].items()
    if dev.get("protocols_data", {}).get("dot11", {}).get("role") == "AP"
}

```

### Custom Configuration

```python
config = DissectConfig(
    parse={"ieee802_11_radio": {"assume_fcs": True}},
    credentials={"ieee802_11": {"psk": "MinhaSenha123"}},
    analysis={"traffic_summary": True}
)
dissector = Dissector("DLT_IEEE802_11_RADIO", config=config)

```

### JSON Writing

```python
from pktparsers.io import write_json, write_jsonl

write_json("frame.json", resultado["parsed"])
write_jsonl("frames.jsonl", [dissector.dissect(p)["parsed"] for p in pacotes])

```

---

## 11. Filter Engine Reference

| Syntax | Example |
| --- | --- |
| Comparison | `campo == valor`, `campo > 10` |
| Logic | `cond1 and cond2`, `cond1 or cond2`, `not cond` |
| Membership | `campo in (1,2,3)`, `campo not in ("a","b")` |
| Path | `dot11.mac_hdr.sa.addr` (case-insensitive, enters "parsed") |
| Types | Auto-detection: int, float, bool, string (quoted) |

---

## 12. Future Roadmap

| Phase | Focus |
| --- | --- |
| **1 (Current)** | Complete dot3, IP/ARP analyzers, testing, adjust imports |
| **2** | Configurable FCS, protocol selection, decryption keys |
| **3** | I/O pcap/pcapng/ERF, format conversion, packet merge |
| **4** | TUI (list, tree, hexdump), graphs, CLI |
| **5** | L4/L7 parsers, WPA2/WPA3 decryption, Bluetooth, hashcat 22000 |

---

## 13. Contribution Guidelines

### Adding a New Protocol

```bash
protocolo/
├── parse.py          # def parse(**kwargs): return unpack(fmt, parser=_parser)
├── definitions.py    # constants
├── analyzers/summary.py  # summarizer() + analyzer()
└── parsers/          # sub-parsers as needed

```

### Adding a New DLT for an Existing Protocol

```bash
protocolo/dlt/<nome>/
├── parse.py          # with ParseContext, calls core protocol parser
└── analyzers/        # DLT-specific summarizer/analyzer

```

Then add it to `core/registry.py` → `DLT_DISPATCH`.

### Code Style

* Use `get_nested()` for dictionary access
* Never use inline logic inside dictionary literals (use variables)
* Follow the `unpack(callback=_parser)` pattern
* Only DLT parsers modify `ParseContext.result`
* Use `insert_item()` for duplicate keys
* Use `fail()` only for critical errors

---

## 14. Conclusion

**pktparsers** offers a clean and extensible architecture for network protocol parsing. The combination of DLT-based entry, thread-safe context management, and hierarchical parsing provides modularity and ease of use. The separation between protocol logic and DLT handling ensures reusability across different capture sources.

The design prioritizes semantic clarity (what protocols mean) over raw binary details, allowing higher-level applications to perform intelligent traffic analysis, filtering, and visualization.

## Explanation and Clarifications

* Ethertypes are an evolution of snap, dsap, or pid. Therefore, I will use only ethertypes for protocol mapping.
* bitwise e endians são detalhes de parsers, não precisam ser constantizados em definitions.
* In parsers/, create a directory for each parse module if it uses its own key names and sizes.
* The correct criterion for managing modules is understanding what the module is and which domain/subsystem it belongs to, not who uses/imports it.
