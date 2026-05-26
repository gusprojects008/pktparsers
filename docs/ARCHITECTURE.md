# Pktparsers Architecture Documentation

## Table of Contents

1. [Project Overview](#project-overview)
2. [Core Concepts](#core-concepts)
3. [Architecture Layers](#architecture-layers)
4. [Functional Flow](#functional-flow)
5. [Data Structures](#data-structures)
6. [Module Organization](#module-organization)
7. [Design Patterns](#design-patterns)
8. [Future Roadmap](#future-roadmap)

---

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

## Architecture Layers

### Layer Structure

```
┌─────────────────────────────────────────────────────────────┐
│                      Application Layer (L7)                  │
│     (HTTP, DNS, DHCP, etc. - Optional for now)              │
└─────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────┐
│                  Transport Layer (L4)                         │
│              (TCP, UDP - Stubs for now)                      │
└─────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────┐
│                    Network Layer (L3)                         │
│        IP (Parse + Analyzers) → ARP, ICMP                   │
└─────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────┐
│                  Data Link Layer (L2)                         │
│                                                               │
│  IEEE 802:                                                   │
│  ├─ Dot11 (802.11 WiFi)  [Fully Implemented]               │
│  │  ├─ DLT: DLT_IEEE802_11_RADIO (127) + Radiotap          │
│  │  ├─ DLT: DLT_IEEE802_11 (105)                           │
│  │  └─ Parsers: MAC Header, Body, IEs                       │
│  │                                                           │
│  ├─ Dot3 (802.3 Ethernet)   [Structure Ready]              │
│  │  ├─ DLT: DLT_EN10MB (1)                                 │
│  │  └─ Parsers: Ethernet Header, Payload Dispatch           │
│  │                                                           │
│  ├─ Dot1x (802.1X - EAP)    [Parsers Ready]                │
│  │  └─ Sub-protocols: EAPOL, EAP, RADIUS                   │
│  │                                                           │
│  ├─ Dot2 (LLC)              [Common Dispatch]              │
│  │  └─ Payload dispatch for Ethernet/WiFi                   │
│  │                                                           │
│  └��� Bluetooth HCI           [Structure Ready]               │
│                                                               │
│  Radiotap Header Parsing    [Fully Implemented]            │
└─────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────┐
│                   Physical Layer (L1)                         │
│                  (No parsing needed)                          │
└─────────────────────────────────────────────────────────────┘
```

### Layer Files Organization

```
pktparsers/core/layers/
├── l1/                      # Physical layer (empty)
├── l2/                      # Data Link Layer
│   ├── definitions.py       # L2 constants (EUI48_LENGTH, OUI_LENGTH)
│   ├── ieee802/             # IEEE 802 standards family
│   │   ├── dot11/           # 802.11 WiFi
│   │   │   ├── dlt/         # DLT-specific implementations
│   │   │   │   ├── ieee802_11_radio/      # With Radiotap
│   │   │   │   └── ieee802_11/            # Without Radiotap
│   │   │   ├── parsers/     # Protocol-level parsers
│   │   │   ├── analyzers/   # Summary generation
│   │   │   ├── definitions.py
│   │   │   ├── parse.py     # Main entry point
│   │   │   └── build.py     # Frame construction (future)
│   │   ├── dot3/            # 802.3 Ethernet
│   │   ├── dot2/            # 802.2 LLC
│   │   ├── dot1x/           # 802.1X EAP
│   │   └── __init__.py
│   └── bluetooth/           # Bluetooth protocols
├── l3/                      # Network Layer
│   ├── ip/                  # IPv4/IPv6
│   ├── arp/                 # ARP
│   └── __init__.py
├── l4/                      # Transport Layer
├── l7/                      # Application Layer
└── __init__.py

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

<<<<<<< HEAD
## Functional Flow

### 1. Entry Point: DLT Registry

```python
# pktparsers/core/registry.py
DLT_DISPATCH = {
    "DLT_IEEE802_11_RADIO": {
        "value": 127,
        "parser": ieee802_11_radio.parse
    },
    "DLT_IEEE802_11": {
        "value": 105,
        "parser": ieee802_11.parse
    },
    # ... other DLTs
}

parser = get_parser("DLT_IEEE802_11_RADIO")  # Returns function reference
```

### 2. Packet Dissection Flow

```
Raw Packet Bytes
    ↓
Dissector.dissect(packet)
    ↓
┌─ DissectContext (manages summaries) ─┐
│                                       │
│  DLT Parser (e.g., ieee802_11_radio) │
│      ↓                                │
│  ParseContext (manages state)         │
│      ├─ Radiotap Header Parser       │
│      ├─ 802.11 MAC Header Parser     │
│      ├─ Frame Body Parser            │
│      │   ├─ Management/Control/Data  │
│      │   └─ Tagged Parameters (IEs)  │
│      └─ LLC/Payload Dispatcher       │
│          ├─ EAPOL Parser             │
│          ├─ IP Parser                │
│          └─ ARP Parser               │
│                                       │
│  Analyzer (generates summary)         │
│      ↓                                │
│  Summary added to DissectContext      │
└─────────────────────────────────────┘
    ↓
TrafficContext.update(summaries)
    ↓
DissectionResult {
    parsed: dict,           # Full parse tree
    summaries: dict,        # Per-protocol summaries
    traffic: TrafficSummary # Aggregated statistics
}
```

### 3. Parser Internal Flow

Each protocol parser follows this pattern:

```python
def parse(**kwargs) -> dict:
    ctx = ParseContext.current()
    
    # 1. Extract metadata
    insert_item(ctx.result, "protocol_key", {})
    
    # 2. Parse header/fields
    result = unpack("<HBB...", parser=_internal_parser)
    
    # 3. Dispatch to sub-protocols
    payload = run_dispatch(DISPATCH_TABLE, dispatch_id, **kwargs)
    
    # 4. Generate summary (optional)
    summary = generate_summary(ctx.result)
    
    # 5. Add to context
    insert_item(ctx.result, "summary", summary)
    
    return ctx.result
```

### 4. Data Flow: From Raw to Summary

```
Raw Bytes: [00 11 22 33 44 55 ...]
    ↓
unpack("<H", parser=_parser)
    ├─ struct.unpack extracts binary values
    ├─ _parser() interprets values semantically
    └─ Returns dict with "parsed" key
    ↓
ParseContext accumulates results
    ├─ ctx.offset advances
    ├─ ctx.result grows hierarchically
    └─ ctx.summary collects summaries
    ↓
Dispatcher routes to next layer
    ↓
Analyzer creates TrafficSummary
    ├─ Device entries (MAC → statistics)
    ├─ Relationships (sender → receiver)
    └─ Annotations (WPS detected, security level, etc.)

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

## Data Structures

### 1. ParseContext.result

Hierarchical dictionary accumulating parse results:

```python
{
    "_metadata_": {
        "start": 0,
        "end": 26,
        "length": 26,
        "raw": "00011b64...",
        "fmt": "<BBH...",
        "tokens": ("<B", "<H", ...),
        "sizes": (1, 2, ...)
    },
    "value": {              # Raw unpacked values
        "0": 0,
        "1": 27,
        "2": 10240
    },
    "parsed": {             # Semantic interpretation
        "timestamp": 1234567890,
        "beacon_interval": 100,
        "capabilities": {"privacy": True, "qos": True}
    }
}
```

### 2. DissectContext.summaries

```python
{
    "dot11": [
        {
            "frame_type": "Data",
            "src": "aa:bb:cc:dd:ee:ff",
            "dst": "11:22:33:44:55:66",
            "bssid": "5c:62:8b:80:83:8a"
        },
        # ... more frames
    ],
    "ip": [
        {
            "src": "192.168.1.100",
            "dst": "10.0.0.1",
            "protocol": 6  # TCP
        }
    ]
}
```

### 3. TrafficSummary


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
        "5c:62:8b:80:83:8a": {  # BSSID or MAC hash
            "first_seen": 1234567890.0,
            "last_seen": 1234567920.5,
            "protocols_data": {
                "dot11": {
                    "role": "AP",
                    "ssids": ["MyNetwork"],
                    "channels_seen": [6, 11],
                    "frames_sent": 542,
                    "frames_received": 128,
                    "retry_count": 12
                }
            },
            "annotations": {
                "security": "WPA2/PSK",
                "wps": True,
                "clients": 3
            }
        }
    },
    "annotations": {
        "total_packets": 1024,
        "total_devices": 15,
        "capture_duration": 45.3,
        "security_summary": {"OPEN": 2, "WEP": 1, "WPA2": 5, "WPA3": 1}
    }
}
```

### 4. DissectionResult

```python
@dataclass
class DissectionResult:
    parsed: dict              # Full parse tree
    summaries: dict           # Per-protocol summaries
    traffic: TrafficSummary   # Aggregated traffic statistics
        "aa:bb:cc:dd:ee:ff": {
            "first_seen": 1234567890.123,
            "protocols_data": {"dot11": {"role": "STA", "frames_sent": 542}},
            "annotations": {"security": "WPA2/PSK"}
        }
    }
}

```

---

## Module Organization

### Common Modules (pktparsers/common/)

```
common/
├── parse/
│   ├── definitions.py       # Constants: PARSED, SUMMARY, VALUE, METADATA, etc.
│   ├── utils.py             # unpack(), run_dispatch(), ParseContext, etc.
│   ├── filter_engine.py     # get_nested(), apply_filters()
│   └── mac-vendors-export.json
├── definitions/
│   ├── parsers.py           # DLT constants
│   └── hashcat.py           # Hashcat integration (future)
└── build/
    └── builder.py           # Frame construction (future)
```

### Core Modules (pktparsers/core/)

**registry.py**: DLT dispatcher mapping

```python
get_parser(dlt: str | int)          # Get parser function
get_dlt_value(dlt_name: str)        # Get numeric value
list_supported_dlts()               # List available parsers
```

**Traffic Analysis** (pktparsers/core/analyzers/traffic/):

- `context.py`: TrafficContext manager
- `definitions.py`: TrafficSummary data structures

### Protocol Module Structure

Each protocol has this hierarchy:

```
protocol/
├── __init__.py
├── definitions.py           # Constants & data classes
├── parse.py                 # Main parser (calls sub-parsers)
├── analyzers/
│   ├── definitions.py       # Device entries, relationships
│   └── summary.py           # analyzer() & summarize() functions
├── dlt/                     # DLT-specific implementations
│   └── dlt_name/
│       ├── parse.py         # DLT-specific entry
│       ├── parsers/         # DLT-specific sub-parsers
│       └── analyzers/       # DLT-specific analyzers
├── parsers/                 # Protocol-level parsers
│   ├── header.py
│   ├── body.py
│   ├── common.py
│   └── ies.py              # Information Elements
├── build.py                 # Frame construction (future)
├── builders/                # Builders directory (future)
└── __main__.py             # Tests/examples
```

---

## Design Patterns

### 1. Parser Pattern

```python
def parser(**kwargs) -> dict:
    """Main parser that orchestrates sub-parsers"""
    def _parser(value: tuple, **k) -> dict:
        """Internal parser receiving unpacked binary values"""
        # Interpret values semantically
        return {...interpreted...}
    
    return unpack("<HBB...", parser=_parser, summarizer=_summarize)
```

### 2. Dispatch Pattern

```python
DISPATCH_TABLE = {
    FRAME_TYPE_MGMT: management_parser,
    FRAME_TYPE_CTRL: control_parser,
    FRAME_TYPE_DATA: data_parser,
}

result = run_dispatch(DISPATCH_TABLE, frame_type, fallback=unpack)
```

### 3. Context Manager Pattern

```python
# Thread-safe parsing state
with ParseContext(frame, offset) as ctx:
    result = parser()  # Updates ctx.result and ctx.offset
    return ctx.result

# Thread-safe dissection
with DissectContext() as dissect_ctx:
    parsed = parser()
    dissect_ctx.add_summary("dot11", summary)
    return dissect_ctx.summaries
```

### 4. Lazy Loading Pattern

MacVendorResolver loads vendor database only once:

```python
class MacVendorResolver:
    _vendor_map = None  # Cached at class level
    
    def __init__(self):
        if self._vendor_map is None:
            # Load from file once
            self._load_vendors()
```

### 5. Analyzer Callback Pattern

After parsing, analyzers process results:

```python
def analyzer(parser_result: dict, parser_summary: dict):
    """Analyze parsed data to update traffic summary"""
    traffic_ctx = TrafficContext.current()
    traffic = traffic_ctx.summary
    
    # Extract device info
    device_mac = get_nested("mac_hdr.sa.addr", parser_result)
    
    # Update or create device entry
    if device_mac not in traffic["devices"]:
        traffic["devices"][device_mac] = make_device_entry()
    
    # Update statistics
    traffic["devices"][device_mac]["frames_sent"] += 1
```

---

## Design Decisions & Rationale

### 1. Why DLT-Based Entry Point?

- **Reason**: Different capture sources (libpcap, tcpdump, nl80211) use DLT to identify layer 2 type
- **Benefit**: Unified interface for multiple capture sources
- **Example**: framesniff can switch DLTs, wnlpy extracts protocol parsers for independent use

### 2. Why ParseContext as ContextVar?

- **Reason**: Allows nested parsing without passing context through every function
- **Benefit**: Cleaner API, thread-safe by default
- **Trade-off**: Implicit state management (less explicit than dependency injection)

### 3. Why Separate Protocol & DLT Parsers?

- **Reason**: Same protocol (802.11) can appear in different DLTs (with/without Radiotap)
- **Benefit**: Protocol logic is shared; DLT-specific logic (like header removal) is isolated
- **Example**: `ieee802_11/parse.py` (core) vs `ieee802_11_radio/parse.py` (with Radiotap)

### 4. Why Analyzer Functions Instead of Dataclasses?

- **Initially**: Dataclasses were considered for documentation
- **Current**: Using dicts with generator functions
- **Reason**: Allows user access to any nested data; no rigid schema
- **Trade-off**: Less type safety, but more flexible

### 5. Why Summary Generation After Parsing?

- **Flow**: Parse → Summary → Traffic Analysis
- **Reason**: Summaries are computed results, not part of core parsing
- **Benefit**: Optional; can skip for performance if only parsed data is needed
- **Future**: Enable toggle to skip summary generation via config

### 6. Why Separate "entries" Field in Traffic Summary?

- **Purpose**: Store heuristic analysis data (security detections, WPS info, etc.)
- **Structure**: Not rigidly defined; depends on analyzer
- **Example**: `{"wps_detected": True, "encryption": "WPA2", "clients": [...]}`

### 7. Why Bytes → Hex in unpack?

- **Reason**: JSON serialization and user filtering requires text format
- **Implementation**: `normalize_bytes()` converts all bytes to hex strings
- **Storage**: `_metadata_.raw` stores hex; parsed values store hex

### 8. Why get_nested() for Field Access?

- **Problem**: Parsed data is deeply nested; case-insensitive paths useful
- **Solution**: `get_nested("mac_hdr.fc.type", parsed)` navigates path
- **Feature**: Auto-detects and enters "parsed" keys; handles numeric dicts
- **Usage**: Filters, display, analysis all use it

---

## Future Roadmap

### Phase 1: Completion (Current)

- [ ] Fix import errors in dissector.py
- [ ] Complete dot3 (Ethernet) parsers
- [ ] Implement IP/ARP analyzers
- [ ] Finalize traffic summary structure
- [ ] Add unit tests for each parser

### Phase 2: Configuration & Options

- [ ] Support user-configurable FCS assumptions
- [ ] Protocol selection (parse/skip certain protocols)
- [ ] Decryption key management (WPA, WEP, WPA3)
- [ ] Custom summary generators

### Phase 3: IO & Utilities

- [ ] `read_pcap()`, `read_pcapng()`, `read_erf()` functions
- [ ] `write_json()`, `write_jsonl()` for parse results
- [ ] Format conversion tools (pcap ↔ pcapng, JSON, etc.)
- [ ] Merge/filter utilities for capture files

### Phase 4: Visualization & Analysis

- [ ] TUI components (packet list, tree view, hexdump)
- [ ] Graph generation module (traffic flows, device relationships)
- [ ] Filter syntax documentation
- [ ] CLI for standalone packet analysis

### Phase 5: Advanced Features

- [ ] Payload decryption (WPA2/WPA3 handshakes)
- [ ] L4/L7 parsers (TCP, UDP, HTTP, DNS)
- [ ] Bluetooth protocol support
- [ ] Anomaly detection heuristics

---

## Usage Examples

### 1. Basic Dissection
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

dissector = Dissector("DLT_IEEE802_11_RADIO")
result = dissector.dissect(raw_frame_bytes)

print(result.parsed)        # Full parse tree
print(result.summaries)     # Per-protocol summaries
print(result.traffic)       # Traffic statistics
```

### 2. Using Specific Protocol Parser

```python
from pktparsers.common.parse.utils import ParseContext
from pktparsers.core.layers.l2.ieee802.dot11.parsers.mac_header import parser as mac_hdr_parser

with ParseContext(frame_bytes, offset=0) as ctx:
    mac_hdr_result = mac_hdr_parser()
    bssid = mac_hdr_result["parsed"]["bssid"]["addr"]
```

### 3. Filtering Parsed Data

```python
from pktparsers.common.parse.filter_engine import apply_filters

store_ok, display = apply_filters(
    store_filter="mac_hdr.fc.type == 2 and dot11.body.llc.type == 0x888e",
    display_filter="mac_hdr.sa.addr, mac_hdr.da.addr, dot11.body.llc.type",
    parsed_frame=result.parsed
)

if store_ok:
    print(display)  # Only requested fields
```

### 4. Traffic Analysis

```python
from pktparsers.core.analyzers.traffic.context import TrafficContext

# After dissecting multiple packets:
traffic_ctx = TrafficContext.current()
summary = traffic_ctx.summary

for device_id, device_info in summary["devices"].items():
    print(f"Device {device_id}: {device_info['frames_sent']} frames sent")
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

## File Reference

### Critical Files

| File | Purpose |
|------|---------|
| `pktparsers/dissector.py` | Main Dissector class orchestrator |
| `pktparsers/core/registry.py` | DLT dispatcher |
| `pktparsers/common/parse/utils.py` | ParseContext, unpack(), run_dispatch() |
| `pktparsers/common/parse/filter_engine.py` | get_nested(), apply_filters() |
| `pktparsers/core/analyzers/traffic/` | Traffic summary management |

### Protocol Parsers

| Path | Protocol | Status |
|------|----------|--------|
| `core/layers/l2/ieee802/dot11/` | 802.11 WiFi | ✅ Implemented |
| `core/layers/l2/ieee802/dot11/dlt/ieee802_11_radio/` | WiFi + Radiotap | ✅ Implemented |
| `core/layers/l2/ieee802/dot3/` | Ethernet | 🟡 Partial |
| `core/layers/l2/ieee802/dot1x/` | 802.1X/EAP | 🟡 Partial |
| `core/layers/l3/ip/` | IPv4/IPv6 | 🟡 Partial |
| `core/layers/l3/arp/` | ARP | 🟡 Partial |

---

## Conclusion

**pktparsers** provides a clean, extensible architecture for network protocol parsing. By combining DLT-based entry points, thread-safe context management, and hierarchical parsing, it achieves both modularity and ease of use. The separation between protocol logic and DLT-specific handling ensures code reusability across different capture sources.

The design prioritizes semantic clarity (what protocols mean) over raw binary details, enabling higher-level applications to perform intelligent traffic analysis, filtering, and visualization.

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
