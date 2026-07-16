This file is a merged representation of a subset of the codebase, containing files not matching ignore patterns, combined into a single document by Repomix.

# File Summary

## Purpose
This file contains a packed representation of a subset of the repository's contents that is considered the most important context.
It is designed to be easily consumable by AI systems for analysis, code review,
or other automated processes.

## File Format
The content is organized as follows:
1. This summary section
2. Repository information
3. Directory structure
4. Repository files (if enabled)
5. Multiple file entries, each consisting of:
  a. A header with the file path (## File: path/to/file)
  b. The full contents of the file in a code block

## Usage Guidelines
- This file should be treated as read-only. Any changes should be made to the
  original repository files, not this packed version.
- When processing this file, use the file path to distinguish
  between different files in the repository.
- Be aware that this file may contain sensitive information. Handle it with
  the same level of security as you would the original repository.

## Notes
- Some files may have been excluded based on .gitignore rules and Repomix's configuration
- Binary files are not included in this packed representation. Please refer to the Repository Structure section for a complete list of file paths, including binary files
- Files matching these patterns are excluded: docs, .venv, __pycache__, **/*.json, **/ie/**, tests, .**
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Files are sorted by Git change count (files with more changes are at the bottom)

# Directory Structure
```
src/
  pktparsers/
    app/
      app.py
      bootstrap.py
      context.py
    cli/
      __init__.py
      __main__.py
      main.py
    common/
      __init__.py
    core/
      definitions/
        analysis.py
        dlt.py
        entries.py
        erf.py
        parsing.py
        protocol.py
        result.py
      dissectors/
        arp/
          analyzers/
            summary.py
          __init__.py
          crypt.py
          definitions.py
          parse.py
        bluetooth/
          hci/
            transports/
              h4.py
            parse.py
            registry.py
          __init__.py
        ieee802/
          dot11/
            analyzers/
              definitions.py
              summary.py
            dlt/
              ieee802_11/
                analyzers/
                  definitions.py
                  summary.py
                parse.py
              ieee802_11_radio/
                analyzers/
                  definitions.py
                  summary.py
                parsers/
                  radiotap_header.py
                definitions.py
                parse.py
            parsers/
              control/
                definitions.py
                parse.py
              data/
                definitions.py
                parse.py
              mac_header/
                definitions.py
                parse.py
              management/
                definitions.py
                parse.py
              body.py
              common.py
            protocol/
              wep/
                crypt.py
                definitions.py
            __init__.py
            crypt.py
            definitions.py
            parse.py
          dot1x/
            eap/
              crypt.py
              parse.py
            eapol/
              analyzers/
                summary.py
              crypt.py
              definitions.py
              parse.py
            radius/
              crypt.py
              parse.py
            __init__.py
          dot2/
            llc/
              definitions.py
              parse.py
          dot3/
            ethernet/
              analyzers/
                definitions.py
                summary.py
              dlt/
                en10mb/
                  parse.py
              parsers/
                body.py
                ethernet_header.py
              definitions.py
              parse.py
          __init__.py
          __main__.py
          registry.py
        inet/
          ip/
            analyzers/
              definitions.py
              summary.py
            dlt/
              raw/
                parse.py
            definitions.py
            parse.py
          ipsec/
            crypt.py
          tls/
            analyzers/
              definitions.py
              summary.py
            crypt.py
            definitions.py
            parse.py
          __init__.py
          registry.py
        raw/
          dlt/
            custom_a.py
            custom_b.py
        __init__.py
        registry.py
      __init__.py
      analysis.py
      crypt.py
      dissect.py
      filter_engine.py
      parsing.py
      traffic.py
    io/
      __init__.py
      io.py
      reader.py
      writer.py
    tui/
      screens/
        credentials_config.py
        dissect_config.py
        packet_editor.py
      widgets/
        fieldeditor.py
        hex_view.py
        packet_list.py
        packet_tree.py
        packettree.py
      __init__.py
      __main__.py
      app.py
      main.py
    __init__.py
    __main__.py
LICENSE
pyproject.toml
README.md
```

# Files

## File: src/pktparsers/core/dissectors/ieee802/dot11/protocol/wep/crypt.py
```python

```

## File: src/pktparsers/core/dissectors/ieee802/dot11/protocol/wep/definitions.py
```python

```

## File: src/pktparsers/core/dissectors/registry.py
```python
# pktparsers/core/registry.py

# core/registry.py — agrega tudo, mantém flat
from pktparsers.core.dissectors.ieee802 import registry as ieee802_registry
from pktparsers.core.dissectors.inet    import registry as inet_registry
from pktparsers.core.dissectors.bluetooth import registry as bt_registry
# protocolos, dlts ou padrões simples, que não possuem sub-protocolos, ou que não estão associados à nenhum domínio/família como inet ou ieee80211, são registrados diretamente na tabela, como o no caso de ARP
from pktparsers.core.dissectors.arp import parse as arp_parse
import pktparsers.core.definitions.protocol as proto
import pktparsers.core.definitions.entries as (L2, L3, L4, L7)

DISSECTORS: dict[int str, DissectorEntry] = {
    **ieee802_registry.DISSECTORS,
    **ieee802_registry.DISSECTORS,
    **inet_registry.DISSECTORS,
    **bt_registry.DISSECTORS,
    # arp diretamente aqui
    proto.ARP: DissectorEntry(
        description="Address Resolution Protocol",
        kind=PROTOCOL,
        layer=L3,
        parser=arp_parse.arp,
        config=None,
    ),
}

def get_dissector(identifier):
    if isinstance(identifier, int):
        identifier = DLTS.get(identifier)
    return DISSECTORS.get(identifier)

# used by dissectors in dissectors/raw/
def register(dissector_id: int | str, entry: DissectorEntry): # dissector_id it could be a protocol name or a DLT value.
    DISSECTORS[dissector_id] = entry
    return DISSECTORS
```

## File: src/pktparsers/tui/screens/credentials_config.py
```python
# pktparsers/tui/screens/credentials_config.py

class CredentialsConfigScreen(ModalScreen):
    """
    Modal de edição de credentials de um protocolo de autenticação.
    Gerado a partir de config["protocol"][protocol_name]["crypt"].
    """

    def __init__(self, protocol_name: str, crypt_config: dict) -> None:
        self._protocol   = protocol_name
        self._crypt_cfg  = crypt_config
        super().__init__()

    def compose(self):
        keys = self._crypt_cfg.get(CREDENTIALS, {}).get("keys", [])

        yield Label(f"Credentials — {self._protocol}")

        # Lista de keys existentes — cada uma editável/removível
        for i, key_entry in enumerate(keys):
            yield Horizontal(
                Input(value=key_entry.get("value", ""), id=f"key-value-{i}"),
                Select([(t, t) for t in self._supported_types()], value=key_entry.get("type"), id=f"key-type-{i}"),
                Button("✕", id=f"remove-{i}"),
            )

        yield Horizontal(
            Button("+ Add key",            id="btn-add-key"),
            Button("Load from capture…",   id="btn-load-capture"),
            Button("Save",                 id="btn-save"),
        )

    def _supported_types(self) -> list[str]:
        # Lido do make_config() do protocolo — sem hardcode aqui
        return self._crypt_cfg.get("supported_key_types", ["psk", "pmk", "tk"])

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-load-capture":
            # Abre FileSelector → on_file_selected chama analyze_capture_for_credentials()
            self.app.push_screen(FileSelectorScreen(callback=self._on_capture_selected))

    def _on_capture_selected(self, path: Path) -> None:
        from pktparsers.core.crypt import analyze_capture_for_credentials
        keys = analyze_capture_for_credentials(path, self._protocol)
        # Popula a lista de keys automaticamente
        self._crypt_cfg[CREDENTIALS]["keys"].extend(keys)
        self.refresh()
```

## File: src/pktparsers/tui/screens/packet_editor.py
```python
# pktparsers/tui/screens/packet_editor.py

class PacketEditorScreen(Screen):
    """
    Tela de edição de pacote bruto.
    `extra_actions` permite aplicações hospedeiras injetar widgets
    (ex: botão "Send Raw" do framesniff) sem modificar esta classe.
    """
    
    def __init__(self, parsed: dict, raw: str, extra_actions: list = None):
        self._parsed       = parsed
        self._raw          = raw
        self._extra_actions = extra_actions or []   # lista de Widgets prontos
        super().__init__()

    def compose(self):
        yield PacketTree(id="editor-tree")
        yield HexView(id="editor-hex")
        yield Horizontal(
            Button("Save", id="btn-save"),
            Button("Export", id="btn-export"),
            *self._extra_actions,          # framesniff injeta aqui
        )
```

## File: src/pktparsers/app/bootstrap.py
```python
from dataclasses import dataclass
from cli_core.deps import check_dependencies

@dataclass
class BootstrapResult:
    context: object
    operations: object

def init(config: dict) -> BootstrapResult:
    MODULE_DEPENDENCIES = config.get("module_dependencies")
    SYSTEM_DEPENDENCIES = config.get("system_dependencies")

    check_dependencies(MODULE_DEPENDENCIES, SYSTEM_DEPENDENCIES)

    from cli_core.log import setup_logging, build_logging_config

    if config.get("argparse"):
        args = config.get("argparse").get("args")
        logging_config = build_logging_config(args.verbose, args.output)
        log_filepath = setup_logging(logging_config=logging_config)
    else:
        log_filepath = setup_logging(verbose=True, output_fullpath="pktparsers-debug.log")

    from pktparsers.app.context import AppContext
    from pktparsers.app.app import Operations

    config["log_filepath"] = log_filepath

    context = AppContext(config)
    operations = Operations(context)

    return BootstrapResult(context, operations)
```

## File: src/pktparsers/cli/__init__.py
```python

```

## File: src/pktparsers/cli/__main__.py
```python
from pktparsers.cli.main import main
main()
```

## File: src/pktparsers/common/__init__.py
```python

```

## File: src/pktparsers/core/definitions/dlt.py
```python
DLT_EN10MB = 1
DLT_ATM_RFC1483 = 11
DLT_RAW = 12
DLT_HDLC = 104
DLT_IEEE802_11_RADIO = 127
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_BLUETOOTH_HCI_H4 = 187
DLT_BLUETOOTH_HCI_H4_PHDR = 201
```

## File: src/pktparsers/core/definitions/entries.py
```python
from dataclasses import dataclass

@dataclass
class DissectorEntry:
    kind: str
    credentials_extractor: callable
    address_extractor: callable
    name: str
    parser: Callable
    layer: str
    description: str
    summarizer: Callable | None = None
    analyzer: Callable | None = None
    encryptor: Callable | None = None
    decryptor: Callable | None = None
    config: dict | None = None

CRYPT  = "crypt"
PARSE  = "parse"
GLOBAL = "global"
ANALYSIS = "analysis"
PROTOCOL = "protocol"
DLT = "dlt"

L2 = "l2"
L3 = "l3"
L4 = "l4"
L7 = "l7"
```

## File: src/pktparsers/core/definitions/erf.py
```python
from .definitions.dlt import *

ERF_TYPE_LEGACY  = 0
ERF_TYPE_HDLC_POS = 2
ERF_TYPE_ETH = 3
ERF_TYPE_ATM = 4
ERF_TYPE_AAL5 = 5
ERF_TYPE_MC_HDLC = 7
ERF_TYPE_MC_RAW = 8
ERF_TYPE_MC_ATM = 9
ERF_TYPE_MC_AAL5 = 10
ERF_TYPE_COLOR_HDLC_POS = 16
ERF_TYPE_COLOR_ETH = 17
ERF_TYPE_MC_AAL2 = 19
ERF_TYPE_IP_COUNTER = 20
ERF_TYPE_IPV4 = 21
ERF_TYPE_IPV6 = 22
ERF_TYPE_RESERVED_23 = 23
ERF_TYPE_RAW_LINK = 24
ERF_TYPE_INFINIBAND = 25
ERF_TYPE_IPC = 26
ERF_TYPE_TUNNEL_IP = 27
ERF_TYPE_CLASSIFICATION = 28
ERF_TYPE_PASSIVE_CONTAINER = 29
ERF_TYPE_ETHERNET_SGMII = 30
ERF_TYPE_PROVENANCE = 31
ERF_TYPE_FIBRE_CHANNEL = 32
ERF_TYPE_I2C = 33
ERF_TYPE_LORA = 34
ERF_TYPE_COEX = 35
ERF_TYPE_GENERIC_METADATA = 36
ERF_TYPE_UTMI = 37
ERF_TYPE_MISC_METADATA = 38
ERF_TYPE_AAL5_INTERLEAVE = 39
ERF_TYPE_P2P_DECAP = 40
ERF_TYPE_EPON_ONU = 41
ERF_TYPE_EPON_OLT = 42
ERF_TYPE_EMULATED_CHANNEL = 43
ERF_EXTENSION_MASK = 0x80

ERF_TYPE_TO_DLT = {
    ERF_TYPE_HDLC_POS: DLT_HDLC,
    ERF_TYPE_ETH: DLT_EN10MB,
    ERF_TYPE_ATM: DLT_ATM_RFC1483,
    ERF_TYPE_AAL5: DLT_ATM_RFC1483,
    ERF_TYPE_MC_HDLC: DLT_HDLC,
    ERF_TYPE_MC_RAW: DLT_RAW,
    ERF_TYPE_MC_ATM: DLT_ATM_RFC1483,
    ERF_TYPE_MC_AAL5: DLT_ATM_RFC1483,
    ERF_TYPE_COLOR_HDLC_POS: DLT_HDLC,
    ERF_TYPE_COLOR_ETH: DLT_EN10MB,
    ERF_TYPE_IPV4: DLT_IPV4,
    ERF_TYPE_IPV6: DLT_IPV6,
    ERF_TYPE_RAW_LINK: DLT_RAW,
    ERF_TYPE_TUNNEL_IP: DLT_RAW,
    ERF_TYPE_ETHERNET_SGMII: DLT_EN10MB,
}
```

## File: src/pktparsers/core/definitions/protocol.py
```python
# standard: family/domain_protocolname

ARP = "arp"
IEEE802_1X =     "ieee802_1x"
IEEE802_2 =      "ieee802_2"
IEEE802_3 =      "ieee802_3"
IEEE802_11 =     "ieee802_11"
IEEE802_LLC =    "ieee802_llc"
IEE802_WAPI =    "ieee802_wapi"
IEEE802_EAPOL =  "ieee802_eapol"
IEEE802_EAP =    "ieee802_eap"
IEEE802_RADIUS = "ieee802_radius"
INET_IP =     "inet_ip"
INET_IPV4 =   "inet_ipv4"
INET_IPV6 =   "inet_ipv6"
INET_ICMP =   "inet_icmp"
INET_ICMPV6 = "inet_icmpv6"
INET_TCP =    "inet_tcp"
INET_UDP =    "inet_udp"
INET_TLS =    "inet_tls"
INET_IPSEC =  "inet_ipsec"

"""
Maybe in the future:

IEEE802_2_LLC =    "ieee802_2_llc"
IEE802_1X_WAPI = "ieee802_1x_wapi"
IEEE802_1X_EAPOL =  "ieee802_1x_eapol"
IEEE802_1X_EAP =    "ieee802_1x_eap"
IEEE802_1X_RADIUS = "ieee802_1x_radius"
"""
```

## File: src/pktparsers/core/definitions/result.py
```python
SUMMARY = "summary"
OUI = "oui"
MAC = "mac"
NAME = "name"
DESCRIPTION = "description"
PAYLOAD = "payload"
BODY = "body"
FCS = "fcs"
VENDOR = "vendor"
ADDR = "addr"
SOURCE = "src"
DESTINATION = "dst"
FLAGS = "flags"
VERSION = "version"
ASSUME_FCS = "assume_fcs"
```

## File: src/pktparsers/core/dissectors/arp/analyzers/summary.py
```python

```

## File: src/pktparsers/core/dissectors/arp/__init__.py
```python

```

## File: src/pktparsers/core/dissectors/arp/crypt.py
```python

```

## File: src/pktparsers/core/dissectors/arp/definitions.py
```python
from pktparsers.common.parse.definitions import (
    EUI48_FMT,
    IPV4_FMT,
)

HW_TYPE = "hw_type"
PROTOCOL_TYPE = "protocol_type"
HW_SIZE = "hw_size"
PROTOCOL_SIZE = "protocol_size"
OPCODE = "opcode"
SRC_MAC = "src_mac"
SRC_IP = "src_ip"
DST_MAC = "dst_mac"
DST_IP = "dst_ip"

HW_TYPE_FMT = "H"
PROTOCOL_TYPE_FMT = "H"
HW_SIZE_FMT = "B"
PROTOCOL_SIZE_FMT = "B"
OPCODE_FMT = "H"

FMT = (
    "!" +
    HW_TYPE_FMT +
    PROTOCOL_TYPE_FMT +
    HW_SIZE_FMT +
    PROTOCOL_SIZE_FMT +
    OPCODE_FMT +
    EUI48_FMT +
    IPV4_FMT +
    EUI48_FMT +
    IPV4_FMT
)
```

## File: src/pktparsers/core/dissectors/arp/parse.py
```python
import socket
from logging import getLogger
from pktparsers.core.parsing import unpack
from pktparsers.core.dissectors.arp.definitions import *

logger = getLogger(__name__)

def arp(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        (
            hw_type,
            proto_type,
            hw_size,
            proto_size,
            opcode,
            src_mac,
            src_ip,
            dst_mac,
            dst_ip,
        ) = value

        return {
            HW_TYPE: hw_type,
            PROTOCOL_TYPE: proto_type,
            HW_SIZE: hw_size,
            PROTOCOL_SIZE: proto_size,
            OPCODE: opcode,
            SRC_MAC: src_mac,
            SRC_IP: socket.inet_ntoa(src_ip),
            DST_MAC: dst_mac,
            DST_IP: socket.inet_ntoa(dst_ip),
        }

    return unpack(FMT, parser=_parser)
```

## File: src/pktparsers/core/dissectors/bluetooth/hci/transports/h4.py
```python

```

## File: src/pktparsers/core/dissectors/bluetooth/hci/parse.py
```python

```

## File: src/pktparsers/core/dissectors/bluetooth/hci/registry.py
```python

```

## File: src/pktparsers/core/dissectors/bluetooth/__init__.py
```python

```

## File: src/pktparsers/core/dissectors/ieee802/dot11/analyzers/definitions.py
```python
# core/layers/l2/ieee802/dot11/analyzers/definitions.py
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/analyzers/summary.py
```python
# dot11/analyzers/summary.py

from pktparsers.core.definitions.protocol import IEEE802_11
from pktparsers.core.definitions.analysis import  (RELATIONSHIPS, ANNOTATIONS)
from pktparsers.core.dissectors.ieee802.dot11.analyzers.definitions import (ROLE, SSIDS, CHANNELS_SEEN, FRAMES_SENT, FRAMES_RECEIVED, RETRY_COUNT)

def make_dot11_device(role: str = UNKNOWN, ) -> dict: # precisa receber os argumentos para montar o dict
    return {
        ROLE: role,
        SSIDS: [],
        CHANNELS_SEEN: [],
        FRAMES_SENT: 0,
        FRAMES_RECEIVED: 0,
        RETRY_COUNT: 0,
        RELATIONSHIPS: {}, # {peer_mac: {"sent": int, "recv": int, "retry": int}}
        ANNOTATIONS: {}
    }

def summarizer(parsed: dict): # dot11 parse result dict
    summary = {} 
    pass

def analyzer(parsed: dict, summary: dict):
    dot11_device = {}
    dot11_device_annotations = {}
    traffic_ctx = TrafficContext.current()
    traffic_summary = traffic_ctx.summary
    summary = summary or dot11.get(SUMMARY)
    pass
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/dlt/ieee802_11/analyzers/definitions.py
```python

```

## File: src/pktparsers/core/dissectors/ieee802/dot11/dlt/ieee802_11/analyzers/summary.py
```python

```

## File: src/pktparsers/core/dissectors/ieee802/dot11/dlt/ieee802_11/parse.py
```python
def parse(frame: bytes, offset: int = 0) -> dict:
    with ParseContext(frame, offset) as ctx:
        insert_item(ctx.result, "rt_hdr", radiotap_header.parser())

        rt_hdr = ctx.result.get("rt_hdr")

        if not rt_hdr:
            return ctx.result

        rt_flags = rt_hdr.get("parsed", {}).get("flags", {})

        if rt_flags.get("bad_fcs"):
            return ctx.result

        dot11.parse()

        return ctx.result

def make_config(assume_fcs: bool = True)
    return {
        "assume_fcs": True,
    }
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/dlt/ieee802_11_radio/analyzers/definitions.py
```python

```

## File: src/pktparsers/core/dissectors/ieee802/dot11/dlt/ieee802_11_radio/analyzers/summary.py
```python
# dlt/ieee802_11_radio/analyzers/summary.py
from pktparsers.core.traffic.context import TrafficContext
from pktparsers.core.dissectors.ieee802.dot11.dlt.ieee802_11_radio.definitions import RT_HDR
from pktparsers.core.dissectors.definitions.parsing import SUMMARY

def summarize(parsed: dict): # recebe ctx.result[RT_HDR] de ParseContext para gerar summary.
    rt_hdr_summary = "radiotap header summary"
    summary = {} 
    return summary

def analyzer(parsed: dict, summary: dict): # Analisa o resultado de parse e o summary, chama a função analyzer: e obtém as informações necessárias para criar ou atualizar as variáveis de TrafficSummary, muitas vezes, ela analisará as próprias variáveis de TrafficSummary antes de criar ou atualizar as variáveis de TrafficSummary.
    # ... lógica de criar/atualizar DeviceEntry em traffic
    traffic_ctx = TrafficContext.current()
    traffic_summary = traffic_ctx.summary
    summary = summary or dot11.get(SUMMARY)
    rt_hdr_summary = summary or summarizer.get(RT_HDR)
    pass
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/dlt/ieee802_11_radio/parsers/radiotap_header.py
```python
from logging import getLogger
from pktparsers.core.parsing import (
    ParseContext, unpack, bitmap_value_for_dict, freq_to_channel, fail
)
from pktparsers.core.dissectors.ieee802.dot11.dlt.ieee802_11_radio.definitions import (BAD_FCS)

logger = getLogger(__name__)

def _parse_flags(value):
    return {'flags': bitmap_value_for_dict(value, [
        'cfp', 'preamble', 'wep', 'fragmentation',
        'fcs_at_end', 'data_pad', 'bad_fcs', 'short_gi'
    ])}

def _parse_channel(value):
    freq, flags_val = value
    channel_flags = bitmap_value_for_dict(flags_val, [
        None, None, None, None,           # bits 0-3 reserved
        'turbo', 'cck', 'ofdm', '2ghz',
        '5ghz', 'passive', 'dynamic_cck_ofdm', 'gfsk',
        'gsm', 'static_turbo', 'half_rate', 'quarter_rate'
    ])
    return {
        'channel_freq': freq,
        'channel': freq_to_channel(freq),
        'channel_flags': channel_flags
    }

def _parse_fhss(value):
    hop_set, hop_pattern = value
    return {'fhss': {'hop_set': hop_set, 'hop_pattern': hop_pattern}}

def _parse_rx_flags(value):
    return {'rx_flags': bitmap_value_for_dict(value, [
        'bad_plcp', None, None, None, None, None, None, None,
        None, None, None, None, None, None, None, None
        # rx_flags: only bit 1 (bad_plcp) defined by spec; rest reserved
        # keeping as full 16-bit map for forward compatibility
    ])}

def _parse_tx_flags(value):
    return {'tx_flags': bitmap_value_for_dict(value, [
        'fail', 'cts', 'rts', 'no_ack', 'no_seq', None, None, None,
        None, None, None, None, None, None, None, None
    ])}

def _parse_mcs(value):
    known, flags_val, mcs_index = value
    known_bits = bitmap_value_for_dict(known, [
        'bandwidth', 'mcs_index', 'guard_interval', 'ht_format',
        'fec_type', 'stbc_streams', 'ness', 'ness_bit_1'
    ])
    flags_bits = bitmap_value_for_dict(flags_val, [
        'bandwidth_0', 'bandwidth_1', 'guard_interval', 'ht_format',
        'fec_type', 'stbc_stream_0', 'stbc_stream_1', 'ness_bit_0'
    ])
    bw_map = {0: 20, 1: 40, 2: '20L', 3: '20U'}
    raw_bw = flags_val & 0x03
    return {'mcs': {
        'known': known_bits,
        'flags': flags_bits,
        'index': mcs_index,
        'bandwidth_mhz': bw_map.get(raw_bw) if known_bits.get('bandwidth') else None,
        'guard_interval_ns': 400 if (flags_val & 0x04) else 800,
        'ht_format': 'greenfield' if (flags_val & 0x08) else 'mixed',
        'fec': 'ldpc' if (flags_val & 0x10) else 'bcc',
        'stbc_streams': (flags_val >> 5) & 0x03,
    }}

def _parse_ampdu_status(value):
    ref_num, flags_val, delim_crc, reserved = value
    flags_bits = bitmap_value_for_dict(flags_val, [
        'report_zerolen', 'is_zerolen', 'last_known', 'is_last',
        'delim_crc_err', 'delim_crc_known', None, None,
        None, None, None, None, None, None, None, None
    ])
    return {'ampdu_status': {
        'reference_num': ref_num,
        'flags': flags_bits,
        'delimiter_crc_value': delim_crc,
        'reserved': reserved
    }}

def _parse_vht(value):
    (known, flags_val, bandwidth,
     mcs_nss1, mcs_nss2, mcs_nss3, mcs_nss4,
     coding, group_id, partial_aid) = value

    known_bits = bitmap_value_for_dict(known, [
        'stbc', 'txop_ps_not_allowed', 'guard_interval', 'sgi_nsym_da',
        'ldpc_extra_symbol', 'beamformed', 'bandwidth', 'group_id', 'partial_aid',
        None, None, None, None, None, None, None
    ])

    def _decode_mcs_nss(raw):
        if raw == 0:
            return None
        return {'nss': raw & 0x0F, 'mcs': (raw >> 4) & 0x0F}

    coding_streams = [
        'ldpc' if (coding >> i) & 1 else 'bcc'
        for i in range(4)
    ]

    bw_map = {
        0: '20', 1: '40', 2: '80', 3: '80+80_or_160',
        4: '20L', 5: '20U', 6: '40L', 7: '40U',
        8: '80L', 9: '80U', 10: '80+80L', 11: '80+80U'
    }

    return {'vht': {
        'known': known_bits,
        'stbc': bool(flags_val & 0x01),
        'txop_ps_not_allowed': bool(flags_val & 0x02),
        'guard_interval': 'short' if (flags_val & 0x04) else 'long',
        'sgi_nsym_disambiguation': bool(flags_val & 0x08),
        'ldpc_extra_ofdm_symbol': bool(flags_val & 0x10),
        'beamformed': bool(flags_val & 0x20),
        'bandwidth': bw_map.get(bandwidth, f'unknown({bandwidth})'),
        'bandwidth_raw': bandwidth,
        'mcs_nss': [_decode_mcs_nss(x) for x in (mcs_nss1, mcs_nss2, mcs_nss3, mcs_nss4)],
        'coding': coding_streams,
        'group_id': group_id,
        'partial_aid': partial_aid,
    }}

def _parse_timestamp(value):
    ts_val, ts_accuracy, ts_unit_pos, ts_flags = value
    unit_map = {
        0: 'ms', 1: 'us', 2: 'ns', 3: '10ns',
        4: '100ns', 5: '500ns', 6: '1us', 7: '10us'
    }
    return {'timestamp': {
        'value': ts_val,
        'accuracy': ts_accuracy,
        'unit': unit_map.get(ts_unit_pos & 0x0F, f'unknown({ts_unit_pos & 0x0F})'),
        'sample_offset': (ts_unit_pos >> 4) & 0x0F,
        'flags': {
            'accuracy_known': bool(ts_flags & 0x01),
            'known': bool(ts_flags & 0x02),
        }
    }}

def _parse_he(value):
    return {'he': {i + 1: v for i, v in enumerate(value)}}

def _parse_he_mu(value):
    flags1, flags2, ru_ch1_0, ru_ch1_1, ru_ch1_2, ru_ch1_3, ru_ch2_0, ru_ch2_1, ru_ch2_2, ru_ch2_3 = value
    return {'he_mu': {
        'flags1': flags1, 'flags2': flags2,
        'ru_channel1': [ru_ch1_0, ru_ch1_1, ru_ch1_2, ru_ch1_3],
        'ru_channel2': [ru_ch2_0, ru_ch2_1, ru_ch2_2, ru_ch2_3],
    }}

RADIOTAP_FIELDS = [
    # bit  name                   fmt              align  parser
    (0,  "tsft",               "<Q",           8,  lambda v, **_: {"tsft": v}),
    (1,  "flags",              "<B",           1,  lambda v, **_: _parse_flags(v)),
    (2,  "rate",               "<B",           1,  lambda v, **_: {"rate_mbps": v * 0.5}),
    (3,  "channel",            "<HH",          2,  lambda v, **_: _parse_channel(v)),
    (4,  "fhss",               "<BB",          1,  lambda v, **_: _parse_fhss(v)),
    (5,  "dbm_antenna_signal", "<b",           1,  lambda v, **_: {"dbm_antenna_signal": v}),
    (6,  "dbm_antenna_noise",  "<b",           1,  lambda v, **_: {"dbm_antenna_noise": v}),
    (7,  "lock_quality",       "<H",           2,  lambda v, **_: {"lock_quality": v}),
    (8,  "tx_attenuation",     "<H",           2,  lambda v, **_: {"tx_attenuation": v}),
    (9,  "db_tx_attenuation",  "<H",           2,  lambda v, **_: {"db_tx_attenuation": v}),
    (10, "dbm_tx_power",       "<b",           1,  lambda v, **_: {"dbm_tx_power": v}),
    (11, "antenna",            "<B",           1,  lambda v, **_: {"antenna": v}),
    (12, "db_antenna_signal",  "<B",           1,  lambda v, **_: {"db_antenna_signal": v}),
    (13, "db_antenna_noise",   "<B",           1,  lambda v, **_: {"db_antenna_noise": v}),
    (14, "rx_flags",           "<H",           2,  lambda v, **_: _parse_rx_flags(v)),
    (15, "tx_flags",           "<H",           2,  lambda v, **_: _parse_tx_flags(v)),
    (16, "rts_retries",        "<B",           1,  lambda v, **_: {"rts_retries": v}),
    (17, "data_retries",       "<B",           1,  lambda v, **_: {"data_retries": v}),
    # bit 18: XChannel (obsolete Atheros extension, skip)
    (19, "mcs",                "<BBB",         1,  lambda v, **_: _parse_mcs(v)),
    (20, "ampdu_status",       "<IHBB",        4,  lambda v, **_: _parse_ampdu_status(v)),
    (21, "vht",                "<HBBBBBBBBxH", 2,  lambda v, **_: _parse_vht(v)),
    (22, "timestamp",          "<QHBB",        8,  lambda v, **_: _parse_timestamp(v)),
    # bits 23–28: HE, HE-MU, HE-MU other user, 0-length PSDU, L-SIG, TLV
    (23, "he",                 "<HHHHHH",      2,  lambda v, **_: _parse_he(v)),
    (24, "he_mu",              "<HHBBBBBBBB",  2,  lambda v, **_: _parse_he_mu(v)),
    # bits 25-28 omitted (rare / very new)
]

_FIELD_BY_BIT = {bit: (name, fmt, align, pfunc) for bit, name, fmt, align, pfunc in RADIOTAP_FIELDS}

def parse(**kwargs) -> dict:
    def _parser(value: tuple, **kwargs) -> dict:
        ctx = ParseContext.current()
        frame_len = len(ctx.frame)
        rth_version, rth_pad, rth_length = value

        result = {
            "version": rth_version,
            "pad": rth_pad,
            "length": rth_length,
        }

        if rth_version != 0 or rth_length > frame_len:
            logger.debug(f"Radiotap: invalid header ver={rth_version} len={rth_length} frame_len={frame_len}")
            return fail(result, rth_length, "Invalid radiotap header")

        present_bitmaps = {}
        combined_present = 0

        try:
            for word_index in range(32):
                present_data = unpack("<I", parser=lambda v, **kw: v)
                word_val = present_data["parsed"]
                present_bitmaps[word_index] = word_val

                combined_present |= (word_val & 0x7FFFFFFF)

                if not (word_val & (1 << 31)):
                    break

        except Exception as e:
            logger.debug(f"Radiotap: error reading present bitmaps: {e}")
            result["present_bitmaps"] = present_bitmaps
            return fail(result, rth_length, "Invalid radiotap header")

        result["present_bitmaps"] = present_bitmaps

        for bit_index in range(29):
            if not (combined_present & (1 << bit_index)):
                continue
            if bit_index not in _FIELD_BY_BIT:
                logger.debug(f"Radiotap: unknown bit {bit_index} at offset {ctx.offset}, stopping")
                break
              
            name, fmt, alignment, pfunc = _FIELD_BY_BIT[bit_index]

            try:
                if alignment > 1:
                    pad = (alignment - (ctx.offset % alignment)) % alignment
                    ctx.offset += pad

                field_result = unpack(fmt, parser=pfunc)

                if pfunc is None:
                    result[name] = field_result["value"]
                else:
                    result.update(field_result["parsed"])
            except Exception as e:
                logger.debug(
                    f"Radiotap: error parsing field bit={bit_index} name={name}: {e}"
                )
                break

        ctx.offset = min(rth_length, frame_len)
        return result

    result = {}

    try:
        result = unpack("<BBH", parser=_parser)
    except Exception as e:
        logger.debug(f"Parser radiotap header error: {e}")

    return result
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/dlt/ieee802_11_radio/definitions.py
```python
from .parse import make_config as parse_config
from .crypt import make_config as crypt_config
from .analyzers import make_config as analysis_config

BAD_FCS = "bad_fcs"
RT_HDR = "rt_hdr"

CONFIG = {
    PARSE: parse_config(),
    CRYPT: crypt_config(),
    ANALYSIS: analysis_config()
}
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/dlt/ieee802_11_radio/parse.py
```python
from logging import getLogger
from pktparsers.core.dissectors.ieee802.dot11.parse import parse_dot11
from pktparsers.core.dissectors.ieee802.dot11.dlt.ieee802_11_radio.definitions import (BAD_FCS, RT_HDR, INCLUDE_RADIOTAP_RAW)
from pktparsers.core.definitions.parsing import (FLAGS, SUMMARY, PARSED, ASSUME_FCS)

logger = getLogger(__name__)

def parse() -> dict:
    logger.debug("Frame parse")
    ctx = ParseContext.current()
    insert_item(ctx.result, RT_HDR, radiotap_header.parser())
    rt_hdr = ctx.result.get(RT_HDR)
    if not rt_hdr:
        logger.debug("Unexpected radiotap header error")
        return ctx.result
    rt_flags = rt_hdr.get(PARSED, {}).get(FLAGS, {})
    bad_fcs = rt_flags.get(BAD_FCS)
    if bad_fcs:
        logger.debug(f"Dropping frame: {BAD_FCS} indicated by radiotap")
        return ctx.result
    parse_dot11()
    if traffic_ctx:
        summary = summarizer(ctx.result[RT_HDR))
        insert_item(ctx.result[RT_HDR], SUMMARY, summary)
        analyzer(ctx.result[RT_HDR], summary)
    return ctx.result

def make_config(assume_fcs: bool = False, include_radiotap_raw: bool = False):
    return {
        ASSUME_FCS: assume_fcs,
        INCLUDE_RADIOTAP_RAW: include_radiotap_raw,
    }
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/parsers/control/definitions.py
```python
BLOCK_ACK_REQUEST = 8
BLOCK_ACK = 9
PS_POLL = 10
RTS = 11
CTS = 12
ACK = 13
CF_END = 14
CF_END_ACK = 15

SUBTYPES_NAMES = {
    BLOCK_ACK_REQUEST: "Block Ack Request",
    BLOCK_ACK: "Block Ack",
    PS_POLL: "PS-Poll",
    RTS: "RTS",
    CTS: "CTS",
    ACK: "ACK",
    CF_END: "CF-End",
    CF_END_ACK: "CF-End+CF-Ack",
}
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/parsers/control/parse.py
```python
from core.core.parsing import (unpack, run_dispatch)
from core.dissectors.ieee802.dot11.parsers.control import definitions as ctrl_defs
from core.dissectors.ieee802.dot11.parsers.mac_hdr import definitions as mac_hdr_defs

def ctrl_block_ack_request(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        ctrl, start_seq = value
        return {
            ctrl_defs.BLOCK_ACK_CTRL: ctrl,
            ctrl_defs.BLOCK_ACK_START_SEQ: start_seq
        }
    return unpack("<HH", parser=_parser)

def ctrl_block_ack(**kwargs) -> dict:
    return unpack("<Q", parser=lambda v: {ctrl_defs.BLOCK_ACK_BITMAP: v})

def ctrl_ps_poll(**kwargs) -> dict:
    return unpack("<H", parser=lambda v: {ctrl_defs.AID: v & 0x3FFF})

def ctrl_ack(**kwargs) -> dict:
    return unpack()

def ctrl_cf_end(**kwargs) -> dict:
    return unpack()

def ctrl_cf_end_ack(**kwargs) -> dict:
    return unpack()

DISPATCH_TABLE = {
    ctrl_defs.BLOCK_ACK_REQUEST: ctrl_block_ack_request,
    ctrl_defs.BLOCK_ACK: ctrl_block_ack,
    ctrl_defs.PS_POLL: ctrl_ps_poll,
    ctrl_defs.ACK: ctrl_ack,
    ctrl_defs.CF_END: ctrl_cf_end,
    ctrl_defs.CF_END_ACK: ctrl_cf_end_ack,
}

def parser(**kwargs):
    return run_dispatch(DISPATCH_TABLE, kwargs.get(mac_hdr_defs.SUBTYPE))
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/parsers/data/definitions.py
```python
DATA = 0
DATA_CF_ACK = 1
DATA_CF_POLL = 2
DATA_CF_ACK_CF_POLL = 3
NULL = 4
CF_ACK = 5
CF_POLL = 6
CF_ACK_CF_POLL = 7
QOS_DATA = 8
QOS_DATA_CF_ACK = 9
QOS_DATA_CF_POLL = 10
QOS_DATA_CF_ACK_CF_POLL = 11
QOS_NULL = 12
RESERVED = 13
QOS_CF_POLL = 14
QOS_CF_ACK_CF_POLL = 15

NULL_DATA_SUBTYPES = [
    NULL,
    CF_ACK,
    CF_POLL,
    CF_ACK_CF_POLL,
    QOS_NULL,
    RESERVED,
    QOS_CF_POLL,
    QOS_CF_ACK_CF_POLL
]

SUBTYPES_NAMES = {
    DATA: "Data",
    DATA_CF_ACK: "Data+CF-Ack",
    DATA_CF_POLL: "Data+CF-Poll",
    DATA_CF_ACK_CF_POLL: "Data+CF-Ack+CF-Poll",
    NULL: "Null",
    CF_ACK: "CF-Ack",
    CF_POLL: "CF-Poll",
    CF_ACK_CF_POLL: "CF-Ack+CF-Poll",
    QOS_DATA: "QoS Data",
    QOS_DATA_CF_ACK: "QoS Data+CF-Ack",
    QOS_DATA_CF_POLL: "QoS Data+CF-Poll",
    QOS_DATA_CF_ACK_CF_POLL: "QoS Data+CF-Ack+CF-Poll",
    QOS_NULL: "QoS Null",
    RESERVED: "Reserved",
    QOS_CF_POLL: "QoS CF-Poll",
    QOS_CF_ACK_CF_POLL: "QoS CF-Ack+CF-Poll",
}
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/parsers/data/parse.py
```python
from logging import getLogger
from core.dissectors.ieee802.dot2.llc.parse import parse as llc_parse
from core.dissectors.ieee802.dot2.llc import definitions as llc_defs
from core.dissectors.ieee802.dot11.mac_header import definitions as mac_hdr_defs
from core.dissectors.ieee802.dot11.parsers.data import definitions as data_defs

logger = getLogger(__name__)

def parser(**kwargs) -> dict:
    subtype = kwargs.get(mac_hdr_defs.SUBTYPE)
    logger.debug(f"DATA Parser - Subtype: {subtype}")
    
    body = {}

    if subtype in data_defs.NULL_DATA_SUBTYPES:
        logger.debug("Null Data frame detected: skipping LLC parser")
        return body
    
    try:
        body[llc_defs.LLC] = llc_parser()
    except Exception as e:
        logger.warning(f"Could not parse LLC on data frame: {e}")
    
    return body
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/parsers/mac_header/definitions.py
```python
FC = "fc"
PROTOCOL_VERSION = "protocol_version"
TYPE = "type"
TYPE_NAME = "type_name"
SUBTYPE = "subtype"
SUBTYPE_NAME = "subtype_name"
TO_DS = "tods"
FROM_DS = "fromds"
PROTECTED = "protected"
DURATION_ID = "duration_id"
RA = "ra"
TA = "ta"
SA = "sa"
DA = "da"
SEQUENCE_NUMBER = "sequence_number"
QOS_CONTROL = "qos_control"
BSSID = "bssid"

DURATION_FMT = "<H"
FS_FMT = "<H"
QOS_CONTROL_FMT = "<H"
FC_FMT = "<H"
FMT = FC_FMT
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/parsers/mac_header/parse.py
```python
from logging import getLogger
from pktparsers.core.parsing import (unpack, read_mac)
from pkparsers.core.dissectors.ieee802.dot11.parsers.mac_header.definitions import *
from pkparsers.core.dissectors.ieee802.dot11.definitions import dot11_defs
from pktparsers.core.dissectors.ieee802.dot11.parsers.management import definitions as mgmt_defs
from pktparsers.core.dissectors.ieee802.dot11.parsers.control import definitions as ctrl_defs
from pktparsers.core.dissectors.ieee802.dot11.parsers.data import definitions as data_defs

logger = getLogger(__name__)

def parse(**kwargs) -> dict:
    logger.debug("MAC Header parse")

    def _parser(fc_val: int, **k) -> dict:
        protocol_version = fc_val & 0b11
        ftype = (fc_val >> 2) & 0b11
        fsubtype = (fc_val >> 4) & 0b1111
        to_ds = (fc_val >> 8) & 1
        from_ds = (fc_val >> 9) & 1
        protected = bool(fc_val & 0x4000)
        
        type_name = dot11_defs.FRAME_TYPES.get(ftype)
        subtype_name = dot11_defs.FRAME_SUBTYPES.get(ftype, {}).get(fsubtype)
        is_qos = ftype == dot11_defs.DATA and bool(fsubtype & 0b1000)

        duration = unpack(DURATION_FMT)
        
        addr1 = read_mac()
        
        addr2 = addr3 = addr4 = fs = qos = None

        if ftype == dot11_defs.CTRL:
            if fsubtype in (ctrl_defs.BLOCK_ACK_REQUEST, ctrl_defs.BLOCK_ACK, ctrl_defs.PS_POLL, 
                             ctrl_defs.RTS, ctrl_defs.CF_END, ctrl_defs.CF_END_ACK):
                addr2 = read_mac() 
        else:
            addr2 = read_mac() 
            addr3 = read_mac() 
            fs = unpack(FS_FMT, parser=lambda v, **k: v >> 4) # fragment number + sequence number

            if to_ds and from_ds:
                addr4 = read_mac() 

        ra = addr1
        ta = addr2 if addr2 else None
        a3 = addr3 if addr3 else None
        a4 = addr4 if addr4 else None

        sa = da = bssid = None
        if to_ds == 0 and from_ds == 0:
            sa, da, bssid = ta, ra, a3
        elif to_ds == 0 and from_ds == 1:
            sa, da, bssid = a3, ra, ta
        elif to_ds == 1 and from_ds == 0:
            sa, da, bssid = ta, a3, ra
        elif to_ds == 1 and from_ds == 1:
            sa, da, bssid = a4, a3, None

        # QoS Control
        if is_qos:
            qos = unpack(QOS_CONTROL_FMT)

        return {
            FC: {
                PROTOCOL_VERSION: protocol_version,
                TYPE: ftype,
                TYPE_NAME: type_name,
                SUBTYPE: fsubtype,
                SUBTYPE_NAME: subtype_name,
                TO_DS: to_ds,
                FROM_DS: from_ds,
                PROTECTED: protected,
            },
            DURATION_ID: duration,
            RA: ra,
            TA: ta,
            SA: sa,
            DA: da,
            BSSID: bssid,
            SEQUENCE_NUMBER: fs,
            QOS_CONTROL: qos,
        }

    result = {}

    try:
        result = unpack(FMT, parser=_parser)
    except Exception as e:
        logger.debug(f"MAC Header parser error: {e}")

    return result
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/parsers/management/definitions.py
```python
ASSOCIATION_REQUEST = 0
ASSOCIATION_RESPONSE = 1
REASSOCIATION_REQUEST = 2
REASSOCIATION_RESPONSE = 3
PROBE_REQUEST = 4
PROBE_RESPONSE = 5
TIMING_ADVERTISEMENT = 6
BEACON = 8
ATIM = 9
DISASSOCIATION = 10
AUTHENTICATION = 11
DEAUTHENTICATION = 12
ACTION = 13
ACTION_NO_ACK = 14

SUBTYPES_NAMES = {
    ASSOCIATION_REQUEST: "Association Request",
    ASSOCIATION_RESPONSE: "Association Response",
    REASSOCIATION_REQUEST: "Reassociation Request",
    REASSOCIATION_RESPONSE: "Reassociation Response",
    PROBE_REQUEST: "Probe Request",
    PROBE_RESPONSE: "Probe Response",
    TIMING_ADVERTISEMENT: "Timing Advertisement",
    BEACON: "Beacon",
    ATIM: "ATIM",
    DISASSOCIATION: "Disassociation",
    AUTHENTICATION: "Authentication",
    DEAUTHENTICATION: "Deauthentication",
    ACTION: "Action",
    ACTION_NO_ACK: "Action No Ack",
}
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/parsers/management/parse.py
```python
from pktparsers.core.parsing import (ParseContext, unpack, run_dispatch)
from pktparsers.core.definitions.parsing import BODY
from pktparsers.core.dissectors.ieee802.dot11.parsers.common import (fixed_parameters, tagged_parameters)
from pktparsers.core.dissectors.ieee802.dot11.definitions import (FIXED_PARAMETERS, TAGGED_PARAMETERS, REASON_CODE, AID, AUTH_ALGORITHM, AUTH_SEQUENCE, STATUS_CODE, ACTION, CATEGORY, SUBTYPE)

def mgmt_beacon(**kwargs) -> dict:
    fp = fixed_parameters()
    tp = tagged_parameters()
    return {
        FIXED_PARAMETERS: fp,
        TAGGED_PARAMETERS: tp
    }

def mgmt_probe_response(**kwargs) -> dict:
    fp = fixed_parameters()
    tp = tagged_parameters()
    return {
        FIXED_PARAMETERS: fp,
        TAGGED_PARAMETERS: tp
    }

def mgmt_atim(**kwargs) -> dict:
    return unpack("<H", parser=lambda v: {AID: v & 0x3FFF})

def mgmt_disassociation(**kwargs) -> dict:
    return unpack("<H", parser=lambda v: {REASON_CODE: v})

def mgmt_deauthentication(**kwargs) -> dict:
    return mgmt_disassociation()

def mgmt_authentication(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        alg, seq, status = value
        
        ctx = ParseContext.current()

        res = {
            AUTH_ALGORITHM: alg,
            AUTH_SEQUENCE: seq,
            STATUS_CODE: status,
        }

        if ctx.offset < len(ctx.frame):
            res[TAGGED_PARAMETERS] = tagged_parameters()
            
        return res

    return unpack("<HHH", parser=_parser)

def mgmt_action(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        cat, act = value
        ctx = ParseContext.current()
        
        res = {"category": cat, "action": act}
        
        remaining = len(ctx.frame) - ctx.offset
        if remaining > 0:
            res["body"] = unpack(f"{remaining}s")
        
        return res
    return unpack("BB", parser=_parser)

DISPATCH_TABLE = {
    MGMT_BEACON: mgmt_beacon,
    MGMT_PROBE_RESPONSE: mgmt_probe_response,
    MGMT_ATIM: mgmt_atim,
    MGMT_DISASSOCIATION: mgmt_disassociation,
    MGMT_DEAUTHENTICATION: mgmt_deauthentication,
    MGMT_AUTHENTICATION: mgmt_authentication,
    MGMT_ACTION: mgmt_action
}

def parser(**kwargs):
    return run_dispatch(DISPATCH_TABLE, kwargs.get("subtype"))
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/parsers/body.py
```python
# pktparsers/core/layers/l2/ieee802/dot11/parsers/body.py
from logging import getLogger
from pktparsers.core.parsing import ParseContext, unpack, run_dispatch
from pktparsers.core.filter_engine import get_nested
from pktparsers.core.dissectors.ieee802.dot11.parsers import management, control, data
from pktparsers.core.dissectors.ieee802.dot11.definitions import *
from pktparsers.core.dissectors.ieee802.dot11.parsers.mac_header import definitions as mac_hdr_defs
from pktparsers.core.definitions.protocol import IEEE802_11

logger = getLogger(__name__)

BODY_DISPATCH = {
    MGMT: management.parser,
    CTRL: control.parser,
    DATA: data.parser,
}

def parser(**kwargs):
    result = {}
    ctx = ParseContext.current()
    fc = get_nested(f"{IEEE802_11}.{mac_hdr_defs.MAC_HDR}.{mac_hdr_defs.FC}", ctx.result)
    logger.debug(f"{mac_hdr_defs.FC}={fc}") 
    frame_type = fc.get(mac_hdr_defs.TYPE)
    frame_subtype = fc.get(mac_hdr_defs.SUBTYPE)
    protected = fc.get(mac_hdr_defs.PROTECTED, False)
    if protected:
        return unpack()
    logger.debug(f"frametype={frame_type}") 
    try:
        result = run_dispatch(BODY_DISPATCH, frame_type, subtype=frame_subtype)
    except Exception as e:
        logger.debug(f"Body parser error: {e}")
    return result
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/parsers/common.py
```python
from logging import getLogger
from core.common.parser import (ParseContext, unpack, bitmap_value_for_dict, insert_item)
from core.layers.l2.ieee802.dot11.constants import *
from core.layers.l2.ieee802.dot11.parsers.ies import ie_dispatch

logger = getLogger(__name__)

# Parsers that can be used in both management frames and data frames

def fixed_parameters(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        ts, interval, cap_raw = value
        
        cap_list = [
            "ess_capabilities", "ibss_status", "reserved1", "reserved2",
            "privacy", "short_preamble", "critical_update_flag",
            "nontransmitted_bssid_critical_update_flag", "spectrum_management",
            "qos", "short_slot_time", "automatic_power_save_delivery",
            "radio_measurement", "epd", "reserved3", "reserved4",
        ]
        
        capabilities = bitmap_value_for_dict(cap_raw, cap_list)
        
        return {
            "timestamp": ts,
            "beacon_interval": interval,
            "capabilities_information": capabilities
        }

    result = {}

    try:
        result = unpack("<QHH", parser=_parser)
    except Exception as e:
       logger.debug(f"Parser fixed parameters error: {e}")

    return result

def tagged_parameters(value: bytes = None, **kwargs) -> dict:
    logger.debug(f"Tagged parameters parser{' (callback mode)' if value is not None else ''}")

    ies_container = {}
    ctx = ParseContext.current()
    
    if value is not None:
        limit = ctx.offset
        ctx.offset -= len(value)
    else:
        max_length = kwargs.get('max_length', 0)
        limit = (ctx.offset + max_length) if max_length else len(ctx.frame)

    while ctx.offset + MIN_IE_LEN <= limit:
        try:
            ie_entry = unpack("<BB", parser=ie_dispatch, **kwargs)
            
            parsed_data = ie_entry.get("parsed", {})
            tag_name = parsed_data.get("name") or parsed_data.get("tag_number")
            
            insert_item(ies_container, tag_name, ie_entry)
        except Exception as e:
            logger.error(f"Error parsing IE at offset {ctx.offset}: {e}")
            break

    ctx.offset = limit
    return ies_container
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/__init__.py
```python

```

## File: src/pktparsers/core/dissectors/ieee802/dot11/crypt.py
```python
# pktparsers/core/layers/l2/ieee802/dot11/crypt.py
#
# IEEE 802.11 key derivation and frame-level decryption.
#
# Responsibilities:
#   - PMK derivation (PSK/SAE)
#   - PTK/GTK derivation from handshake material
#   - CCMP decryption  (WPA2/WPA3)
#   - TKIP decryption  (WPA legacy)
#   - WEP decryption   (legacy)
#
# NOT responsible for:
#   - EAPOL MIC verification  → dot1x/eapol/crypt.py
#   - EAP / RADIUS processing → their own modules
#   - Persistent credential storage → DissectConfig.credentials
#
# All decryptors follow the calling convention expected by DltEntry.decryptor:
#   decryptor(payload: bytes, credentials: dict) -> bytes | None

import struct
import logging
from typing import Optional

from pktparsers.core.crypt import (
    pbkdf2_sha1,
    prf_sha1,
    aes_ccm_decrypt,
    rc4,
    crc32_bytes,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PMK derivation
# ---------------------------------------------------------------------------

def derive_pmk(psk: str, ssid: str) -> bytes:
    """
    WPA2/WPA3 Personal: derive PMK from passphrase + SSID.
    Result is 32 bytes (256-bit).
    """
    return pbkdf2_sha1(psk, ssid)


# ---------------------------------------------------------------------------
# PTK derivation
# ---------------------------------------------------------------------------

PTK_LABEL = "Pairwise key expansion"

# PTK field offsets (lengths in bytes)
_KCK_LEN = 16
_KEK_LEN = 16
_TK_LEN  = 16   # CCMP-128; CCMP-256 would be 32
_PTK_LEN = _KCK_LEN + _KEK_LEN + _TK_LEN  # 48 bytes for CCMP-128


def derive_ptk(
    pmk: bytes,
    anonce: bytes,
    snonce: bytes,
    bssid: bytes,
    sta_mac: bytes,
) -> bytes:
    """
    IEEE 802.11-2020 §12.7.1.3 PTK derivation.

    Args:
        pmk:     32-byte PMK (from derive_pmk or pre-shared)
        anonce:  32-byte ANonce from EAPOL msg 1/4 (Authenticator nonce)
        snonce:  32-byte SNonce from EAPOL msg 2/4 (Supplicant nonce)
        bssid:   6-byte AP MAC address
        sta_mac: 6-byte STA MAC address

    Returns:
        48-byte PTK (KCK[0:16] | KEK[16:32] | TK[32:48])
    """
    # min(AA, SPA) || max(AA, SPA) || min(ANonce, SNonce) || max(ANonce, SNonce)
    mac_min = min(bssid, sta_mac)
    mac_max = max(bssid, sta_mac)
    nonce_min = min(anonce, snonce)
    nonce_max = max(anonce, snonce)

    data = mac_min + mac_max + nonce_min + nonce_max
    return prf_sha1(pmk, PTK_LABEL, data, _PTK_LEN * 8)


def ptk_kck(ptk: bytes) -> bytes:
    return ptk[:_KCK_LEN]


def ptk_kek(ptk: bytes) -> bytes:
    return ptk[_KCK_LEN : _KCK_LEN + _KEK_LEN]


def ptk_tk(ptk: bytes) -> bytes:
    return ptk[_KCK_LEN + _KEK_LEN : _KCK_LEN + _KEK_LEN + _TK_LEN]


# ---------------------------------------------------------------------------
# CCMP (AES-CCM, WPA2/WPA3)
# ---------------------------------------------------------------------------

_CCMP_HDR_LEN = 8   # PN bytes + reserved
_CCMP_MIC_LEN = 8


def _build_ccmp_nonce(priority: int, ta: bytes, pn: bytes) -> bytes:
    """Build 13-byte CCM nonce per IEEE 802.11-2020 §12.5.3.3.3."""
    # nonce = flags(1) || A2(6) || PN5..PN0(6)
    flags = priority & 0x0F
    return bytes([flags]) + ta + pn


def _extract_ccmp_pn(ccmp_header: bytes) -> bytes:
    """Extract 6-byte PN from CCMP header (PN0..PN5, reconstructed big-endian)."""
    pn0 = ccmp_header[0]
    pn1 = ccmp_header[1]
    # byte 2 = reserved, byte 3 = key_id
    pn2 = ccmp_header[4]
    pn3 = ccmp_header[5]
    pn4 = ccmp_header[6]
    pn5 = ccmp_header[7]
    # PN in replay order is PN5..PN0
    return bytes([pn5, pn4, pn3, pn2, pn1, pn0])


def decrypt_ccmp(
    payload: bytes,
    tk: bytes,
    ta: bytes,
    priority: int = 0,
    aad: bytes = b"",
) -> Optional[bytes]:
    """
    Decrypt a CCMP-protected 802.11 MPDU body.

    Args:
        payload:  raw bytes starting at the CCMP header (after MAC header)
        tk:       16-byte Temporal Key (ptk_tk(ptk))
        ta:       6-byte Transmitter Address (addr2 from MAC header)
        priority: QoS priority (0 for non-QoS frames)
        aad:      Additional Authenticated Data (MAC header bytes, caller-supplied)

    Returns:
        Decrypted plaintext, or None on failure.
    """
    if len(payload) < _CCMP_HDR_LEN + _CCMP_MIC_LEN:
        logger.debug("CCMP: payload too short")
        return None

    ccmp_hdr = payload[:_CCMP_HDR_LEN]
    ciphertext_and_mic = payload[_CCMP_HDR_LEN:]

    pn = _extract_ccmp_pn(ccmp_hdr)
    nonce = _build_ccmp_nonce(priority, ta, pn)

    return aes_ccm_decrypt(tk, nonce, ciphertext_and_mic, aad)


# ---------------------------------------------------------------------------
# TKIP (RC4 + Michael MIC, WPA1)
# ---------------------------------------------------------------------------

def _tkip_phase1(tk: bytes, ta: bytes, tsc_msb: int) -> list[int]:
    """TKIP Phase 1 key mixing."""
    # tk[0:16] for encryption, tk[16:24] for Tx MIC, tk[24:32] for Rx MIC
    p1k = [0] * 5
    tsc_i = (tsc_msb >> 16) & 0xFFFF
    tsc_i2 = tsc_msb & 0xFFFF

    s = lambda a, b: (a + b) & 0xFFFF
    xor = lambda a: a ^ (a >> 8)

    # Simplified TKIP phase 1 — for full production code use a reference impl
    # This is a structural placeholder aligned with the crypt module pattern
    ta_words = [
        (ta[1] << 8) | ta[0],
        (ta[3] << 8) | ta[2],
        (ta[5] << 8) | ta[4],
    ]

    p1k[0] = tsc_i
    p1k[1] = tsc_i2
    p1k[2] = ta_words[0]
    p1k[3] = ta_words[1]
    p1k[4] = ta_words[2]

    tk_words = [struct.unpack_from("<H", tk, i)[0] for i in range(0, 16, 2)]

    for i in range(8):
        p1k[0] = (p1k[0] + _sbox(p1k[4] ^ tk_words[i & 1])) & 0xFFFF
        p1k[1] = (p1k[1] + _sbox(p1k[0] ^ tk_words[(i & 1) + 2])) & 0xFFFF
        p1k[2] = (p1k[2] + _sbox(p1k[1] ^ tk_words[(i & 1) + 4])) & 0xFFFF
        p1k[3] = (p1k[3] + _sbox(p1k[2] ^ tk_words[(i & 1) + 6])) & 0xFFFF
        p1k[4] = (p1k[4] + _sbox(p1k[3] ^ tk_words[i & 1])) & 0xFFFF
        p1k[4] = (p1k[4] + i) & 0xFFFF

    return p1k


_SBOX = [
    0xC6A5F432, 0xF884976F, 0xEE99B05B, 0xF68D8C43,
    0xFF0DD05B, 0xD6BD9367, 0xDEB1601C, 0x91E40E67,
    # (truncated — full 256-entry S-box belongs in a dedicated TKIP impl)
]


def _sbox(v: int) -> int:
    lo = v & 0xFF
    hi = (v >> 8) & 0xFF
    return ((_SBOX[lo >> 3] >> ((lo & 7) * 4)) ^ (_SBOX[hi >> 3] >> ((hi & 7) * 4))) & 0xFFFF


def decrypt_tkip(
    payload: bytes,
    tk: bytes,
    ta: bytes,
    priority: int = 0,
) -> Optional[bytes]:
    """
    Decrypt a TKIP-protected 802.11 MPDU body.

    NOTE: This is a structural placeholder. Full TKIP requires a complete
    phase-1/phase-2 key mixing implementation and Michael MIC verification.
    For production use, delegate to a library (e.g. scapy, wpa_supplicant).

    Args:
        payload:  bytes starting at the TKIP header (after MAC header)
        tk:       32-byte TKIP TK (first 16 for encryption, [16:24] Tx MIC, [24:32] Rx MIC)
        ta:       6-byte Transmitter Address
        priority: QoS TID

    Returns:
        Decrypted plaintext (without MIC), or None on failure.
    """
    if len(payload) < 12:
        logger.debug("TKIP: payload too short")
        return None

    # TKIP header: IV(3) | Key-ID | Extended IV(4) = 8 bytes
    tsc1  = payload[0]
    _     = payload[1]   # (tsc1 | 0x20) & 0x7f — IV byte 2 used as WEP compatibility
    tsc0  = payload[2]
    key_id = payload[3]
    tsc2  = payload[4]
    tsc3  = payload[5]
    tsc4  = payload[6]
    tsc5  = payload[7]

    tsc = (tsc5 << 40) | (tsc4 << 32) | (tsc3 << 24) | (tsc2 << 16) | (tsc1 << 8) | tsc0

    body = payload[8:]
    # body = data(N) + MIC(8) + ICV(4)  — strip trailing ICV check
    if len(body) < 12:
        return None

    # Phase 2 key derivation + RC4 decryption — structural only
    # Full implementation needs complete _tkip_phase2()
    logger.debug("TKIP decryption: structural placeholder, not production-ready")
    return None


# ---------------------------------------------------------------------------
# WEP
# ---------------------------------------------------------------------------

_WEP_IV_LEN = 3
_WEP_ICV_LEN = 4


def decrypt_wep(
    payload: bytes,
    key: bytes,
) -> Optional[bytes]:
    """
    Decrypt a WEP-protected 802.11 MPDU body.

    Args:
        payload: bytes starting at the WEP IV (after MAC header, before data)
        key:     WEP key bytes (5 bytes for WEP-40, 13 bytes for WEP-104)

    Returns:
        Decrypted plaintext (ICV stripped and verified), or None on ICV failure.
    """
    if len(payload) < _WEP_IV_LEN + 1 + _WEP_ICV_LEN:
        logger.debug("WEP: payload too short")
        return None

    iv = payload[:_WEP_IV_LEN]
    # byte 3 = key_id (ignored here — key passed directly)
    ciphertext = payload[4:]

    rc4_key = iv + key
    plaintext_and_icv = rc4(rc4_key, ciphertext)

    plaintext = plaintext_and_icv[:-_WEP_ICV_LEN]
    received_icv = plaintext_and_icv[-_WEP_ICV_LEN:]
    computed_icv = crc32_bytes(plaintext)

    if received_icv != computed_icv:
        logger.debug("WEP: ICV mismatch")
        return None

    return plaintext


# ---------------------------------------------------------------------------
# High-level decryptor — called by DLT parser or body.py
# ---------------------------------------------------------------------------

def decrypt_dot11_payload(
    payload: bytes,
    cipher: str,           # "ccmp" | "tkip" | "wep"
    credentials: dict,     # bssid-keyed entry from DissectConfig.credentials["dot11"]
    ta: bytes,             # 6-byte transmitter address
    bssid: bytes,          # 6-byte BSSID
    sta_mac: bytes,        # 6-byte station MAC
    priority: int = 0,
    aad: bytes = b"",
) -> Optional[bytes]:
    """
    Unified decryption entry point for 802.11 Data frame payloads.

    Called by the DLT parser after detecting `protected=True` in the FC.
    Resolves PTK from credentials (pre-computed or derived) then delegates
    to the cipher-specific function.

    Args:
        payload:     raw encrypted bytes (starting at cipher header)
        cipher:      "ccmp", "tkip", or "wep"
        credentials: the bssid sub-dict from DissectConfig.credentials["dot11"]
                     e.g. {"psk": "...", "ssid": "...", "clients": {...}}
        ta:          Transmitter Address (addr2 raw bytes)
        bssid:       BSSID raw bytes
        sta_mac:     Station MAC raw bytes
        priority:    QoS TID (0 for non-QoS)
        aad:         Additional Authenticated Data for CCMP (MAC header bytes)

    Returns:
        Decrypted plaintext bytes, or None on failure.
    """
    cipher = cipher.lower()

    if cipher == "wep":
        wep_cfg = credentials.get("wep", {})
        wep_key_hex = wep_cfg.get("key")
        if not wep_key_hex:
            logger.debug("WEP: no key in credentials")
            return None
        return decrypt_wep(payload, bytes.fromhex(wep_key_hex))

    # For CCMP / TKIP we need a PTK
    ptk = _resolve_ptk(credentials, bssid, sta_mac)
    if ptk is None:
        logger.debug(f"{cipher.upper()}: could not resolve PTK for {ta.hex()}")
        return None

    tk = ptk_tk(ptk)

    if cipher == CCMP:
        return decrypt_ccmp(payload, tk, ta, priority, aad)
    elif cipher == TKIP:
        return decrypt_tkip(payload, ptk[_KCK_LEN + _KEK_LEN:], ta, priority)

    logger.debug(f"Unknown cipher: {cipher}")
    return None


def _resolve_ptk(
    credentials: dict,
    bssid: bytes,
    sta_mac: bytes,
) -> Optional[bytes]:
    """
    Resolve PTK for a given (bssid, sta) pair.

    Resolution order:
      1. Pre-computed PTK in credentials["clients"][sta_hex]["ptk"]
      2. Pre-computed PMK in credentials["pmk"] + handshake nonces
      3. Derived PMK from credentials["psk"] + credentials["ssid"]

    Nonces (anonce, snonce) must be in credentials["clients"][sta_hex]
    and are populated by the EAPOL analyzer as frames are processed.
    """
    sta_hex = sta_mac.hex(":")
    client_creds = credentials.get("clients", {}).get(sta_hex, {})

    # 1. Pre-computed PTK
    ptk_hex = client_creds.get("ptk")
    if ptk_hex:
        return bytes.fromhex(ptk_hex)

    # 2. Need nonces to derive PTK
    anonce_hex = client_creds.get("anonce")
    snonce_hex = client_creds.get("snonce")
    if not anonce_hex or not snonce_hex:
        logger.debug("PTK derivation: missing anonce/snonce — need EAPOL handshake frames")
        return None

    anonce = bytes.fromhex(anonce_hex)
    snonce = bytes.fromhex(snonce_hex)

    # 3. Resolve PMK
    pmk_hex = credentials.get("pmk")
    if pmk_hex:
        pmk = bytes.fromhex(pmk_hex)
    else:
        psk  = credentials.get("psk")
        ssid = credentials.get("ssid")
        if not psk or not ssid:
            logger.debug("PTK derivation: no pmk, no psk+ssid")
            return None
        pmk = derive_pmk(psk, ssid)

    return derive_ptk(pmk, anonce, snonce, bssid, sta_mac)

def make_config(
    bssid: str = "",
    ssid: str = "",
    psk: str = "",
    pmk: str = "",
    clients: Optional[dict] = None,
) -> dict:
    """
    Build a single AP entry for credentials["dot11"][bssid].

    The dot11 section only holds what is needed to decrypt CCMP/TKIP/WEP at
    the 802.11 layer.  EAP, RADIUS, and TLS credentials live in their own
    top-level sections.

    Args:
        bssid:   AP MAC address string ("aa:bb:cc:dd:ee:ff")
        ssid:    Network name (needed for PMK derivation from PSK)
        psk:     WPA2/WPA3 Personal passphrase (derives PMK internally)
        pmk:     Pre-computed 32-byte PMK as hex string (skips derivation)
        clients: Optional dict of per-STA overrides:
                 {
                     "11:22:33:44:55:66": {
                         "ptk":    "hex...",    # skip derivation entirely
                         "anonce": "hex...",    # populated by EAPOL analyzer
                         "snonce": "hex...",    # populated by EAPOL analyzer
                     }
                 }

    Returns:
        AP credentials entry dict.

    WEP example (add to the returned dict):
        entry["wep"] = {"key_index": 0, "key": "0102030405"}
    """
    return {
        CREDENTIALS: {
            SSID: ssid,
            PSK: psk,
            PMK: pmk,
            CLIENTS: clients
        },
        CRYPT: {
        }
    }
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/definitions.py
```python
from pktparsers.core.dissectors.ieee802.dot11.parsers.management import definitions as mgmt_defs
from pktparsers.core.dissectors.ieee802.dot11.parsers.control import definitions as ctrl_defs
from pktparsers.core.dissectors.ieee802.dot11.parsers.data import definitions as data_defs

FCS_LEN = 4

MGMT = 0
CTRL = 1
DATA = 2

FRAME_TYPES = {
    MGMT: "Management",
    CTRL: "Control",
    DATA: "Data",
}

FRAME_SUBTYPES = {
    MGMT: mgmt_defs.SUBTYPES,
    CTRL: ctrl_defs.SUBTYPES,
    DATA: data_defs.SUBTYPES
}

RSN_CIPHER_WEP40 = 1
RSN_CIPHER_TKIP = 2
RSN_CIPHER_CCMP = 4
RSN_CIPHER_WEP104 = 5
RSN_CIPHER_GCMP = 8
RSN_CIPHER_GCMP_256 = 9
RSN_CIPHER_CCMP_256 = 10
RSN_CIPHER_BIP_GMAC_128 = 11
RSN_CIPHER_BIP_GMAC_256 = 12
RSN_CIPHER_BIP_CMAC_256 = 13
RSN_AKM_8021X = 1
RSN_AKM_PSK = 2
RSN_AKM_FT_8021X = 3
RSN_AKM_FT_PSK = 4
RSN_AKM_8021X_SHA256 = 5
RSN_AKM_PSK_SHA256 = 6
RSN_AKM_TDLS = 7
RSN_AKM_SAE = 8
RSN_AKM_FT_SAE = 9
RSN_AKM_AP_PEERKEY = 10
RSN_AKM_SUITE_B_8021X = 11
RSN_AKM_SUITE_B_192_8021X = 12
RSN_AKM_FILS_SHA256 = 14
RSN_AKM_FILS_SHA384 = 15
RSN_AKM_OWE = 18

RSN_MIN_LEN = 2
RSN_GROUP_CIPHER_LEN = 4
RSN_SUITE_LEN = 4
```

## File: src/pktparsers/core/dissectors/ieee802/dot11/parse.py
```python
# pktparsers/core/layers/l2/ieee802/dot11/parse.py
from logging import getLogger
from pktparsers.core.parsing import (ParseContext, insert_item, detect_fcs)
from pktparsers.core.dissectors.ieee802.dot11.parsers import (mac_header, body)
from pktparsers.core.dissectors.ieee802.dot11.definitions import (FCS_LEN, MAC_HDR)
from pktparsers.core.definitions.protocol import IEEE802_11
from pktparsers.core.definitions.result import (BODY, FCS, SUMMARY)

logger = getLogger(__name__)

def parse() -> dict:
    ctx = ParseContext.current()
    if ctx is None:
        raise RuntimeError("parse() called without active ParseContext")

    insert_item(ctx.result, IEEE802_11, {})
    insert_item(ctx.result[IEEE802_11], FCS, detect_fcs(FCS_LEN))

    if ctx.offset >= len(ctx.buffer):
        logger.debug("Empty dot11 buffer body")
        return ctx.result[IEEE802_11]

    insert_item(ctx.result[IEEE802_11], MAC_HDR, mac_header.parser())
    insert_item(ctx.result[IEEE802_11], BODY, body.parser())

    traffic_ctx = TrafficContext.current()

    if traffic_ctx:
        summary = summarizer(ctx.result[IEEE802_11))
        insert_item(ctx.result[IEEE802_11], SUMMARY, summary)
        analyzer(ctx.result[IEEE802_11], summary)

    return ctx.result[IEEE802_11]
```

## File: src/pktparsers/core/dissectors/ieee802/dot1x/eap/crypt.py
```python
def make_eap_credentials(
    bssid: str = "",
    method: str = "",
    identity: str = "",
    password: str = "",
    ca_cert: str = "",
) -> dict:
    """
    Build an EAP/Enterprise credentials entry for credentials["eap"][bssid].

    Keyed by BSSID because EAP Enterprise is negotiated per-AP.
    The decrypted EAPOL payload is handed here after dot11/crypt.py removes
    the CCMP/TKIP wrapper.
    """
    return {
        METHOD: method,
        IDENTITY: identity,
        PASSWORD: password,
        CA_CERT: ca_cert
    }
```

## File: src/pktparsers/core/dissectors/ieee802/dot1x/eap/parse.py
```python

```

## File: src/pktparsers/core/dissectors/ieee802/dot1x/eapol/analyzers/summary.py
```python
def summarizer(parser_result: dict) -> dict:
    def _classify_eapol_message(parser_result: dict) -> int:
        ki = eapol.get("key_information", {})
        ack  = ki.get("key_ack", False)
        mic  = ki.get("key_mic", False)
        inst = ki.get("install", False)
        sec  = ki.get("secure", False)
        enc  = ki.get("encrypted_key_data", False)
        klen = eapol.get("key_data_length", 0)
    
        if     ack and not mic and not sec:  return 1  # AP → STA, ANonce
        if not ack and     mic and not sec:  return 2  # STA → AP, SNonce + MIC
        if     ack and     mic and inst:     return 3  # AP → STA, GTK cifrado
        if not ack and     mic and sec:      return 4  # STA → AP, confirmação

        return 0

    eapol_msg = _classify_eapol_message(parser_result)

    """
    version_map = {
        0: "reserved(0)",
        1: "HMAC_MD5_ARC4_WPA1",
        2: "HMAC_SHA1_128_AES_WPA2_RSN",
        3: "AES_128_CMAC_AES_128_GCMP_WPA3",
        **{i: f"reserved({i})" for i in range(4, 8)},
    }

    key_description_version = parser_result.get()
    """

    ki = parser_result["key_information"]
    enc = "WPA3" if parser_result["authentication_version"] == 3 else \
          "WPA2/RSN" if parser_result["authentication_version"] == 2 else "WPA1"

    kd_ver = ki["key_descriptor_version"]["value"]
    cipher_desc = {
        1: "RC4 (WPA1/TKIP)",
        2: "AES-CCM (WPA2/CCMP)",
        3: "AES-GCM (WPA3/GCMP)"
    }.get(kd_ver, f"unknown({kd_ver})")

    msg_desc = {
        1: "AP → STA: ANonce (início do 4-way handshake)",
        2: "STA → AP: SNonce + MIC (resposta com credencial)",
        3: "AP → STA: GTK cifrado (instalação de chave)",
        4: "STA → AP: Confirmação (handshake completo)",
    }.get(eapol_msg, "Mensagem EAPOL desconhecida")

    flags = []
    if eapol_msg in (1, 2):
        flags.append("HANDSHAKE_CAPTURABLE")   # par M1+M2 → hashcat 22000
    if ki.get("encrypted_key_data"):
        flags.append("KEY_DATA_ENCRYPTED")
    if not ki.get("key_mic") and eapol_msg == 1:
        flags.append("NO_MIC")                 # esperado no msg1

    return {
        "summary": f"EAPOL Key (Message {eapol_msg} of 4) [{enc}]",
        "details": {
            "message": eapol_msg,
            "encryption": enc,
            "cipher_suite": cipher_desc,
            "direction": "AP→STA" if eapol_msg in (1, 3) else "STA→AP",
        },
        "flags": flags
    }
```

## File: src/pktparsers/core/dissectors/ieee802/dot1x/eapol/crypt.py
```python
# pktparsers/core/layers/l2/ieee802/dot1x/eapol/crypt.py
#
# EAPOL-specific cryptographic operations.
#
# Responsibilities:
#   - MIC computation and verification for EAPOL Key frames
#   - Extracting nonces (ANonce, SNonce) from EAPOL Key frames to enable PTK derivation
#   - Generating hashcat 22000 (WPA-PBKDF2-PMKID+EAPOL) output for offline cracking
#
# NOT responsible for:
#   - PTK/PMK derivation (→ dot11/crypt.py)
#   - Frame decryption (→ dot11/crypt.py)
#   - Persistent credential storage (→ DissectConfig.credentials)
#
# The EAPOL analyzer calls extract_handshake_material() as Key frames arrive,
# and populates DissectConfig.credentials["dot11"][bssid]["clients"][sta] with
# the nonces needed by dot11/crypt.py for PTK derivation.

import hmac
import hashlib
import logging
from typing import Optional

from pktparsers.core.crypt import hmac_sha1, hmac_md5

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# EAPOL Key descriptor version → MIC algorithm mapping
# (IEEE 802.11-2020 Table 12-7)
# ---------------------------------------------------------------------------

_MIC_ALGO = {
    1: "hmac_md5",    # WPA (TKIP)
    2: "hmac_sha1",   # WPA2 (CCMP)
    3: "hmac_sha256", # WPA3 / AES-128-CMAC (simplified — use aes_cmac for real)
}

def compute_eapol_mic(kck: bytes, eapol_frame: bytes, descriptor_version: int) -> Optional[bytes]:
    """
    Compute MIC over an EAPOL Key frame.

    The MIC field inside the frame must be zeroed before calling this
    (use clear_mic() first).

    Args:
        kck:               16-byte Key Confirmation Key (ptk_kck(ptk))
        eapol_frame:       full EAPOL Key frame with MIC zeroed
        descriptor_version: from Key Information bits [0:3]

    Returns:
        MIC bytes (16 bytes for MD5/SHA1, 16 bytes for AES-CMAC), or None.
    """
    algo = _MIC_ALGO.get(descriptor_version)
    if algo == "hmac_md5":
        return hmac_md5(kck, eapol_frame)[:16]
    elif algo == "hmac_sha1":
        return hmac_sha1(kck, eapol_frame)[:16]
    elif algo == "hmac_sha256":
        import hmac as _hmac
        return _hmac.new(kck, eapol_frame, hashlib.sha256).digest()[:16]
    else:
        logger.debug(f"Unknown descriptor version {descriptor_version}")
        return None

def verify_eapol_mic(
    kck: bytes,
    eapol_frame: bytes,
    received_mic: bytes,
    descriptor_version: int,
) -> bool:
    """
    Verify MIC of an EAPOL Key frame.

    Args:
        kck:               Key Confirmation Key
        eapol_frame:       raw EAPOL Key frame (MIC field must be zeroed)
        received_mic:      16-byte MIC extracted from the original frame
        descriptor_version: Key Information bits [0:3]

    Returns:
        True if MIC matches.
    """
    computed = compute_eapol_mic(kck, eapol_frame, descriptor_version)
    if computed is None:
        return False
    return hmac.compare_digest(computed, received_mic[:len(computed)])

# ---------------------------------------------------------------------------
# Handshake material extraction
# ---------------------------------------------------------------------------

def extract_handshake_material(eapol_parsed: dict) -> dict:
    """
    Extract nonces and MIC from a parsed EAPOL Key frame dict (as produced
    by dot1x/eapol/parse.py).

    Returns a dict with the fields that are present:
        {
            "anonce": "hex...",    # from msg 1/4 or 3/4 (key_ack=True)
            "snonce": "hex...",    # from msg 2/4 or 4/4 (key_ack=False, mic=True)
            "mic":    "hex...",    # from msg 2/4+
            "replay_counter": int,
            "msg": 1|2|3|4,       # inferred EAPOL message number
        }

    The caller (EAPOL analyzer) is responsible for storing nonces under
    DissectConfig.credentials["dot11"][bssid]["clients"][sta].
    """
    result = {}

    ki = eapol_parsed.get("key_information", {})
    key_ack  = ki.get("key_ack", False)
    key_mic  = ki.get("key_mic", False)
    secure   = ki.get("key_secure", False)
    install  = ki.get("key_install", False)

    nonce_raw = eapol_parsed.get("key_nonce")
    mic_raw   = eapol_parsed.get("key_mic")
    replay    = eapol_parsed.get("key_replay_counter")

    if nonce_raw:
        nonce_bytes = nonce_raw if isinstance(nonce_raw, bytes) else bytes.fromhex(nonce_raw)
        if any(nonce_bytes):  # non-zero nonce
            if key_ack:
                result["anonce"] = nonce_bytes.hex()
            else:
                result["snonce"] = nonce_bytes.hex()

    if mic_raw:
        mic_bytes = mic_raw if isinstance(mic_raw, bytes) else bytes.fromhex(mic_raw)
        if any(mic_bytes):
            result["mic"] = mic_bytes.hex()

    if replay is not None:
        result["replay_counter"] = replay

    # Infer message number
    if key_ack and not key_mic:
        result["msg"] = 1
    elif key_mic and not key_ack and not secure:
        result["msg"] = 2
    elif key_ack and key_mic and secure:
        result["msg"] = 3
    elif key_mic and not key_ack and secure:
        result["msg"] = 4

    return result
```

## File: src/pktparsers/core/dissectors/ieee802/dot1x/eapol/definitions.py
```python
DOT1X_VERSION = "dot1x_version"
DOT1X_TYPE = "dot1x_type"
DOT1X_HEADER_LEN = "dot1x_header_length"

KEY_DESCRIPTOR_TYPE = "key_descriptor_type"
KEY_INFORMATION = "key_information"
KEY_DESCRIPTOR_VERSION = "key_descriptor_version"
KEY_TYPE = "key_type"
KEY_INDEX = "key_index"
KEY_INSTALL = "key_install"
KEY_ACK = "key_ack"
KEY_MIC = "key_mic"
KEY_SECURE = "key_secure"
KEY_ERROR = "key_error"
KEY_REQUEST = "key_request"
ENCRYPTED_KEY_DATA = "encrypted_key_data"
SMK_MESSAGE = "smk_message"

KEY_LENGTH = "key_length"
KEY_REPLAY_COUNTER = "key_replay_counter"
KEY_NONCE = "key_nonce"
KEY_IV = "key_iv"
KEY_RSC = "key_rsc"
KEY_ID = "key_id"
KEY_DATA = "key_data"
KEY_DATA_LENGTH = "key_data_length"

PAIRWISE = "pairwise"
GROUP_SMK = "group_smk"

DOT1X_VERSION_FMT = "B"
DOT1X_TYPE_FMT = "B"
DOT1X_HEADER_LEN_FMT = "H"

KEY_DESCRIPTOR_TYPE_FMT = "B"
KEY_INFORMATION_FMT = "H"
KEY_LENGTH_FMT = "H"

KEY_REPLAY_COUNTER_FMT = "8s"
KEY_NONCE_FMT = "32s"
KEY_IV_FMT = "16s"
KEY_RSC_FMT = "8s"
KEY_ID_FMT = "8s"
KEY_MIC_FMT = "16s"
KEY_DATA_LENGTH_FMT = "H"

FMT = (
    "!" +
    DOT1X_VERSION_FMT +
    DOT1X_TYPE_FMT +
    DOT1X_HEADER_LEN_FMT +
    KEY_DESCRIPTOR_TYPE_FMT +
    KEY_INFORMATION_FMT +
    KEY_LENGTH_FMT +
    KEY_REPLAY_COUNTER_FMT +
    KEY_NONCE_FMT +
    KEY_IV_FMT +
    KEY_RSC_FMT +
    KEY_ID_FMT +
    KEY_MIC_FMT +
    KEY_DATA_LENGTH_FMT
)
```

## File: src/pktparsers/core/dissectors/ieee802/dot1x/eapol/parse.py
```python
# core/layers/l2/ieee802/dot1x/eapol/parse.py

from pktparsers.core.definitions.parsing import (VALUE, DESCRIPTION)

from pktparsers.core.dissectors.ieee802.dot1x.eapol import definitions as eapol_defs

logger = getLogger(__name__)

def parse(**kwargs) -> dict:
    def _parser(value: tuple, **kwargs) -> dict:
        logger.debug("EAPOL _parser")

        (
            auth_ver,
            eapol_type,
            length,
            desc_type,
            key_info,
            key_len,
            replay,
            nonce,
            iv,
            rsc,
            key_id,
            mic,
            key_data_len,
        ) = value

        version_map = {
            0: "reserved(0)",
            1: "HMAC_MD5_ARC4_WPA1",
            2: "HMAC_SHA1_128_AES_WPA2_RSN",
            3: "AES_128_CMAC_AES_128_GCMP_WPA3",
            **{i: f"reserved({i})" for i in range(4, 8)},
        }

        descriptor_version_value = key_info & 0x0007

        descriptor_version = {
            VALUE: descriptor_version_value,
            DESCRIPTION: version_map.get(descriptor_version_value),
        }

        key_type_bit = (key_info >> 3) & 0x01

        key_type = {
            VALUE: key_type_bit,
            DESCRIPTION: GROUP_SMK if key_type_bit else PAIRWISE,
        }

        key_index = (key_info >> 4) & 0x03

        install_bit = bool((key_info >> 6) & 0x01)
        ack_bit = bool((key_info >> 7) & 0x01)
        mic_bit = bool((key_info >> 8) & 0x01)
        secure_bit = bool((key_info >> 9) & 0x01)
        error_bit = bool((key_info >> 10) & 0x01)
        request_bit = bool((key_info >> 11) & 0x01)
        encrypted_key_data = bool((key_info >> 12) & 0x01)
        smk_message = bool((key_info >> 13) & 0x01)

        result = {
            eapol_defs.DOT1X_VERSION: auth_ver,
            eapol_defs.DOT1X_TYPE: eapol_type,
            eapol_defs.DOT1X_HEADER_LEN: length,
            eapol_defs.KEY_DESCRIPTOR_TYPE: desc_type,
            eapol_defs.KEY_INFORMATION: {
                eapol_defs.KEY_DESCRIPTOR_VERSION: descriptor_version,
                eapol_defs.KEY_TYPE: key_type,
                eapol_defs.KEY_INDEX: key_index,
                eapol_defs.KEY_INSTALL: install_bit,
                eapol_defs.KEY_ACK: ack_bit,
                eapol_defs.KEY_MIC: mic_bit,
                eapol_defs.KEY_SECURE: secure_bit,
                eapol_defs.KEY_ERROR: error_bit,
                eapol_defs.KEY_REQUEST: request_bit,
                eapol_defs.ENCRYPTED_KEY_DATA: encrypted_key_data,
                eapol_defs.SMK_MESSAGE: smk_message,
            },
            eapol_defs.KEY_LENGTH: key_len,
            eapol_defs.KEY_REPLAY_COUNTER: replay,
            eapol_defs.KEY_NONCE: nonce,
            eapol_defs.KEY_IV: iv,
            eapol_defs.KEY_RSC: rsc,
            eapol_defs.KEY_ID: key_id,
            eapol_defs.KEY_MIC: mic,
            eapol_defs.KEY_DATA_LENGTH: key_data_len,
        }

        if key_data_len > 0:
            fmt = f"{key_data_len}s"

            if not encrypted_key_data:
                result[eapol_defs.KEY_DATA] = unpack(
                    fmt,
                    parser=tagged_parameters,
                )
            else:
                result[eapol_defs.KEY_DATA] = unpack(fmt)

        return result

    logger.debug("EAPOL Parser")

    result = {}

    try:
        result = unpack(
            eapol_defs.FMT,
            parser=_parser,
        )

    except Exception as e:
        logger.debug(f"EAPOL Parser error: {e}")

    return result
```

## File: src/pktparsers/core/dissectors/ieee802/dot1x/radius/crypt.py
```python
def make_radius_credentials(server_ip: str = "", secret: str = "") -> dict:
    """
    Build a RADIUS shared secret entry for credentials["radius"][server_ip].

    Keyed by server IP — a given RADIUS server may serve multiple SSIDs.
    """
    entry: dict[str, Any] = {}
    if secret:
        entry["secret"] = secret
    return entry
```

## File: src/pktparsers/core/dissectors/ieee802/dot1x/radius/parse.py
```python

```

## File: src/pktparsers/core/dissectors/ieee802/dot1x/__init__.py
```python

```

## File: src/pktparsers/core/dissectors/ieee802/dot2/llc/definitions.py
```python
DSAP = "dsap"
SSAP = "ssap"
CONTROL_FIELD = "control_field"
PID = "pid"

DSAP_FMT = "B"
SSAP_FMT = "B"
CONTROL_FIELD_FMT = "B"
PID_FMT = "H"

FMT = (
    "!" +
    DSAP_FMT +
    SSAP_FMT +
    CONTROL_FMT +
    OUI_FMT +
    PID_FMT
)
```

## File: src/pktparsers/core/dissectors/ieee802/dot2/llc/parse.py
```python
# l2/ieee802/llc/parser.py

from logging import getLogger
from pktparsers.parsing import (unpack, bytes_for_oui) 
from pktparsers.core.registry import get_protocol
from pktparsers.core.dissectors.ieee802.dot3.ethernet.definitions import ETHERTYPE_DISPATCH
from pktparsers.core.definitions.parsing import OUI_FMT
from pktparsers.core.definitions.result import (OUI, PAYLOAD, NAME, DESCRIPTION)
from pktparsers.core.dissectors.ieee802.dot2.llc.definitions import (DSAP, SSAP, CONTROL_FIELD, OUI, PID, FMT)

logger = getLogger(__name__)

def parser(**kwargs) -> dict:
    logger.debug("LLC parse")

    def _parser(value: tuple, **kwargs) -> dict:
        dsap, ssap, ctrl, oui, pid = value
        
        oui = bytes_for_oui(oui)

        pid_name = ETHERTYPE_DISPATCH.get(pid)
        entry: DissectorEntry = get_protocol(pid_name)
        pid_desc = entry.description

        payload = entry.parser(**kwargs)
        
        result = {
            DSAP: dsap,
            SSAP: ssap,
            CONTROL_FIELD: ctrl,
            OUI: oui,
            PID: pid,
            NAME: pid_name,
            DESCRIPTION: pid_desc,
            PAYLOAD: payload
        }
        
        return result

    return unpack(FMT, parser=_parser)
```

## File: src/pktparsers/core/dissectors/ieee802/dot3/ethernet/analyzers/definitions.py
```python

```

## File: src/pktparsers/core/dissectors/ieee802/dot3/ethernet/analyzers/summary.py
```python

```

## File: src/pktparsers/core/dissectors/ieee802/dot3/ethernet/dlt/en10mb/parse.py
```python

```

## File: src/pktparsers/core/dissectors/ieee802/dot3/ethernet/parsers/body.py
```python
# dot3/parse.py
from logging import getLogger
from pktparsers.core.parsing import unpack
from pktparsers.core.filter_engine import get_nested
from pktparsers.core.dissectors.ieee802.dot3.definitions import (DOT3, ETHER_HDR, ETHERTYPE)
from pktparsers.core.dissectors.ieee802.dot2.parse import PAYLOAD_DISPATCH

logger = getLogger(__name__)

def parse(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        ctx = ParseContext.current()
        ethertype = get_nested(f"{DOT3}.{ETHER_HDR}.{ETHERTYPE}", ctx.result)

        payload = run_dispatch(PAYLOAD_DISPATCH, ethertype, **kwargs)

        return {
            "payload": payload,
        }

    return unpack(parser=_parser)
```

## File: src/pktparsers/core/dissectors/ieee802/dot3/ethernet/parsers/ethernet_header.py
```python
# dot3/parse.py
from logging import getLogger
from pktparsers.common.parse.utils import unpack, read_mac
from pktparsers.core.layers.l2.ieee802.dot3.definitions import *
from pktparsers.core.layers.l3.ip.parse import parse as ip_parse
from pktparsers.core.layers.l3.arp.parse import parse as arp_parse
from pktparsers.core.layers.l2.ieee802.dot1x.parsers.eapol import parser as eapol_parse
from pktparsers.core.layers.l2.ieee802.dot2.parse import PAYLOAD_DISPATCH

logger = getLogger(__name__)

def parse(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        dst, src, ethertype = value

        payload_name = entry.get("name")
        payload_description = entry.get("description")

        return {
            "dst": dst,
            "src": src,
            "ethertype"  ethertype,
            "name": entry.get("name"),
            "description": entry.get("description"),
        }

    return unpack(f"!{MAC_ADDRESS_LENGTH}s{MAC_ADDRESS_LENGTH}sH", parser=_parser)
```

## File: src/pktparsers/core/dissectors/ieee802/dot3/ethernet/definitions.py
```python
from pktparsers.core.definitions import protocol as proto

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_EAPOL = 0x888E
ETHERTYPE_WAPI = 0x88B4

ETHERTYPE_DISPATCH = {
    ETHERTYPE_IPV4:  proto.INET_IPV4,
    ETHERTYPE_IPV6:  proto.INET_IPV6,
    ETHERTYPE_EAPOL: proto.IEE802_EAPOL,
    ETHERTYPE_WAPI:  proto.WAPI,
    ETHERTYPE_ARP:   proto.ARP,
}
```

## File: src/pktparsers/core/dissectors/ieee802/dot3/ethernet/parse.py
```python
from logging import getLogger
from pktparsers.core.parsing import (ParseContext, insert_item, detect_fcs)
from pktparsers.core.definitions import parsing as (FCS, BODY)
from pktparsers.core.dissectors.ieee802.dot3.parsers import (ethernet_header, body)
from pktparsers.core.dissectors.ieee802.dot3.definitions import (DOT3, ETHER_HDR, FCS_LEN, VLAN_STRIPPING)

logger = getLogger(__name__)

def parse() -> dict:
    ctx = ParseContext.current()
    if ctx is None:
        raise RuntimeError("parse() called without active ParseContext")

    insert_item(ctx.result, DOT3, {})
    insert_item(ctx.result[DOT3], FCS, detect_fcs(FCS_LEN))

    if ctx.offset >= len(ctx.frame):
        logger.debug("Empty dot3 frame body")
        return ctx.result[DOT3]

    insert_item(ctx.result[DOT3], ETHER_HDR, ethernet_header.parser())
    insert_item(ctx.result[BODY], BODY, body.parser())

    return ctx.result[DOT3]

def make_config(vlan_stripping: bool = True):
    return {
        VLAN_STRIPPING: True,
    }
```

## File: src/pktparsers/core/dissectors/ieee802/__init__.py
```python

```

## File: src/pktparsers/core/dissectors/ieee802/__main__.py
```python
# for tests

IEEE802_11_FRAMES = {
  "raw": ["ffffffffffffa4f933ed5b75080045000156b50e00004011c48900000000ffffffff0044004301426781010106006ef3d0d803b9000000000000000000000000000000000000a4f933ed5b750000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000063825363350101370701031c21333a3b390205d03c316468637063642d31302e312e303a4c696e75782d362e362e3132365f313a7838365f36343a47656e75696e65496e74656c740101910101ff"]
}



def main():
    from core.common.filter_engine import apply_filters

    parsed_frame = Frame.frames_parser(eapol_msg1, mac_vendor_resolver)
    #store_filter, display_result = apply_filters("mac_hdr.fc.type == 2 and mac_hdr.mac_src.mac in ('06:ab:f1:d6:31:16', '5c:62:8b:80:83:8a') and mac_hdr.mac_dst.mac in ('06:ab:f1:d6:31:16', '5c:62:8b:80:83:8a') and mac_hdr.bssid.mac == '5c:62:8b:80:83:8a' and body.llc.type == '0x888e' and body.eapol", "mac_hdr, body", parsed_frame)
    store_filter, display_result = apply_filters("mac_hdr.fc.type == 2 and mac_hdr.mac_src.mac in ('aa:bb:cc:dd:ee:ff', 'ab:cd:ef:ab:cd:ef') and mac_hdr.mac_dst.mac in ('aa:bb:cc:dd:ee:ff', 'ab:cd:ef:ab:cd:ef') and mac_hdr.bssid == 'aa:bb:cc:dd:ee:ff' and llc.type == '0x888e' and body.eapol", "mac_hdr, body", parsed_frame)
    store_filter, display_result = apply_filters("mac_hdr.fc.type == 2 and mac_hdr.mac_src.mac in ('06:ab:f1:d6:31:16', '5c:62:8b:80:83:8a') and mac_hdr.mac_dst.mac in ('06:ab:f1:d6:31:16', '5c:62:8b:80:83:8a')", "mac_hdr, body", parsed_frame)
    if store_filter:
        print(display_result)
    print(parsed_frame)
    #for k, v in parsed_frame.items():
     #   print(f"{k} => {v}\n")
    #if store_filter_result:
        #print(frame_filter_result)
        #for k, v in frame_filter_result.items():
         #   for kk, vv in v.items():
          #      print(vv)
           #     print()

if __name__ == "__main__":
    main()
```

## File: src/pktparsers/core/dissectors/ieee802/registry.py
```python
from pktparsers.core.definitions import dlt as dlt
from pktparsers.core.definitions import protocol as proto
from pktparsers.core.definitions.entries import (DissectorEntry, L2, L3, DLT, PROTOCOL)

DISSECTORS = {
    dlt.DLT_IEEE802_11_RADIO: DissectorEntry(
        name="DLT_IEEE802_11_RADIO",
        parser=dot11_radio.parse,
        kind=DLT,
        layer=L2,
        summarizer=dot11_radio.analyzers.summary.summarizer,
        analyzer=dot11_radio.analyzers.summary.analyzer,
        config=dot11_radio.definitions.config,
    ),

    dlt.DLT_IEEE802_11: DissectorEntry(
        name="DLT_IEEE802_11",
        parser=dot11.parse,
        layer=L2,
        kind=DLT,
        summarizer=dot11_summary.summarizer,
        analyzer=dot11_summary.analyzer,
        config=dot11.definitions.config,
    ),

    dlt.DLT_EN10MB: DissectorEntry(
        name="DLT_EN10MB",
        kind=DLT,
        parser=dot3.parse,
        layer=L2,
        summarizer=dot3_summary.summarizer,
        analyzer=dot3_summary.analyzer,
        config=dot3.definitions.config,
    ),
    proto.IEEE802_11: DissectorEntry(
        description="IEEE 802.11",
        kind=PROTOCOL,
        parser=dot11.parse,
        layer=L2,
        summarizer=dot11_summary.summarizer,
        analyzer=dot11_summary.analyzer,
        config=dot11.definitions.config,
    ),

    proto.IEEE802_3: DissectorEntry(
        description="IEEE 802.3 Ethernet",
        parser=dot3.parse,
        layer=L2,
        kind=PROTOCOL,
        summarizer=dot3_summary.summarizer,
        analyzer=dot3_summary.analyzer,
        config=dot3.definitions.config,
    ),

    proto.IEEE802_1X: DissectorEntry(
        layer=L2,
        description="IEEE 802.1X",
        kind=PROTOCOL,
        config=dot1x.definitions.config,
    ),

    proto.IEEE802_LLC: DissectorEntry(
        layer=L2,
        description="Logical Link Control",
        kind=PROTOCOL,
        parser=llc.parse,
        summarizer=llc_summary.summarizer,
        analyzer=llc_summary.analyzer,
        config=llc.definitions.config,
    ),

    proto.IEEE802_EAPOL: DissectorEntry(
        description="EAP over LAN",
        layer=L2,
        parser=eapol.parse,
        kind=PROTOCOL,
        credentials_extractor=eapol.crypt.credentials_extractor,
        summarizer=eapol_summary.summarizer,
        analyzer=eapol_summary.analyzer,
        config=eapol.definitions.config,
    ),

    proto.IEEE802_EAP: DissectorEntry(
        description="Extensible Authentication Protocol",
        layer=L2,
        parser=eap.parse,
        kind=PROTOCOL,
        summarizer=eap_summary.summarizer,
        analyzer=eap_summary.analyzer,
        config=eap.definitions.config,
    ),

    proto.IEEE802_RADIUS: DissectorEntry(
        description="Remote Authentication Dial-In User Service",
        parser=radius.parse,
        summarizer=radius_summary.summarizer,
        analyzer=radius_summary.analyzer,
        kind=PROTOCOL,
        layer=L2,
        config=radius.definitions.config,
    ),
}
```

## File: src/pktparsers/core/dissectors/inet/ip/analyzers/definitions.py
```python

```

## File: src/pktparsers/core/dissectors/inet/ip/analyzers/summary.py
```python

```

## File: src/pktparsers/core/dissectors/inet/ip/dlt/raw/parse.py
```python

```

## File: src/pktparsers/core/dissectors/inet/ip/definitions.py
```python
# pktparsers/core/layers/l3/ip/definitions.py

from pktparsers.common.parse.definitions import (IPV4_FMT)

IHL = "ihl"
TOS = "tos"
TOTAL_LENGTH = "total_length"
IDENTIFICATION = "identification"
FRAGMENT_OFFSET = "fragment_offset"
TTL = "ttl"
PROTOCOL = "protocol"
HEADER_CHECKSUM = "header_checksum"

VERSION_FMT = "B"
IHL_FMT = "B"
TOS_FMT = "B"
TOTAL_LENGTH_FMT = "H"
IDENTIFICATION_FMT = "H"
FLAGS_FRAGMENT_FMT = "H"
TTL_FMT = "B"
PROTOCOL_FMT = "B"
HEADER_CHECKSUM_FMT = "H"

FMT = (
    "!" +
    VERSION_FMT +
    IHL_FMT +
    TOS_FMT +
    TOTAL_LENGTH_FMT +
    IDENTIFICATION_FMT +
    FLAGS_FRAGMENT_FMT +
    TTL_FMT +
    PROTOCOL_FMT +
    HEADER_CHECKSUM_FMT +
    IPV4_FMT +
    IPV4_FMT
)
```

## File: src/pktparsers/core/dissectors/inet/ip/parse.py
```python
import socket
from logging import getLogger
from pktparsers.common.parse.utils import unpack, ParseContext
from pktparsers.core.layers.l3.ip.definitions import *

logger = getLogger(__name__)

def ip(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        version_ihl, tos, total_length, identification, flags_frag, ttl, protocol, checksum, src, dst = value
        version = version_ihl >> 4
        ihl = version_ihl & 0x0F

        result = {
            VERSION: version,
            IHL: ihl,
            TOS: tos,
            TOTAL_LENGTH: total_length,
            IDENTIFICATION: identification,
            FLAGS: (flags_frag >> 13) & 0x7,
            FRAGMENT_OFFSET: flags_frag & 0x1FFF,
            TTL: ttl,
            PROTOCOL: protocol,
            HEADER_CHECKSUM: checksum,
            SRC: socket.inet_ntoa(src),
            DST: socket.inet_ntoa(dst),
        }

        ctx = ParseContext.current()
        payload_len = total_length - (ihl * 4)
        if payload_len > 0 and ctx.offset + payload_len <= len(ctx.frame):
            result[PAYLOAD] = unpack(f"{payload_len}s")

        return result

    return unpack(FMT, parser=_parser)
```

## File: src/pktparsers/core/dissectors/inet/ipsec/crypt.py
```python
def make_ipsec_credentials(spi_hex: str = "", esp_key: str = "", auth_key: str = "") -> dict:
    """
    Build an IPsec credentials entry for credentials["ipsec"][spi_hex].
    """
    entry: dict[str, Any] = {}
    if esp_key:
        entry["esp_key"] = esp_key
    if auth_key:
        entry["auth_key"] = auth_key
    return entry
```

## File: src/pktparsers/core/dissectors/inet/tls/analyzers/definitions.py
```python

```

## File: src/pktparsers/core/dissectors/inet/tls/analyzers/summary.py
```python

```

## File: src/pktparsers/core/dissectors/inet/tls/crypt.py
```python

```

## File: src/pktparsers/core/dissectors/inet/tls/definitions.py
```python

```

## File: src/pktparsers/core/dissectors/inet/tls/parse.py
```python

```

## File: src/pktparsers/core/dissectors/inet/__init__.py
```python

```

## File: src/pktparsers/core/dissectors/inet/registry.py
```python
# dissectors/inet/registry.py

from pktparsers.core.definitions.entries import DissectorEntry
from pktparsers.core.definitions import dlt as dlt
from pktparsers.core.definitions import protocol as proto

DISSECTORS: dict[[int | str], DissectorEntry] = {
    dlt.DLT_RAW: DissectorEntry(...),
    proto.IP: DissectorEntry(
        description="Internet Protocol",
        layer=L3,
        parser=ip.parse,
        summarizer=ip_summary.summarizer,
        analyzer=ip_summary.analyzer,
        config=ip.definitions.config,
    ),

    proto.IPV4: DissectorEntry(
        description="Internet Protocol Version 4",
        parser=ipv4.parse,
        layer=L3,
        summarizer=ipv4_summary.summarizer,
        analyzer=ipv4_summary.analyzer,
        config=ipv4.definitions.config,
    ),

    proto.IPV6: DissectorEntry(
        layer=L3,
        description="Internet Protocol Version 6",
        parser=ipv6.parse,
        summarizer=ipv6_summary.summarizer,
        analyzer=ipv6_summary.analyzer,
        config=ipv6.definitions.config,
    ),

    proto.ICMP: DissectorEntry(
        description="Internet Control Message Protocol",
        parser=icmp.parse,
        summarizer=icmp_summary.summarizer,
        analyzer=icmp_summary.analyzer,
        config=icmp.definitions.config,
    ),

    proto.ICMPV6: DissectorEntry(
        description="Internet Control Message Protocol Version 6",
        parser=icmpv6.parse,
        summarizer=icmpv6_summary.summarizer,
        analyzer=icmpv6_summary.analyzer,
        config=icmpv6.definitions.config,
    ),

    proto.TCP: DissectorEntry(
        description="Transmission Control Protocol",
        layer=L4,
        parser=tcp.parse,
        summarizer=tcp_summary.summarizer,
        analyzer=tcp_summary.analyzer,
        config=tcp.definitions.config,
    ),

    proto.UDP: DissectorEntry(
        description="User Datagram Protocol",
        parser=udp.parse,
        layer=L4,
        summarizer=udp_summary.summarizer,
        analyzer=udp_summary.analyzer,
        config=udp.definitions.config,
    ),
}
```

## File: src/pktparsers/core/dissectors/raw/dlt/custom_a.py
```python

```

## File: src/pktparsers/core/dissectors/raw/dlt/custom_b.py
```python

```

## File: src/pktparsers/core/dissectors/__init__.py
```python

```

## File: src/pktparsers/core/__init__.py
```python

```

## File: src/pktparsers/core/crypt.py
```python
# pktparsers/core/crypt.py
#
# Generic cryptographic primitives shared by protocol-specific crypt modules.
# Nothing here knows about 802.11, EAPOL, or any protocol.
# Protocol-specific key derivation and decryption live in their own modules.

import hmac
import hashlib
import struct
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from typing import Optional

# ---------------------------------------------------------------------------
# PRF / KDF
# ---------------------------------------------------------------------------

def prf_sha1(key: bytes, label: str, data: bytes, length_bits: int) -> bytes:
    """
    IEEE 802.11 PRF-SHA1 (used for PTK/GTK derivation).
    Produces `length_bits` of pseudo-random keying material.
    """
    result = b""
    counter = 0
    label_bytes = label.encode() + b"\x00"
    while len(result) * 8 < length_bits:
        result += hmac.new(
            key,
            label_bytes + data + bytes([counter]),
            hashlib.sha1,
        ).digest()
        counter += 1
    return result[: length_bits // 8]


def pbkdf2_sha1(password: str, ssid: str, iterations: int = 4096, length: int = 32) -> bytes:
    """PBKDF2-HMAC-SHA1 — used for PSK → PMK derivation (WPA2 Personal)."""
    return hashlib.pbkdf2_hmac(
        "sha1",
        password.encode(),
        ssid.encode(),
        iterations,
        dklen=length,
    )


def hmac_sha1(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha1).digest()


def hmac_md5(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.md5).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

# ---------------------------------------------------------------------------
# AES-CCM (CCMP)
# ---------------------------------------------------------------------------

def aes_ccm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> Optional[bytes]:
    """
    AES-CCM decryption used by CCMP (802.11i).
    Returns plaintext on success, None on MIC failure.

    Requires `cryptography` (pip install cryptography).
    Uses 8-byte MIC (M=8) and 2-byte length field (L=2), per 802.11 CCMP spec.
    """
    try:
        aesccm = AESCCM(key, tag_length=8)
        return aesccm.decrypt(nonce, ciphertext, aad)
    except Exception:
        return None

# ---------------------------------------------------------------------------
# RC4 (TKIP / WEP)
# ---------------------------------------------------------------------------

def rc4(key: bytes, data: bytes) -> bytes:
    """Raw RC4 stream cipher. Used by TKIP and WEP."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)


# ---------------------------------------------------------------------------
# Michael MIC (TKIP integrity)
# ---------------------------------------------------------------------------

def _michael_b(l: int, r: int) -> tuple[int, int]:
    r = r ^ ((l << 17) | (l >> 15)) & 0xFFFFFFFF
    l = (l + r) & 0xFFFFFFFF
    r = r ^ ((l & 0x00FF00FF) << 8 | (l & 0xFF00FF00) >> 8)
    l = (l + r) & 0xFFFFFFFF
    r = r ^ ((l << 3) | (l >> 29)) & 0xFFFFFFFF
    l = (l + r) & 0xFFFFFFFF
    r = r ^ ((l >> 2) | (l << 30)) & 0xFFFFFFFF
    l = (l + r) & 0xFFFFFFFF
    return l, r


def michael_mic(key: bytes, da: bytes, sa: bytes, priority: int, data: bytes) -> bytes:
    """
    TKIP Michael MIC. Key is 8 bytes (KCK[16:24] for Tx MIC or [24:32] for Rx MIC).
    """
    kl, kr = struct.unpack_from("<II", key)
    msg = da + sa + bytes([priority, 0, 0, 0]) + data

    # Pad to multiple of 4
    pad_len = (4 - len(msg) % 4) % 4
    msg += bytes([0x5a]) + bytes(pad_len)

    l, r = kl, kr
    for i in range(0, len(msg), 4):
        word = struct.unpack_from("<I", msg, i)[0]
        l ^= word
        l, r = _michael_b(l, r)

    mic_bytes = struct.pack("<II", l, r)
    return mic_bytes


# ---------------------------------------------------------------------------
# CRC-32 (WEP ICV)
# ---------------------------------------------------------------------------

def crc32_bytes(data: bytes) -> bytes:
    """CRC-32 as little-endian 4 bytes (WEP ICV)."""
    crc = binascii.crc32(data) & 0xFFFFFFFF
    return struct.pack("<I", crc)

# pktparsers/core/crypt.py — acréscimo

def analyze_capture_for_credentials(capture_path: Path, protocol: str) -> list[dict]:
    """
    Lê um arquivo de captura e extrai material de credentials para o protocolo.
    
    Para "ieee802_eapol": extrai pares (anonce, snonce, mic) de handshakes,
    retorna como entries do tipo "handshake_material" para o usuário completar
    com a PSK ou PMK.
    
    Para "tls": verifica se é um NSS keylog e retorna {"type": "keylog_file", "value": path}.
    
    Retorna lista de dicts prontos para inserir em credentials["keys"].
    """
    from pktparsers.io import read
    from pktparsers.core.dissect import Dissector

    result = []
    with Dissector(protocol) as d:
        for packet in read(capture_path):
            dissected = d.dissect(packet)
            # Cada protocolo registra um extractor em seu crypt.py
            extractor = _get_credential_extractor(protocol)
            if extractor:
                entries = extractor(dissected)
                result.extend(entries)
    return result
```

## File: src/pktparsers/io/__init__.py
```python
"""
I/O operations: reading and writing packet files.

Supported formats:
    - pcap, pcapng: libpcap formats
    - erf: Endace ERF format
    - json, jsonl: JSON formats

Usage:
    # Read packets
    for dissect_result in read("capture.pcap"):
        print(dissect_result[PARSED])
    
    # Write packets
    write(raw_bytes, "output.pcap", fmt="pcap", dlt=1)
    
    # Incremental write with size limit
    with PacketWriter("output.pcapng", max_bytes=100*1024*1024) as w:
        for result in read("large.pcap"):
            if not w.write(result):
                break  # size cap reached
    
    # Merge files
    merge_packets("input.pcap", "output.jsonl", "jsonl")
"""

from pktparsers.io.reader import read
from pktparsers.io.writer import write, PacketWriter, merge_packets
from pktparsers.io.filters import read_filters, write_filters

__all__ = [
    "read",
    "write",
    "PacketWriter",
    "merge_packets",
    "read_filters",
    "write_filters",
]
```

## File: src/pktparsers/io/io.py
```python
# pktparsers/common/io.py
import json
import struct
import time
import dpkt
from pathlib import Path
from typing import Generator
from cli_core.files import iter_from_json, iter_json_objects, new_file_path
from pktparsers.dissector import Dissector
from pktparsers.common.definitions.dissect import DissectConfig
from pktparsers.common.parse.definitions import ERF_TYPE_TO_DLT
from pktparsers.common.parse.utils import raw_packet_extractor

supported_formats = ["pcap", "pcapng", "erf", "json", "jsonl"]
supported_compression_formats = ["gzip", "lz4"]

@dataclass
class CreateNewFileAfter:
    packets_counter: int
    kilobytes: int
    seconds: int
    hours: int
    file_infix_pattern: Path
    
@dataclass
class OutputConfig:
    output_format: str | None
    compression: str | None 

def _detect_format(path: Path) -> str:
    suffix = path.suffix.lstrip(".").lower()
    if suffix not in supported_formats:
        raise ValueError(f"Unsupported format: {suffix!r}")
    return suffix


def _extract_raw(result: dict) -> bytes | None:
    """Extract raw bytes from a dissect result dict."""
    parsed = result.get(PARSED)
    raw = parsed.get(RAW) if isinstance(parsed, dict) else result.get(RAW)
    if isinstance(raw, str):
        return bytes.fromhex(raw)
    return raw


def _build_erf_record(raw: bytes, ts: float, erf_type: int) -> bytes:
    """
    Build a minimal ERF record from raw bytes.

    ERF header layout (16 bytes):
        timestamp (8) | type (1) | flags (1) | rlen (2) | lctr (2) | wlen (2)
    For TYPE_ETH (0x02) an additional 2-byte pad follows the header.
    """
    ETH_PAD = 2
    ERF_HDR_LEN = 16 + ETH_PAD
    flags = 0x00
    wlen = len(raw)
    rlen = ERF_HDR_LEN + wlen

    # 64-bit little-endian fixpoint: upper 32 bits = seconds, lower 32 = fraction
    sec = int(ts)
    frac = int((ts - sec) * (2 ** 32))
    erf_ts = (sec << 32) | frac

    header = struct.pack("<QBBHHHH", erf_ts, erf_type, flags, rlen, 0, wlen, 0)
    pad = b"\x00" * ETH_PAD
    return header + pad + raw


def _write_pcap(packet: bytes | dict, path: Path, dlt: int = 1, ts: float = None):
    """
    Append a single packet to a .pcap file.

    dpkt.pcap.Writer always writes a fresh global header when constructed,
    so appending by seeking to the end is not straightforward. The safest
    approach for a standalone write() call is to open a new file each time.
    For high-frequency incremental writes use PacketWriter instead.
    """
    ts = ts or time.time()
    raw = packet if isinstance(packet, bytes) else _extract_raw(packet)
    if not raw:
        return
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f, linktype=dlt)
        w.writepkt(raw, ts=ts)


def _write_pcapng(packet: bytes | dict, path: Path, dlt: int = 1, ts: float = None):
    """Append a single packet to a .pcapng file."""
    ts = ts or time.time()
    raw = packet if isinstance(packet, bytes) else _extract_raw(packet)
    if not raw:
        return
    with open(path, "wb") as f:
        w = dpkt.pcapng.Writer(f)
        w.writepkt(raw, ts=ts)


def _write_erf(packet: bytes | dict, path: Path, dlt: int = 1, ts: float = None):
    """
    Append a single ERF record to a .erf file.

    The ERF type is inferred from the DLT when possible; defaults to
    TYPE_ETH (0x02) for DLT_EN10MB (1).
    """
    ts = ts or time.time()
    raw = packet if isinstance(packet, bytes) else _extract_raw(packet)
    if not raw:
        return

    # Reverse-lookup: DLT → ERF type (take the first match)
    erf_type = next(
        (etype for etype, d in ERF_TYPE_TO_DLT.items() if d == dlt),
        0x02,  # fallback to TYPE_ETH
    )
    record = _build_erf_record(raw, ts, erf_type=erf_type)
    with open(path, "ab") as f:
        f.write(record)


def _write_jsonl(packet: bytes | dict, path: Path, dlt: int = 1, ts: float = None):
    """Append a single entry to a .jsonl file."""
    entry = packet if isinstance(packet, dict) else {RAW: packet.hex()}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _write_json(packet: bytes | dict, path: Path, dlt: int = 1, ts: float = None):
    """
    Write a single entry to a .json file.

    Because JSON is a single serialised value, each call overwrites the
    file. This is intentional: json is a batch/single-object format.
    For streaming writes use jsonl instead.
    """
    entry = packet if isinstance(packet, dict) else {RAW: packet.hex()}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=4, ensure_ascii=False)
        f.write("\n")


_WRITE_DISPATCH: dict[str, callable] = {
    "pcap":   _write_pcap,
    "pcapng": _write_pcapng,
    "erf":    _write_erf,
    "jsonl":  _write_jsonl,
    "json":   _write_json,
}

def _read_pcap(
    path: Path,
    config: DissectConfig = None,
) -> Generator[dict, None, None]:
    """
    Read a .pcap file and dissect each packet with a single Dissector
    instantiated from the file's global DLT.

    Yields: Dissector.dissect() result for each packet.
    """
    with open(path, "rb") as f:
        reader = dpkt.pcap.Reader(f)
        dlt = reader.datalink()
        with Dissector(dlt, config) as dissector:
            for _ts, raw in reader:
                yield dissector.dissect(raw)


def _read_pcapng(
    path: Path,
    config: DissectConfig = None,
) -> Generator[dict, None, None]:
    """
    Read a .pcapng file.

    pcapng may contain multiple interfaces (IDB — Interface Description
    Block), each with its own DLT. One Dissector is instantiated per
    interface and kept alive for the entire read so that each interface
    accumulates its own TrafficContext.

    Yields: Dissector.dissect() result enriched with
            {"interface_id": <int>, "dlt": <int>}.
    """
    dissectors: dict[int, Dissector] = {}  # iface_id → Dissector

    with open(path, "rb") as f:
        reader = dpkt.pcapng.Reader(f)

        # Pre-instantiate a Dissector for every interface declared in the file.
        for iface_id, iface_info in enumerate(reader.interfaces):
            dlt = iface_info.get("dlt") or iface_info.get("linktype")
            if dlt is not None:
                dissectors[iface_id] = Dissector(dlt, config)

        for _ts, raw, iface_id in reader:  # requires dpkt >= 1.9.8
            dissector = dissectors.get(iface_id)

            if dissector is None:
                # Interface discovered at runtime (rare — IDB after first EPB).
                iface_info = reader.interfaces[iface_id]
                dlt = iface_info.get("dlt") or iface_info.get("linktype")
                dissectors[iface_id] = Dissector(dlt, config)
                dissector = dissectors[iface_id]

            result = dissector.dissect(raw)
            result["interface_id"] = iface_id
            result["dlt"] = dissector.dlt
            yield result


def _read_erf(
    path: Path,
    config: DissectConfig = None,
) -> Generator[dict, None, None]:
    """
    Read an .erf file (Endace ERF format).

    ERF has no global DLT header — the link type is determined by the
    'type' field in each record. One Dissector is instantiated lazily per
    ERF type and kept alive to accumulate TrafficContext per link type.

    Yields: Dissector.dissect() result enriched with
            {"erf_type": <int>, "dlt": <int>},
            or an error dict for unsupported ERF types.
    """
    dissectors: dict[int, Dissector] = {}  # erf_type → Dissector

    with open(path, "rb") as f:
        for record in dpkt.erf.ERF(f):
            erf_type = record.type & 0x7F  # mask out bit 7 (extension headers flag)
            dlt = ERF_TYPE_TO_DLT.get(erf_type)

            if dlt is None:
                yield {
                    "erf_type": erf_type,
                    "dlt": None,
                    PARSED: None,
                    "error": f"Unsupported ERF type 0x{erf_type:02x}",
                }
                continue

            if erf_type not in dissectors:
                dissectors[erf_type] = Dissector(dlt, config)

            result = dissectors[erf_type].dissect(bytes(record.data))
            result["erf_type"] = erf_type
            result["dlt"] = dlt
            yield result


_READ_DISPATCH: dict[str, callable] = {
    "pcap":   _read_pcap,
    "pcapng": _read_pcapng,
    "erf":    _read_erf,
}

def read(
    path: Path,
    config: DissectConfig = None,
) -> Generator[dict, None, None]:
    """
    Read any supported format and yield dissection results.

    For json/jsonl: iterates objects directly (no dissection).
    For pcap/pcapng/erf: dissects each packet via the appropriate reader.
    """
    path = Path(path)
    fmt = _detect_format(path)

    if fmt in ("json", "jsonl"):
        yield from iter_json_objects(path)
        return

    yield from _READ_DISPATCH[fmt](path, config)


def write(
    packet: bytes | dict,
    path: Path,
    fmt: str,
    dlt: int = 1,
    ts: float = None,
):
    """
    Write a single packet (raw bytes or dissect result dict) to a file.

    Delegates to the format-specific internal writer via _WRITE_DISPATCH.
    For high-frequency incremental writes, prefer PacketWriter to avoid
    reopening the file on every call.
    """
    path = Path(path)
    fn = _WRITE_DISPATCH.get(fmt)
    if fn is None:
        raise ValueError(f"Unsupported write format: {fmt!r}")
    fn(packet, path, dlt=dlt, ts=ts or time.time())


def merge_packets(src: Path, dst: Path | None, dst_format: str):
    """
    Read packets from `src` (any supported format), extract raw bytes, and
    write them to `dst` in `dst_format`.

    Source format is detected automatically from the file extension.
    If `dst` is None, a path is derived from `src` with the new suffix;
    if that path already exists, new_file_path() adds a timestamp suffix.

    For json/jsonl sources, raw bytes are extracted via raw_packet_extractor
    and iter_from_json so the full object tree is walked correctly.
    For pcap/pcapng/erf sources, raw bytes are extracted from each dissect
    result the same way.
    """
    src = Path(src)
    src_fmt = _detect_format(src)

    if dst is None:
        dst = src.with_suffix(f".{dst_format}")
        if dst.exists():
            dst = new_file_path(dst)

    dst = Path(dst)
    extractor = raw_packet_extractor()

    with PacketWriter(dst, fmt=dst_format) as writer:
        if src_fmt in ("json", "jsonl"):
            """
            iter_from_json walks the full object tree with the extractor,
            which is more correct than iterating raw objects and calling
            the extractor manually.
            """
            for _hex, _raw in iter_from_json(src, extractor):
                writer.write({RAW: _hex})
        else:
            for result in _READ_DISPATCH[src_fmt](src):
                for _hex, _raw in extractor(result):
                    writer.write({RAW: _hex})


class PacketWriter:
    """
    Utility class for incremental packet writing with an optional output
    file size cap.

    Supports all formats in `supported_formats`. When the output file
    reaches `max_bytes`, write() returns False and the caller is
    responsible for stopping. The file is not closed automatically on
    limit; use the context manager or call close() explicitly.

    Basic usage:
        with PacketWriter("capture.pcap", dlt=1, max_bytes=50*1024*1024) as w:
            for result in read(src):
                if not w.write(result):
                    break  # size limit reached

    Notes on json format:
        Because a JSON file is a single serialised value, incremental
        appending is not meaningful. PacketWriter accumulates all entries
        in memory and serialises the complete list on close(). For large
        captures, prefer jsonl to avoid memory pressure.
    """

    def __init__(
        self,
        path: Path | str,
        fmt: str = None,
        dlt: int = 1,
        max_bytes: int = None,
    ):
        self.path = Path(path)
        self.fmt = fmt or _detect_format(self.path)
        self.dlt = dlt
        self.max_bytes = max_bytes

        self._handle = None
        self._writer = None
        self._json_buffer: list[dict] = []  # only used when fmt == "json"
        self._closed = False

    def __enter__(self):
        self._open()
        return self

    def __exit__(self, *args):
        self.close()

    def _open(self):
        if self.fmt in ("json", "jsonl"):
            self._handle = open(self.path, "w", encoding="utf-8")
        else:
            self._handle = open(self.path, "wb")

        if self.fmt == "pcap":
            self._writer = dpkt.pcap.Writer(self._handle, linktype=self.dlt)
        elif self.fmt == "pcapng":
            self._writer = dpkt.pcapng.Writer(self._handle)
        elif self.fmt == "erf":
            self._writer = self._handle
        # jsonl and json write directly through self._handle / self._json_buffer

    def _current_size(self) -> int:
        """Return the current on-disk size of the output file in bytes."""
        return self.path.stat().st_size if self.path.exists() else 0

    def write(self, result: dict, ts: float = None) -> bool:
        """
        Write one dissect result (or a plain {"raw": ...} dict) to the file.

        Returns True on success, False if the size limit has been reached.
        The file is NOT closed on False; call close() or use the context manager.
        """
        if self._closed:
            return False

        if self.max_bytes and self._current_size() >= self.max_bytes:
            return False

        ts = ts or time.time()

        if self.fmt == "pcap":
            raw = _extract_raw(result)
            if raw:
                self._writer.writepkt(raw, ts=ts)

        elif self.fmt == "pcapng":
            raw = _extract_raw(result)
            if raw:
                self._writer.writepkt(raw, ts=ts)

        elif self.fmt == "erf":
            raw = _extract_raw(result)
            if raw:
                erf_type = result.get("erf_type")
                self._handle.write(_build_erf_record(raw, ts, erf_type=erf_type))

        elif self.fmt == "jsonl":
            self._handle.write(json.dumps(result, ensure_ascii=False) + "\n")

        elif self.fmt == "json":
            # Accumulate in memory; the list is flushed to disk on close().
            self._json_buffer.append(result)

        return True

    def close(self):
        if self._closed:
            return

        if self.fmt == "json" and self._json_buffer and self._handle:
            json.dump(self._json_buffer, self._handle, indent=4, ensure_ascii=False)
            self._handle.write("\n")

        if self._handle:
            self._handle.flush()
            self._handle.close()

        self._closed = True

def normalize_filter(value):
    if isinstance(value, (list, tuple)):
        return " ".join(map(str, value))
    return value or ""

def build_filter_dict(store_filter=None, display_filter=None) -> dict:
    return {
        "store": normalize_filter(store_filter),
        "display": normalize_filter(display_filter),
    }

def read_filters(path: str | Path):
    result = []
    for entry in iter_json_objects(path):
        if isinstance(entry, dict):
            result.append({
                "store": entry.get("store", ""),
                "display": entry.get("display", ""),
            })
    if str(path).lower().endswith(".json"):
        return result[0] if result else {}
    return result

def write_json(path: str | Path, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def write_jsonl(path: str | Path, data: list[dict]):
    with open(path, "w", encoding="utf-8") as f:
        for entry in data:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def write_filters(
    path: str | Path = None,
    simple_output: bool = False,
    store_filter=None,
    display_filter=None,
):
    path = path if path else new_file_path(f"pktparsers-filters{'.jsonl' if simple_output else '.json'}")
    data = build_filter_dict(store_filter=store_filter, display_filter=display_filter)
    if simple_path:
        write_jsonl(path, data)
        return
    write_json(path, [data])
```

## File: src/pktparsers/io/reader.py
```python
"""
Packet readers for various formats (pcap, pcapng, erf, json, jsonl).
"""

from pathlib import Path
from typing import Generator
from logging import getLogger

logger = getLogger(__name__)

import dpkt

from pktparsers.core.dissector import Dissector, DissectConfig
from pktparsers.core.definitions import ERF_TYPE_TO_DLT, PARSED


def _detect_format(path: Path) -> str:
    """Detect file format from extension"""
    suffix = path.suffix.lstrip(".").lower()
    supported = ["pcap", "pcapng", "erf", "json", "jsonl"]
    if suffix not in supported:
        raise ValueError(f"Unsupported format: {suffix!r}")
    return suffix


def _read_pcap(
    path: Path,
    config: DissectConfig = None,
) -> Generator[dict, None, None]:
    """Read .pcap file and dissect each packet"""
    with open(path, "rb") as f:
        reader = dpkt.pcap.Reader(f)
        dlt = reader.datalink()
        with Dissector(dlt, config) as dissector:
            for _ts, raw in reader:
                yield dissector.dissect(raw)


def _read_pcapng(
    path: Path,
    config: DissectConfig = None,
) -> Generator[dict, None, None]:
    """Read .pcapng file (may contain multiple interfaces with different DLTs)"""
    dissectors: dict[int, Dissector] = {}
    
    with open(path, "rb") as f:
        reader = dpkt.pcapng.Reader(f)
        
        # Pre-instantiate Dissector per interface
        for iface_id, iface_info in enumerate(reader.interfaces):
            dlt = iface_info.get("dlt") or iface_info.get("linktype")
            if dlt is not None:
                dissectors[iface_id] = Dissector(dlt, config)
        
        for _ts, raw, iface_id in reader:
            dissector = dissectors.get(iface_id)
            
            if dissector is None:
                # Runtime interface discovery
                iface_info = reader.interfaces[iface_id]
                dlt = iface_info.get("dlt") or iface_info.get("linktype")
                dissectors[iface_id] = Dissector(dlt, config)
                dissector = dissectors[iface_id]
            
            result = dissector.dissect(raw)
            result["interface_id"] = iface_id
            result["dlt"] = dissector.dlt
            yield result


def _read_erf(
    path: Path,
    config: DissectConfig = None,
) -> Generator[dict, None, None]:
    """Read .erf file (link type varies per record)"""
    dissectors: dict[int, Dissector] = {}
    
    with open(path, "rb") as f:
        for record in dpkt.erf.ERF(f):
            erf_type = record.type & 0x7F
            dlt = ERF_TYPE_TO_DLT.get(erf_type)
            
            if dlt is None:
                yield {
                    "erf_type": erf_type,
                    "dlt": None,
                    PARSED: None,
                    "error": f"Unsupported ERF type 0x{erf_type:02x}",
                }
                continue
            
            if erf_type not in dissectors:
                dissectors[erf_type] = Dissector(dlt, config)
            
            result = dissectors[erf_type].dissect(bytes(record.data))
            result["erf_type"] = erf_type
            result["dlt"] = dlt
            yield result


def _read_json(path: Path) -> Generator[dict, None, None]:
    """Read .json file (single list of objects)"""
    import json
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
        if isinstance(data, list):
            for obj in data:
                yield obj
        else:
            yield data


def _read_jsonl(path: Path) -> Generator[dict, None, None]:
    """Read .jsonl file (one JSON object per line)"""
    import json
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def read(
    path: Path,
    config: DissectConfig = None,
) -> Generator[dict, None, None]:
    """
    Read packets from any supported format.
    
    For json/jsonl: yields raw objects (no dissection).
    For pcap/pcapng/erf: yields dissected results (if config provided).
    
    Args:
        path: file path
        config: DissectConfig (required for pcap/pcapng/erf)
        
    Yields:
        dict: dissect result or raw JSON object
    """
    path = Path(path)
    fmt = _detect_format(path)
    
    if fmt == "json":
        yield from _read_json(path)
    elif fmt == "jsonl":
        yield from _read_jsonl(path)
    elif fmt == "pcap":
        yield from _read_pcap(path, config)
    elif fmt == "pcapng":
        yield from _read_pcapng(path, config)
    elif fmt == "erf":
        yield from _read_erf(path, config)
```

## File: src/pktparsers/io/writer.py
```python
# pktparsers/app/app.py

import json
from pathlib import Path

def save_app_config(config: AppConfig, path: Path) -> None:
    """Salva AppConfig em JSON. PTKs efêmeros NÃO são salvos."""
    data = _strip_ephemeral(config.dissect)
    path.write_text(json.dumps({"dissect": data, "output": config.output}, indent=2))

def load_app_config(path: Path) -> AppConfig:
    data = json.loads(path.read_text())
    return AppConfig(
        dissect=data.get("dissect", {}),
        output=data.get("output", {}),
    )

def _strip_ephemeral(dissect: dict) -> dict:
    """Remove PTKs derivados em tempo de execução antes de salvar em disco."""
    import copy
    d = copy.deepcopy(dissect)
    dot11 = d.get("dlt", {}).get("DLT_IEEE802_11_RADIO", {}).get("crypt", {}).get("dot11", {})
    for bssid_entry in dot11.values():
        for client in bssid_entry.get("clients", {}).values():
            client.pop("ptk", None)     # PTK: efêmero, não persiste
            client.pop("anonce", None)  # nonces: específicos da sessão
            client.pop("snonce", None)
    return d
```

## File: src/pktparsers/tui/screens/dissect_config.py
```python
# pktparsers/tui/screens/dissect_config.py

from textual.screen import ModalScreen
from textual.widgets import ListView, ListItem, Label, Switch, Input

class DissectConfigScreen(ModalScreen):
    """
    Modal gerado dinamicamente a partir de AppConfig.dissect.
    Não tem nenhuma referência hardcoded a protocolos específicos.
    """

    def __init__(self, app_config: "AppConfig") -> None:
        self._app_config = app_config
        super().__init__()

    def compose(self):
        # Itera dlt configs e protocol configs do AppConfig
        # Cada chave do config dict vira um widget baseado no tipo do valor:
        #   bool  → Switch
        #   str   → Input
        #   dict  → sub-seção expandível
        for section, configs in self._app_config.dissect.items():
            yield Label(section)
            yield from self._widgets_for(configs)

    def _widgets_for(self, cfg: dict):
        for key, val in cfg.items():
            if isinstance(val, bool):
                yield Switch(value=val, id=key)
            elif isinstance(val, str):
                yield Input(value=val, placeholder=key, id=key)
            elif isinstance(val, dict):
                yield Label(f"  {key}")
                yield from self._widgets_for(val)
```

## File: src/pktparsers/tui/widgets/fieldeditor.py
```python

```

## File: src/pktparsers/tui/widgets/hex_view.py
```python
# pktparsers/tui/widgets/hex_view.py

from textual.widget import Widget
from textual.reactive import reactive
from rich.text import Text

BYTES_PER_ROW = 16

class HexView(Widget):
    
    highlight_start: reactive[int] = reactive(0)
    highlight_end:   reactive[int] = reactive(0)

    def load(self, raw_hex: str) -> None:
        self._raw = bytes.fromhex(raw_hex)
        self.refresh()

    def set_highlight(self, start: int, end: int) -> None:
        self.highlight_start = start
        self.highlight_end   = end

    def render(self) -> Text:
        if not hasattr(self, "_raw"):
            return Text()
        text = Text()
        for i, byte in enumerate(self._raw):
            hl = self.highlight_start <= i < self.highlight_end
            style = "bold white on dark_blue" if hl else ""
            text.append(f"{byte:02x} ", style=style)
            if (i + 1) % BYTES_PER_ROW == 0:
                text.append("\n")
        return text
```

## File: src/pktparsers/tui/widgets/packet_list.py
```python
# pktparsers/tui/widgets/packet_list.py

from textual.widgets import DataTable
from textual.message import Message

class PacketList(DataTable):
    
    class PacketSelected(Message):
        def __init__(self, index: int, parsed: dict, raw: str) -> None:
            self.index  = index
            self.parsed = parsed
            self.raw    = raw
            super().__init__()

    class PacketEditRequested(Message):
        def __init__(self, index: int, parsed: dict) -> None:
            self.index  = index
            self.parsed = parsed
            super().__init__()
```

## File: src/pktparsers/tui/widgets/packet_tree.py
```python
# pktparsers/tui/widgets/packet_tree.py

from textual.widgets import Tree
from textual.widgets.tree import TreeNode
from pktparsers.core.definitions.parsing import METADATA, PARSED, VALUE
from pktparsers.core.definitions.analysis import SUMMARY

class PacketTree(Tree):
    """
    Renderiza um dict parsed (resultado de Dissector.dissect) como árvore.
    
    Cada nó carrega o sub-dict correspondente para:
      - Highlight sincronizado com HexView (via _metadata_.start/end)
      - Context menu com Copy/As filter
      - Edição de campo (se FieldEditor estiver ativo)
    """
    
    def load_packet(self, parsed: dict) -> None:
        self.clear()
        self._build_node(self.root, parsed)
        self.root.expand()

    def _build_node(self, node: TreeNode, data: dict, key: str = "root") -> None:
        meta     = data.get(METADATA, {})
        parsed   = data.get(PARSED)
        value    = data.get(VALUE)
        summary  = data.get(SUMMARY)

        label = self._make_label(key, parsed, value, summary, meta)
        child = node.add(label, data=data)

        if isinstance(parsed, dict):
            for k, v in parsed.items():
                if isinstance(v, dict):
                    self._build_node(child, v, k)
                else:
                    child.add_leaf(f"{k}: {v}", data={VALUE: v})

    def _make_label(self, key, parsed, value, summary, meta) -> str:
        if summary:
            return f"{key}  [{summary}]"
        if value is not None and not isinstance(value, dict):
            return f"{key}: {value}"
        return key

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        data = event.node.data
        if not data:
            return
        meta = data.get(METADATA, {})
        # Emite mensagem para HexView sincronizar highlight
        self.post_message(self.FieldFocused(
            start=meta.get("start", 0),
            end=meta.get("end", 0),
            field_data=data,
        ))

    class FieldFocused(Message):
        def __init__(self, start: int, end: int, field_data: dict) -> None:
            self.start      = start
            self.end        = end
            self.field_data = field_data
            super().__init__()
```

## File: src/pktparsers/tui/widgets/packettree.py
```python

```

## File: src/pktparsers/tui/__init__.py
```python
"""
Text User Interface widgets and application.

Public widgets:
    - HexView: hexadecimal view of raw bytes
    - PacketTree: hierarchical packet structure
    - PacketList: data table of packets
    - FieldEditor: edit individual fields

Application:
    - TUIApp: main Textual application
"""

try:
    from pktparsers.tui.widgets.hexview import HexView
    from pktparsers.tui.widgets.packettree import PacketTree
    from pktparsers.tui.widgets.packetlist import PacketList
    from pktparsers.tui.widgets.fieldeditor import FieldEditor
    from pktparsers.tui.app import TUIApp
    
    __all__ = [
        "HexView",
        "PacketTree",
        "PacketList",
        "FieldEditor",
        "TUIApp",
    ]
except ImportError as e:
    # TUI dependencies not available
    __all__ = []
    _IMPORT_ERROR = e
```

## File: src/pktparsers/tui/__main__.py
```python
from pktparsers.tui.main import main
main()
```

## File: src/pktparsers/tui/main.py
```python

```

## File: src/pktparsers/__main__.py
```python
from pktparsers.cli.main import main
main()
```

## File: LICENSE
```
MIT License

Copyright (c) 2026 Gustavo Araújo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## File: README.md
```markdown
# pktparsers
Parsers for communication standards protocols
```

## File: src/pktparsers/app/app.py
```python
# pktparsers/app/app.py

import json
import copy
from dataclasses import dataclass, field
from pktparsers.io import OutputConfig
from pktparsers.core.definitions import (
    GLOBAL,
    CRYPT,
    PARSE,
    ANALYSIS,
    DLT,
    PROTOCOL
)
from pktparsers.core import registry
from pktparsers.core.analysis import make_config as make_analysis_config
from pktparsers.core.parsing import make_config as make_parse_config
from pktparsers.core.crypt import make_config as make_crypt_config
from pathlib import Path

@dataclass
class Config:
    """
    Configuração raiz do pktparsers como framework.
    Gerada por make_config() e serializada/carregada como JSON.
    
    Separação de responsabilidades:
      - Config é o contrato serializado (pode ir para disco)
      - DissectConfig é gerado a partir dela no momento de uso
      - AppContext (app/context.py) gerencia paths e I/O de disco
    """
    dissect: dict = field(default_factory=dict)   # → gera DissectConfig
    output:  dict = field(default_factory=dict)   # → gera OutputConfig

def make_config() -> AppConfig:
    """
    Gera AppConfig lendo os CONFIGs registrados em registry.DLT e registry.PROTOCOL.
    
    Cada entry que tiver um CONFIG definido contribui com sua estrutura.
    Entries sem CONFIG (MESH_CTRL, TDLS etc.) são ignoradas silenciosamente.
    """
    dlt_configs = {
        entry.name: entry.config
        for entry in registry.DLT.values()
        if entry.config is not None
    }

    protocol_configs = {
        name: entry.config
        for name, entry in registry.PROTOCOL.items()
        if entry.config is not None
    }

    return AppConfig(
        dissect={
            GLOBAL: {
                CRYPT: make_crypt_config(),
                PARSE: make_parse_config(),
                ANALYSIS: make_analysis_config(),
            },
            DLT:      dlt_configs,
            PROTOCOL: protocol_configs,
        },
        output={},
    )
```

## File: src/pktparsers/app/context.py
```python
"""
Application context: configuration, cache, log directories.
"""

import os
import pwd
from pathlib import Path
from logging import getLogger

logger = getLogger(__name__)

class Context:
    """
    Manages application directories and configuration.
    
    Attributes:
        real_user: actual user (respects SUDO_USER)
        home_dir: user's home directory
        config_dir: ~/.config/pktparsers
        cache_dir: ~/.cache/pktparsers
        log_file: path to main log file
    """
    
    def __init__(self, config: dict = None, log_file: Path = None, app_name: str = "pktparsers"):
        self.config = config or {}
        
        # Determine real user (handle sudo)
        self.real_user = os.environ.get("SUDO_USER") or os.getlogin()
        pw = pwd.getpwnam(self.real_user)
        self.home_dir = Path(pw.pw_dir)
        
        # Setup dirs
        self.config_dir = self.home_dir / ".config" / app_name
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.chmod(0o740)
        
        self.cache_dir = self.home_dir / ".cache" / app_name
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.chmod(0o740)
        
        self.log_file = log_file or (self.cache_dir / f"{app_name}.log")
        
        logger.debug(
            f"AppContext initialized — user={self.real_user}, "
            f"config_dir={self.config_dir}, log_file={self.log_file}"
        )

    def get_config_file(self, name: str) -> Path:
        """Get path to config file"""
        return self.config_dir / name

    def get_cache_file(self, name: str) -> Path:
        """Get path to cache file"""
        return self.cache_dir / name
```

## File: src/pktparsers/cli/main.py
```python
#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import argcomplete
from pathlib import Path
from core.bootstrap import init

config = {
    "module_dependencies": ["a", "b", "c"],
    "system_dependencies": ["d", "e"],
    "argparse": {}
}

def parse_args():
    parser = argparse.ArgumentParser(
        description="",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging and save logs to file"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=Path,
        help="Output fullpath to save debug logs to file"
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    argcomplete.autocomplete(parser)

    return parser

def main():
    parser = parse_args()
    config["argparse"]["parser"] = parser
    config["argparse"]["args"] = parser.parse_args()
    result = init(config)
    operations = result.operations
    logger = getLogger(__name__)
    operations.dispatch()

if __name__ == "__main__":
    main()
```

## File: src/pktparsers/core/definitions/analysis.py
```python
FIRST_SEEN = "first_seen"
LAST_SEEN = "last_seen"
TRAFFIC_SUMMARY = "traffic_summary"
ANNOTATIONS = "annotations"
DEVICES = "devices"
```

## File: src/pktparsers/core/definitions/parsing.py
```python
EUI48_FMT = "6s"
EUI64_FMT = "8s"
OUI_FMT = "3s"
IPV4_FMT = "4s"
IPV6_FMT = "16s"

PARSED = "parsed"
COUNTER = "counter"
VALUE = "value"
METADATA = "_metadata_"
RAW = "raw"
TOKENS = "tokens"
```

## File: src/pktparsers/core/filter_engine.py
```python
import re
import operator
from pktparsers.core.definitions.parsing import (PARSED, VALUE, METADATA)

operators = {
    ">=": operator.ge,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    "<": operator.lt,
}

def get_nested(path: str, dct: dict, default=None):
    keys = path.split(".")
    current = dct
    i = 0

    if isinstance(current, dict) and PARSED in current:
        current = current[PARSED]

    while i < len(keys):
        if not isinstance(current, dict):
            return default

        key = keys[i]
        key_lower = str(key).lower()
        found = False

        for dct_key, dct_value in current.items():
            if str(dct_key).lower() == key_lower:
                current = dct_value
                found = True
                break

        if not found and _is_numeric_dict(current):
            result = _search_in_numeric_dict(current, keys[i:])
            return result if result is not None else default

        if not found:
            return default

        if isinstance(current, dict) and PARSED in current:
            next_key = keys[i + 1] if i + 1 < len(keys) else None
            if next_key is None or str(next_key).lower() not in (PARSED, VALUE, METADATA):
                current = current[PARSED]

        i += 1

    if isinstance(current, bytes):
        return current.hex()

    if isinstance(current, dict) and PARSED in current:
        if all(k in (PARSED, VALUE, METADATA) for k in current.keys()):
            return current.get(PARSED, default)

    return current if current is not None else default

def _is_numeric_dict(d: dict) -> bool:
    return (
        isinstance(d, dict)
        and len(d) > 0
        and all(str(k).isdigit() for k in d.keys())
    )

def _search_in_numeric_dict(d: dict, remaining_keys: list[str]):
    results = []
    for entry in d.values():
        candidate = entry
        if isinstance(entry, dict) and PARSED in entry and VALUE in entry:
            candidate = entry[PARSED]

        result = get_nested(".".join(remaining_keys), candidate)
        if result is not None:
            results.append(result)

    if not results:
        return None
    if len(results) == 1:
        return results[0]
    return results

def _to_value(val: str, parsed_frame: dict):
    val = val.strip()
    if val.lower() == "true":
        return True
    if val.lower() == "false":
        return False
    if re.fullmatch(r"[-+]?\d+", val):
        return int(val)
    if re.fullmatch(r"[-+]?\d*\.\d+", val):
        return float(val)
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        return val[1:-1]
    nested = get_nested(val, parsed_frame)
    if nested is not None:
        return nested
    return None

def _extract_tuple_values(text: str, parsed_frame: dict):
    text = text.strip()
    m = re.fullmatch(r"\(([^()]*)\)", text)
    if not m:
        return [_to_value(text, parsed_frame)]
    items = [i.strip() for i in m.group(1).split(",") if i.strip()]
    return [_to_value(i, parsed_frame) for i in items]

def _evaluate_simple(expr: str, parsed_frame: dict):
    expr = expr.strip()
    if " not in " in expr:
        left, right = expr.split(" not in ", 1)
        left_val = _to_value(left, parsed_frame)
        options = _extract_tuple_values(right, parsed_frame)
        if isinstance(left_val, list):
            return not any(v in options for v in left_val)
        return left_val not in options

    if " in " in expr:
        left, right = expr.split(" in ", 1)
        left_val = _to_value(left, parsed_frame)
        options = _extract_tuple_values(right, parsed_frame)
        if isinstance(left_val, list):
            return any(v in options for v in left_val)
        return left_val in options

    for op_str, op_func in operators.items():
        if op_str in expr:
            parts = expr.split(op_str, 1)
            if len(parts) == 2:
                left, right = parts
                left_val = _to_value(left.strip(), parsed_frame)
                right_val = _to_value(right.strip(), parsed_frame)
                if isinstance(left_val, list):
                    return any(op_func(v, right_val) for v in left_val)
                return op_func(left_val, right_val)

    val = _to_value(expr, parsed_frame)
    if isinstance(val, list):
        return len(val) > 0
    return bool(val)

def _split_by_operator(expr: str, operator: str):
    parts = []
    current = []
    paren_count = 0
    bracket_count = 0
    
    i = 0
    while i < len(expr):
        if expr[i] == '(':
            paren_count += 1
            current.append(expr[i])
        elif expr[i] == ')':
            paren_count -= 1
            current.append(expr[i])
        elif expr[i] == '[':
            bracket_count += 1
            current.append(expr[i])
        elif expr[i] == ']':
            bracket_count -= 1
            current.append(expr[i])
        elif paren_count == 0 and bracket_count == 0 and expr[i:i+len(operator)] == operator:
            parts.append(''.join(current).strip())
            current = []
            i += len(operator) - 1
        else:
            current.append(expr[i])
        i += 1
    
    if current:
        parts.append(''.join(current).strip())
    
    return parts if len(parts) > 1 else None

def _parse_filter_expression(expr: str, parsed_frame: dict) -> bool:
    expr = expr.strip()

    if expr.startswith('(') and expr.endswith(')'):
        balance = 0
        should_remove = True
        for i, char in enumerate(expr):
            if char == '(':
                balance += 1
            elif char == ')':
                balance -= 1
            if balance == 0 and i < len(expr) - 1:
                should_remove = False
                break
        if should_remove:
            expr = expr[1:-1].strip()

    if expr.lower().startswith("not "):
        return not _parse_filter_expression(expr[4:].strip(), parsed_frame)

    parts = _split_by_operator(expr, " and ")
    if parts and len(parts) > 1:
        return all(_parse_filter_expression(p, parsed_frame) for p in parts)

    parts = _split_by_operator(expr, " or ")
    if parts and len(parts) > 1:
        return any(_parse_filter_expression(p, parsed_frame) for p in parts)

    return _evaluate_simple(expr, parsed_frame)

def apply_filters(store_filter: str = None, display_filter: str = None, parsed_frame: dict = None):
    if parsed_frame is None:
        parsed_frame = {}
        
    store_filter_result = True
    if store_filter:
        store_filter_result = _parse_filter_expression(store_filter, parsed_frame)
        
    display_filter_result = None
    if display_filter:
        keys = [k.strip() for k in display_filter.split(",")]
        display_filter_result = {}
        
        for key in keys:
            value = get_nested(key, parsed_frame)
            if value is not None:
                display_filter_result[key] = value
                
    return store_filter_result, display_filter_result
```

## File: src/pktparsers/tui/app.py
```python
def on_packet_tree_field_focused(self, event: PacketTree.FieldFocused) -> None:
    self.query_one(HexView).set_highlight(event.start, event.end)
```

## File: src/pktparsers/__init__.py
```python
"""
pktparsers — comprehensive packet parsing and analysis framework

Public API:
    Core parsing:
        - Dissector: main class for packet dissection
        - DissectConfig: configuration for Dissector
        - ParseContext: context manager for parsing
        
    I/O operations:
        - read(): read packets from file (pcap, pcapng, erf, json, jsonl)
        - write(): write packets to file
        - PacketWriter: incremental packet writer with size limits
        - merge_packets(): merge packets from multiple sources
        
    Filtering:
        - apply_filters(): execute store/display filters
        - get_nested(): navigate nested parsed results
        
    Utilities:
        - HexView, PacketTree, FieldEditor: TUI widgets
        - AppContext: CLI application context
        - ProtocolEntry, DltEntry: registry entries
"""

__version__ = "0.1.0"

# Core APIs
from pktparsers.core.dissector import (
    Dissector,
    DissectConfig,
    AnalysisConfig,
    CredentialsConfig,
)
from pktparsers.core.parsing import ParseContext
from pktparsers.core.traffic import TrafficContext
from pktparsers.core.registry import (
    ProtocolEntry,
    DltEntry,
    get_dlt_parser,
    get_protocol,
)
from pktparsers.core.filter_engine import apply_filters, get_nested

# I/O APIs
from pktparsers.io.reader import read
from pktparsers.io.writer import write, PacketWriter, merge_packets
from pktparsers.io.filters import read_filters, write_filters

# TUI widgets (optional import)
try:
    from pktparsers.tui.widgets import (
        HexView,
        PacketTree,
        PacketList,
        FieldEditor,
    )
    _HAS_TUI = True
except ImportError:
    _HAS_TUI = False

# CLI context (optional)
try:
    from pktparsers.app.context import AppContext
    from pktparsers.app.bootstrap import AppBootstrap
except ImportError:
    AppContext = None
    AppBootstrap = None

__all__ = [
    # Core
    "Dissector",
    "DissectConfig",
    "ParseContext",
    "TrafficContext",
    "ProtocolEntry",
    "DltEntry",
    "get_dlt_parser",
    "get_protocol",
    "raw_packet_extractor",
    # Filters
    "apply_filters",
    "get_nested",
    # I/O
    "read",
    "write",
    "PacketWriter",
    "merge_packets",
    "read_filters",
    "write_filters",
    # TUI (conditional)
    "HexView",
    "PacketTree",
    "PacketList",
    "FieldEditor",
    # Apps
    "AppContext",
    "AppBootstrap",
]
```

## File: pyproject.toml
```toml
[project]
name = "pktparsers"
version = "1.0.0"
description = "Extensible framework for dissecting and creating protocol packets and parsers."
readme = "README.md"
requires-python = ">=3.12"

authors = [
    { name = "Gustavo Araújo" }
]

dependencies = [
    "dpkt==1.9.8",
    "textual==6.2.1",
    "rich==14.3.3",
    "argcomplete",
    "cli-core @ git+https://github.com/gusprojects008/cli-core.git@v1.0.0"
]

keywords = [
    "engine",
    "framework",
    "parsers",
    "dissection",
    "dissectors",
    "network",
    "sniffer",
    "packets",
    "ethernet",
    "wifi",
    "bluetooth",
    "security"
]

classifiers = [
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.12",
    "Operating System :: POSIX :: Linux",
    "Environment :: Console",
    "Topic :: System :: Networking",
    "Topic :: Security"
]

[project.scripts]
pktparsers = "pktparsers.cli.main:main"
pktparsers-tui = "pktparsers.tui.main:main"

[tool.setuptools.packages.find]
include = ["pktparsers*"]
```

## File: src/pktparsers/core/analysis.py
```python
from pktparsers.core.definitions.result import TRAFFIC_SUMMARY

def make_config(traffic_summary: bool = True):
    return {
        TRAFFIC_SUMMARY: traffic_summary,
    }
```

## File: src/pktparsers/core/dissect.py
```python
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
from pktparsers.core.parsing import insert_item
from pktparsers.core.registry import get_dissector_parser
from pktparsers.core.traffic import TrafficContext
from pktparsers.core.definitions.result import TIMESTAMP
from pktparsers.core.definitions.parsing import (PARSED, RAW, COUNTER)
from pktparsers.core.dissectors import registry
from pktparsers.core.analysis import make_config as make_analysis_config
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
    
    def __init__(self, dissector_id str | int = DLT_IEEE802_11_RADIO, config: DissectConfig = DissectConfig()):
        """
        Args:
            dissector_id: protocol name or DLT type as string ("DLT_IEEE802_11_RADIO") or int (127)
            config: DissectConfig instance (default: empty config)
        """
        self.dissector_id = dissector_id
        self.config = config
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

def make_config() -> AppConfig:
    """
    Build a dissect config using only the defaults baked into the DLT/PROTOCOL

    Useful for:
      - Passive capture analysis (no decryption needed)
      - Tooling that derives config programmatically from pcapng metadata

    The result has empty credentials and default parse/analysis options.
    """

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

    return AppConfig(
        dissect={
            GLOBAL: {
                CRYPT:    {},
                PARSE:    {},
                ANALYSIS: make_analysis_config(),
            },
            DISSECTORS: configs
        },
        output={},
    )
```

## File: src/pktparsers/core/parsing.py
```python
import json
import re
import binascii
import struct
import random
from logging import getLogger
from functools import lru_cache
from contextvars import ContextVar
from pktparsers.core.definitions.parsing import (FMT, TOKENS, SIZE, SIZES, RAW, PARSED, VALUE, METADATA, START, END, EUI48_FMT, OUI_FMT)
from pktparsers.core.definitions.result import (ADDR, FAIL, LENGTH, VENDOR, OUI, SUMMARY)
from pktparsers.core import registry

logger = getLogger(__name__)

class MacVendorResolver:
    _vendor_map = None
    def __init__(self, filepath: str = "./pktparsers/common/parse/mac-vendors-export.json"):
        if MacVendorResolver._vendor_map is None:
            logger.debug(f"Loading MAC vendors file {filepath} ...")
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    MacVendorResolver._vendor_map = {
                        item['macPrefix']: item['vendorName'] for item in data
                    }
                logger.debug("MAC vendors loaded successfully.")
            except (FileNotFoundError, json.JSONDecodeError) as e:
                logger.error(f"Could not load or parse MAC vendors file: {e}")
                MacVendorResolver._vendor_map = {}

    def mac_resolver(self, mac_bytes: bytes):
        mac_address = ':'.join(format(byte, "02x") for byte in mac_bytes)
        if not self._vendor_map or not mac_address:
            return None
        oui = mac_address.upper()[:8]
        return {ADDR: mac_address, VENDOR: self._vendor_map.get(oui)}
    
    def oui_resolver(self, oui_bytes: bytes):
        oui = ':'.join(format(byte, "02x") for byte in oui_bytes)
        if not self._vendor_map or not oui:
            return None
        return {OUI: oui, VENDOR: self._vendor_map.get(oui)}

mac_vendor_resolver = MacVendorResolver()

def bytes_for_mac(mac): 
    return mac_vendor_resolver.mac_resolver(mac)

def bytes_for_oui(oui):
    return mac_vendor_resolver.oui_resolver(oui)

def read_mac() -> dict:
    return unpack(EUI48_FMT, parser=bytes_for_mac)

def read_oui() -> dict:
    return unpack(OUI_FMT, parser=bytes_for_oui)

def random_mac():
    mac = [random.randint(0x00, 0xFF) for _ in range(6)]
    return ':'.join(f"{hex_byte:02x}" for hex_byte in mac)

def mac_for_bytes(mac):
    return bytes(int(hex_byte, 16) for hex_byte in mac.split(":"))

def insert_item(container: dict, key: str | int, val):
    if key not in container:
        container[key] = val
        return
    if not isinstance(container[key], dict) or not all(k.isdigit() for k in container[key]):
        container[key] = {"1": container[key]}
    idx = str(len(container[key]) + 1)
    container[key][idx] = val

def make_addresses(sa: str = None, da: str = None, ta: str = None, ra: str = None):
    return {SA: sa, DA: da, TA: ta, RA: ra}

"""
Context manager for parsing.
ParseContext: maintains offset, buffer bytes, and result dict during parsing
"""
_parse_context = ContextVar("_parse_context")
class ParseContext:
    """
    Context manager for packet parsing.
    Maintains:
        - buffer: raw packet bytes
        - offset: current position in buffer
        - result: accumulated parse result dict
    """
    
    def __init__(self, buffer: bytes, start_offset: int = 0, dissector_id: str | int = None): # dissector_id could be, for example: ieee802_11, DLT_IEEE802_11 or 127
        self.buffer = buffer
        self.offset = start_offset
        self.result = {}
        self.dissector_id = dissector_id 
        self._token = None

    def get_addresses(self) -> dict:
        dissector_entry = registry.get_dissector(self.dissector_id).
        if dissector_entry and dissector_entry.address_extractor:
            return dissector_entry.address_extractor(self.result)
        return make_addresses()

    def __enter__(self):
        self._token = _parse_context.set(self)
        return self

    def __exit__(self, *args):
        if self._token:
            _parse_context.reset(self._token)

    @staticmethod
    def current() -> "ParseContext":
        """Get the current ParseContext from context var"""
        return _parse_context.get(None)

def size_to_struct_fmt(size: int) -> str:
    mapping = {
        1: "B",
        2: "H",
        4: "I",
        8: "Q"
    }
    if size not in mapping:
        raise ValueError(f"Unsupported struct size: {size}")
    return mapping[size]

@lru_cache(maxsize=256)
def _parse_fmt_tokens(fmt: str) -> tuple[tuple[int, ...], tuple[str, ...]]:
    s = struct.Struct(fmt)

    prefix = '<'
    if fmt and fmt[0] in '<>!=@':
        prefix = fmt[0]
        fmt = fmt[1:]

    tokens: list[str] = []
    count_buf = ''

    for ch in fmt:
        if ch.isdigit():
            count_buf += ch
        else:
            count = int(count_buf) if count_buf else 1
            if ch in ('s', 'p'):
                tokens.append(f"{prefix}{count}{ch}")
            else:
                tokens.extend([prefix + ch] * count)
            count_buf = ''

    if count_buf:
        raise ValueError(f"Invalid format: ends with count without type '{count_buf}'")

    sizes = tuple(struct.calcsize(t) for t in tokens)

    return sizes, tuple(tokens), s

def _add_metadata(raw: bytes, start_offset: int, end_offset: int, fmt: str | dict, tokens: str | dict, sizes: int | dict, size: int):
    raw_hex = raw[start_offset:end_offset].hex()
    length = end_offset - start_offset
    return {
        METADATA: {
            START: start_offset,
            END: end_offset,
            LENGTH: length,
            RAW: raw_hex,
            FMT: fmt,
            TOKENS: tokens,
            SIZES: sizes,
            SIZE: size
        }
    }

def unpack(fmt: str = None, parser: callable = None, summarizer: str | callable = None, **kwargs) -> dict:
    def value_to_dict(value):
        return {i: v for i, v in enumerate(value)} if isinstance(value, tuple) else value

    result = {}

    ctx = ParseContext.current()
    raw = ctx.buffer
    offset = ctx.offset
    start = offset
    fmt = (fmt or f"{len(raw) - start}s").replace(" ", "")
    sizes, tokens, s = _parse_fmt_tokens(fmt)
    size = s.size

    fmt = value_to_dict(fmt)
    sizes = value_to_dict(sizes)
    tokens = value_to_dict(tokens)
    future_offset = start + size
    result.update(_add_metadata(raw, start, future_offset, fmt, tokens, sizes, size))

    if offset + size > len(raw):
        logger.debug(f"Truncated raw: start_offset={offset} fmt={fmt} sizes={sizes} size={size}")
        return fail(result, future_offset, "Unpack error truncated")

    value = s.unpack_from(raw, offset)

    ctx.offset = future_offset

    result[VALUE] = value_to_dict(value)

    parser_result = None

    if parser:
        parser_result = normalize_bytes(parser(value, **kwargs))
        result[PARSED] = parser_result

    if summarizer:
        summarizer_result = summarizer(parser_result, **kwargs) if (parser_result and callable(summarizer)) else summarizer
        if summarizer_result:
            result[SUMMARY] = summarizer_result

    return result

def run_dispatch(dispatch_table: dict, dispatch_id, fallback: callable = None, **kwargs):
    logger.debug("run dispatch")

    entry = dispatch_table.get(dispatch_id)

    dispatch_ctx = {
        "dispatch_id": dispatch_id,
        "dispatch_table": dispatch_table,
        "dispatch_fallback": fallback,
        "dispatch_entry": entry
    }

    kwargs["dispatch_ctx"] = dispatch_ctx

    handler = None

    if callable(entry):
        handler = entry

    elif isinstance(entry, dict):
        handler = entry.get("parser")

    if handler:
        return handler(**kwargs)

    if fallback:
        return fallback(**kwargs)

    logger.debug(f"No handler for dispatch_id={dispatch_id}, using unpack fallback")

    return unpack(**kwargs)

def detect_fcs(fcs_len: int) -> bytes | None:
    ctx = ParseContext.current
    buffer = ctx.buffer
    offset = ctx.offset
    logger.debug("detect_fcs function")
    flen = len(buffer)
    logger.debug(f"detect_fcs function: buffer:{buffer} offset={offset} flen={flen}")

    if offset is None or offset < 0 or offset >= flen:
        return None

    payload_len = flen - offset
    if payload_len < fcs_len:
        return None

    fcs_start = flen - fcs_len
    fcs_bytes = buffer[fcs_start:flen]
    candidate_fcs = int.from_bytes(fcs_bytes, "little")
    data_for_crc = buffer[offset:fcs_start]
    calc_crc = binascii.crc32(data_for_crc) & 0xFFFFFFFF

    if calc_crc == candidate_fcs:
        ctx.buffer = buffer[:fcs_start]
        return fcs_bytes.hex()
    else:
        return None

def fail(result: dict, expected_size: int, e: str = "Parser error", debug_msg: str = "Parse error"):
    logger.debug("fail function")
    ctx = ParseContext.current()
    insert_item(result, FAIL, e)
    buffer_len = len(ctx.buffer)
    if expected_size is not None:
        ctx.offset = min(expected_size, buffer_len)
    logger.debug(f"{debug_msg} buffer_len={buffer_len} ctx.offset={ctx.offset} expected_size={expected_size} result={result}")
    return result

def bitmap_dict_to_hex(bitmap_dict: dict):
    result = 0
    for i, (field, active) in enumerate(bitmap_dict.items()):
        if active:
            result |= (1 << i)
    return result

def bitmap_value_for_dict(bitmap_value: int, field_names: list[str]) -> dict:
    result = {}
    for i, name in enumerate(field_names):
        result[name] = bool(bitmap_value & (1 << i))
    return result

def clean_hex_string(s: str) -> str:
    s = s.strip().strip("'").strip('"')
    return re.sub(r'[^0-9a-fA-F]', '', s).lower()

def bytes_encoder(obj):
    if isinstance(obj, bytes):
        return obj.hex()
    raise TypeError(f"Type {type(obj)} not serializable")

def normalize_bytes(obj):
    if isinstance(obj, dict):
        return {k: normalize_bytes(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [normalize_bytes(v) for v in obj]
    elif isinstance(obj, bytes):
        return obj.hex()
    return obj

def calc_offset_from_fmt(tokens: dict, field_index: int) -> int:
    offset = 0
    for i in range(field_index):
        offset += struct.calcsize(tokens[i])
    return offset

def clear_field(raw: bytes, metadata: dict, field_index: int, field_length: int) -> bytes:
    tokens = metadata[TOKENS]
    offset = calc_offset_from_fmt(tokens, field_index)
    buffer = bytearray(raw)
    buffer[offset : offset + field_length] = b"\x00" * field_length
    return bytes(buffer)

def raw_packet_extractor(key=RAW):
    def extractor(data):
        value = data.get(key)

        if isinstance(value, str):
            cleaned = clean_hex_string(value)
            if cleaned:
                yield (cleaned, bytes.fromhex(cleaned))

        elif isinstance(value, list):
            for entry in value:
                if isinstance(entry, str):
                    cleaned = clean_hex_string(entry)
                    if cleaned:
                        yield (cleaned, bytes.fromhex(cleaned))
    return extractor

def wireshark_format(packet_bytes):
    return ":".join(f"{byte:02x}" for byte in packet_bytes)

def freq_converter(freq_unit: tuple, to_unit: str):
    freq, unit = freq_unit
    unit = unit.lower()
    to_unit = to_unit.lower()
    
    if  unit == 'khz':
        base_freq = freq
    elif unit == 'mhz':
         base_freq = freq * 1000
    elif unit == 'ghz':
         base_freq = freq * 1000000
    else:
        raise ValueError(f"Invalid source unit: {unit} Use 'kHz', 'MHz' ou 'GHz'")
    
    if to_unit == 'khz':
       return base_freq
    elif to_unit == 'mhz':
         return base_freq / 1000
    elif to_unit == 'ghz':
         return base_freq / 1000000
    else:
        raise ValueError(f"Destiny unit invalid: {to_unit}. Use 'kHz', 'MHz' ou 'GHz'")

def freq_to_channel(freq_mhz) -> int:
    if not freq_mhz:
        return freq_mhz
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5
    if freq_mhz == 2484:
        return 14
    if 5000 <= freq_mhz <= 5895:
        return (freq_mhz - 5000) // 5
    return "Unknown"

def calc_rates(rates):
    list_rates_transmition = []
    for rate in rates:   
        value_rate = (rate & 0x7f) * 500
        list_rates_transmition.append(value_rate)
    return list_rates_transmition

def find_path(root, target, path=None):
    if path is None:
        path = []

    if root is target:
        return path

    if isinstance(root, dict):
        for k, v in root.items():
            res = find_path(v, target, path + [k])
            if res:
                return res

    elif isinstance(root, list):
        for i, v in enumerate(root):
            res = find_path(v, target, path + [str(i)])
            if res:
                return res

    return None

def clean_path(path):
    return ".".join([p for p in path if p != "parsed"])

def generate_parse_config():
    pass

# pktparsers/core/parsing.py  — adicionar

def build_from_parsed(parsed: dict) -> bytes:
    """
    Reconstrói bytes brutos a partir de um dict parsed editado.
    
    Para cada nó com _metadata_:
        - Usa tokens e sizes para saber o struct format de cada campo
        - Se o value atual for maior que o fmt original, expande o fmt
        - Se for menor, aplica padding até o tamanho original
    
    Percorre a árvore em DFS na mesma ordem em que foi construída
    (ordem de inserção dict é garantida em Python 3.7+).
    """
    result = bytearray()
    _collect_bytes(parsed, result)
    return bytes(result)

def _collect_bytes(node: dict, out: bytearray) -> None:
    if not isinstance(node, dict):
        return

    meta = node.get(METADATA)
    if meta and VALUE in node:
        _pack_field(meta, node[VALUE], out)
        return  # nó folha — não desce para PARSED (já foi compactado no VALUE)

    # Nó intermediário — desce para PARSED
    inner = node.get(PARSED)
    if isinstance(inner, dict):
        for v in inner.values():
            _collect_bytes(v, out)
    elif isinstance(node, dict):
        for k, v in node.items():
            if k not in (METADATA, VALUE, PARSED, SUMMARY):
                _collect_bytes(v, out)

def _pack_field(meta: dict, value, out: bytearray) -> None:
    tokens = meta.get(TOKENS, {})
    sizes  = meta.get(SIZES,  {})

    if not tokens:
        # Sem tokens — raw bytes direto
        if isinstance(value, str):
            out.extend(bytes.fromhex(value))
        elif isinstance(value, (bytes, bytearray)):
            out.extend(value)
        return

    values = value if isinstance(value, dict) else {0: value}

    for idx, token in tokens.items():
        v   = values.get(idx, 0)
        sz  = sizes.get(idx, struct.calcsize(token))

        # Normaliza tipo
        if isinstance(v, str):
            try:
                v = bytes.fromhex(v)
            except ValueError:
                v = v.encode()

        if isinstance(v, (bytes, bytearray)):
            actual_sz = len(v)
            if actual_sz > sz:
                # value cresceu — expande fmt
                out.extend(v)
            else:
                # padding à direita
                out.extend(v + b"\x00" * (sz - actual_sz))
        else:
            out.extend(struct.pack(token.replace("<", "<").replace(">", ">"), v))
```

## File: src/pktparsers/core/traffic.py
```python
# pktparsers/core/traffic.py

import time
from contextvars import ContextVar
from .defintions import ANNOTATIONS, DEVICES, FIRST_SEEN, LAST_SEEN, PROTOCOLS_DATA

def make_device_entry() -> dict:
    return {
        FIRST_SEEN: time.time(),
        LAST_SEEN:  time.time(),
        PROTOCOLS_DATA: {},
        ANNOTATIONS: {},
    }

def make_traffic_summary() -> dict:
    return {
        DEVICES: {},
        ANNOTATIONS: {},
    }

"""
Context manager traffic analysis.
TrafficContext: accumulates traffic statistics across dissected packets
"""

_traffic_context = ContextVar("_traffic_context")

class TrafficContext:
    def __init__(self):
        self.summary = make_traffic_summary()

    def __enter__(self):
        self._token = _traffic_context.set(self)
        return self

    def __exit__(self, *args):
        _traffic_context.reset(self._token)

    @classmethod
    def current(cls) -> "TrafficContext | None":
        return _traffic_context.get(None)
```
