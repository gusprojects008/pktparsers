This file is a merged representation of a subset of the codebase, containing specifically included files and files not matching ignore patterns, combined into a single document by Repomix.

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
- Only files matching these patterns are included: **/*.py
- Files matching these patterns are excluded: .venv, .git, __pycache__, docs, *.json
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
      layers/
        l1/
          __init__.py
        l2/
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
                  control.py
                data/
                  data.py
                ie/
                  definitions.py
                  parse.py
                mac_header/
                  definitions.py
                  mac_header.py
                management/
                  management.py
                body.py
                common.py
              __init__.py
              definitions.py
              parse.py
            dot1x/
              eap/
                parse.py
              eapol/
                analyzers/
                  summary.py
                definitions.py
                parse.py
              radius/
                parse.py
              __init__.py
            dot2/
              llc/
                definitions.py
                parse.py
            dot3/
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
            definitions.py
        l3/
          arp/
            parse.py
          ip/
            analyzers/
              definitions.py
              summary.py
            dlt/
              raw/
                parse.py
            definitions.py
            parse.py
          __init__.py
        l4/
          __init__.py
        l7/
          __init__.py
        __init__.py
      __init__.py
      crypt.py
      definitions.py
      dissect.py
      filter_engine.py
      parsing.py
      registry.py
      traffic.py
    io/
      io.py
      reader.py
      src_pktparsers_io___init__.py
    tui/
      widgets/
        fieldeditor.py
        hexview.py
        packettree.py
      __init__.py
      __main__.py
      app.py
      main.py
    __init__.py
    __main__.py
tests/
  bitmap_key_information.py
  tests.py
```

# Files

## File: src/pktparsers/app/app.py
```python
from dataclasses import dataclass
from pktparsers.io import OutputConfig

class PktparsersConfig:
    dissect_cfg: DissectConfig = DissectConfig()
    output_cfg: OutputConfig = OutputConfig()
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

class AppContext:
    """
    Manages application directories and configuration.
    
    Attributes:
        real_user: actual user (respects SUDO_USER)
        home_dir: user's home directory
        config_dir: ~/.config/pktparsers
        cache_dir: ~/.cache/pktparsers
        log_file: path to main log file
    """
    
    def __init__(self, config: dict = None, log_file: Path = None):
        self.config = config or {}
        
        # Determine real user (handle sudo)
        self.real_user = os.environ.get("SUDO_USER") or os.getlogin()
        pw = pwd.getpwnam(self.real_user)
        self.home_dir = Path(pw.pw_dir)
        
        # Setup dirs
        self.config_dir = self.home_dir / ".config" / "pktparsers"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.chmod(0o740)
        
        self.cache_dir = self.home_dir / ".cache" / "pktparsers"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.chmod(0o740)
        
        self.log_file = log_file or (self.cache_dir / "pktparsers.log")
        
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

## File: src/pktparsers/cli/__init__.py
```python

```

## File: src/pktparsers/cli/__main__.py
```python
from pktparsers.cli.main import main
main()
```

## File: src/pktparsers/cli/main.py
```python
#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import argcomplete
from pathlib import Path
from cli_core.log import setup_logging
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

## File: src/pktparsers/common/__init__.py
```python

```

## File: src/pktparsers/core/layers/l1/__init__.py
```python

```

## File: src/pktparsers/core/layers/l2/bluetooth/hci/transports/h4.py
```python

```

## File: src/pktparsers/core/layers/l2/bluetooth/hci/parse.py
```python

```

## File: src/pktparsers/core/layers/l2/bluetooth/hci/registry.py
```python

```

## File: src/pktparsers/core/layers/l2/bluetooth/__init__.py
```python

```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/analyzers/definitions.py
```python
# core/layers/l2/ieee802/dot11/analyzers/definitions.py

def make_dot11_device() -> dict:
    return {
        "role": "unknown",
        "ssids": [],
        "channels_seen": [],
        "frames_sent": 0,
        "frames_received": 0,
        "retry_count": 0,
        "relationships": {}, # {peer_mac: {"sent": int, "recv": int, "retry": int}}
        "annotations": {}
    }
```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/analyzers/summary.py
```python

```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/dlt/ieee802_11/analyzers/definitions.py
```python

```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/dlt/ieee802_11/analyzers/summary.py
```python

```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/dlt/ieee802_11/parse.py
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
```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/dlt/ieee802_11_radio/analyzers/definitions.py
```python

```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/dlt/ieee802_11_radio/analyzers/summary.py
```python
# dlt/ieee802_11_radio/analyzers/summary.py
from pktparsers.core.analyzers.traffic.context import TrafficContext

def summarize(parsed: dict): # recebe "result" de ParseContext para gerar summary.
    rt_hdr = parsed.get(RT_HEADER)
    rt_hdr_summary = "radiotap header"
    dot11 = parsed.get(DOT11)
    dot11_summary = dot11.analyzers.summary.summarize(dot11)
    return summary

def analyzer(parsed: dict, parser_summary: dict): # Analisa o summary do frame dot11 por exemplo, e obtém as informações necessárias para criar ou atualizar as variáveis de TrafficSummary, muitas vezes, ela analisará as próprias variáveis de TrafficSummary antes de criar ou atualizar as variáveis de TrafficSummary.
    traffic_ctx = TrafficContext.current()
    if traffic_ctx is None:
        return          # parse chamado sem Dissector

    traffic = traffic_ctx.summary

    # ... lógica de criar/atualizar DeviceEntry em traffic

    rt_hdr = parsed.get(RT_HDR)
    rt_hdr_summary = parser_summary.get(RT_HDR)

    dot11 = parsed.get(DOT11)
    dot11_summary = parser_summary.get(DOT11)

    dot11_device = {}

    pass
```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/dlt/ieee802_11_radio/parsers/radiotap_header.py
```python
from logging import getLogger
from pktparsers.common.parse.utils import (
    ParseContext, unpack, bitmap_value_for_dict, freq_to_channel, fail
)

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

## File: src/pktparsers/core/layers/l2/ieee802/dot11/dlt/ieee802_11_radio/definitions.py
```python
BAD_FCS = "bad_fcs"
RT_HDR = "rt_hdr"
```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/dlt/ieee802_11_radio/parse.py
```python
from logging import getLogger
from pktparsers.core.layers.l2.ieee802.dot11.dlt.ieee802_11_radio.parsers.radiotap_header import parse as parse_radiotap
from pktparsers.core.layers.l2.ieee802.dot11.dlt.ieee802_11_radio.definitions import BAD_FCS, RT_HDR
from pktparsers.core.layers.l2.ieee802.dot11.parse import parse_dot11
from pktparsers.common.parse.utils import ParseContext, detect_fcs
from pktparsers.common.parse.definitions import (FLAGS, SUMMARY, PARSED)
from pktparsers.core.layers.l2.ieee802.dot11.definitions import *

logger = getLogger(__name__)

def parse(frame: bytes, offset: int = 0) -> dict:
    logger.debug("Frame parse")
    result = None
    try:
        with ParseContext(frame, offset) as ctx:
            insert_item(ctx.result, RT_HDR, radiotap_header.parser())
            rt_hdr = ctx.result.get(RT_HDR)
            if not rt_hdr is None or {}:
                logger.debug("Unexpected radiotap header error")
                return ctx.result
            rt_flags = rt_hdr.get(PARSED, {}).get(FLAGS, {})
            bad_fcs = rt_flags.get(BAD_FCS)
            if bad_fcs:
                logger.debug(f"Dropping frame: {BAD_FCS} indicated by radiotap")
                return ctx.result
            parse_dot11()
            summary = summary.summarize(ctx.result)
            insert_item(ctx.result, SUMMARY, summary)
            analyzer(ctx.result, summary)
            result = ctx.result
    except Exception as e:
        logger.debug(f"Frames parser error: {e}")
    return result
```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/parsers/control/control.py
```python
from core.common.parser import (unpack, run_dispatch)
from core.layers.l2.ieee802.dot11.constants import *

def ctrl_block_ack_request(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        ctrl, start_seq = value
        return {
            "block_ack_control": ctrl,
            "block_ack_start_seq": start_seq
        }
    return unpack("<HH", parser=_parser)

def ctrl_block_ack(**kwargs) -> dict:
    return unpack("<Q", parser=lambda v: {"block_ack_bitmap": v})

def ctrl_ps_poll(**kwargs) -> dict:
    return unpack("<H", parser=lambda v: {"aid": v & 0x3FFF})

def ctrl_ack(**kwargs) -> dict:
    return unpack()

def ctrl_cf_end(**kwargs) -> dict:
    return unpack()

def ctrl_cf_end_ack(**kwargs) -> dict:
    return unpack()

DISPATCH_TABLE = {
    CTRL_BLOCK_ACK_REQUEST: ctrl_block_ack_request,
    CTRL_BLOCK_ACK: ctrl_block_ack,
    CTRL_PS_POLL: ctrl_ps_poll,
    CTRL_ACK: ctrl_ack,
    CTRL_CF_END: ctrl_cf_end,
    CTRL_CF_END_ACK: ctrl_cf_end_ack,
}

def parser(**kwargs):
    return run_dispatch(DISPATCH_TABLE, kwargs.get("subtype"))
```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/parsers/data/data.py
```python
from logging import getLogger
from core.layers.l2.ieee802.llc.parser import parser as llc_parser
from core.layers.l2.ieee802.dot11.constants import *

logger = getLogger(__name__)

def parser(**kwargs) -> dict:
    subtype = kwargs.get("subtype")
    logger.debug(f"DATA Parser - Subtype: {subtype}")
    
    body = {}

    if subtype in NULL_DATA_SUBTYPES:
        logger.debug("Null Data frame detected: skipping LLC parser")
        return body
    
    try:
        body["llc"] = llc_parser()
    except Exception as e:
        logger.warning(f"Could not parse LLC on data frame: {e}")
    
    return body
```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/parsers/ie/definitions.py
```python
from pktparsers.core.layers.l2.ieee802.dot1x.eapol.definitions import EAPOL_PMKID_FMT

MIN_IE_LEN = 2

TAG_SSID = 0
TAG_SUPPORTED_RATES = 1
TAG_CURRENT_CHANNEL = 3
TAG_TIM = 5
TAG_COUNTRY = 7
TAG_QBSS_LOAD = 11
TAG_POWER_CONSTRAINT = 32
TAG_TPC_REPORT = 35
TAG_ERP = 42
TAG_HT_CAPABILITIES = 45
TAG_RM_ENABLED_CAPABILITIES = 70
TAG_RSN_INFORMATION = 48
TAG_EXTENDED_SUPPORTED_RATES = 50
TAG_EXTENDED_CAPABILITIES = 127
TAG_VENDOR_SPECIFIC = 221
TAG_EXTENDED_HE = 255

TAG_SSID_NAME = "ssid"
TAG_SUPPORTED_RATES_NAME = "supported_rates"
TAG_CURRENT_CHANNEL_NAME = "current_channel"
TAG_TIM_NAME = "tim"
TAG_COUNTRY_NAME = "country"
TAG_QBSS_LOAD_NAME = "qbss_load"
TAG_POWER_CONSTRAINT_NAME = "power_constraint"
TAG_TPC_REPORT_NAME = "tpc_report"
TAG_ERP_NAME = "erp"
TAG_EXTENDED_SUPPORTED_RATES_NAME = "extended_supported_rates"
TAG_VENDOR_SPECIFIC_NAME = "vendor_specific"
TAG_HT_CAPABILITIES_NAME = "ht_capabilities"
TAG_RM_ENABLED_CAPABILITIES_NAME = "rm_enabled_capabilities"
TAG_RSN_INFORMATION_NAME = "rsn_information"
TAG_EXTENDED_CAPABILITIES_NAME = "extended_capabilities"
TAG_EXTENDED_HE_NAME = "extended_he"

OUI_MICROSOFT = "00:50:f2"
OUI_IEEE_80211 = "00:0f:ac"
OUI_WFA = "50:6f:9a"
OUI_MEDIATEK = "00:0c:43"
OUI_BROADCOM = "00:10:18"
OUI_ATHEROS = "00:03:7f"

MS_VENDOR_WPA = 1
MS_VENDOR_WPS = 4
MS_VENDOR_WMM_WME = 2

RSN_VENDOR_RSN_IE = 1
RSN_VENDOR_RSN_IE_ALT = 2
RSN_VENDOR_PMKID = 4

WFA_VENDOR_WPS = 4
WFA_VENDOR_P2P = 9
WFA_VENDOR_HS20 = 16
WFA_VENDOR_OSEN = 18

# ===========================
# Constantes de formato (struct)
# ===========================
OUI_FMT = "3s"
BYTE_FMT = "B"
WORD_FMT = "<H"
DWORD_FMT = "<I"
SHORT_FMT = ">H"   # big-endian short (para WPS attr type/length)
WPS_ATTR_FMT = ">HH"                # usado em _wps_extension
WMM_WME_FMT = "<BBH"                # usado em _wmm_wme_extension
RSN_CAPS_FMT = "<H"                 # usado em _rsn_capabilities
VENDOR_SPECIFIC_FMT = OUI_FMT + "B" # "3sB"
TIM_FMT = "<BBB"                    # tim_info
COUNTRY_FMT = "3sB"                 # country_code (básico)
COUNTRY_SUB_FMT = "<BBB"            # sub-elementos do country
ERP_FMT = "B"                       # erp_info
HT_CAPS_FMT = "<HB10sHBBBHIBB"      # ht_capabilities
RM_CAPS_FMT = "BB"                  # rm_enable_capabilities
QBSS_LOAD_FMT = "<HBH"              # qbss_load_element
TPC_REPORT_FMT = "BB"               # tcp_report
RSN_VERSION_FMT = "<H"              # rsn_information version
RSN_CIPHER_FMT = "3sB"              # group_cipher, pairwise_cipher
RSN_AKM_FMT = "3sB"                 # akm_suite
RSN_PMKID_FMT = EAPOL_PMKID_FMT  # 16s

# ===========================
# Constantes para tamanhos de campos
# ===========================
HT_CAPABILITIES_LEN = 26
RM_CAPABILITIES_LEN = 2
QBSS_LOAD_LEN = 5
TIM_MIN_LEN = 4
COUNTRY_MIN_LEN = 4
RSN_MIN_LEN = 2
EXTENDED_HE_MIN_LEN = 2

# ===========================
# Constantes de nomes de chaves (keys)
# ===========================
# Gerais
ATTR_TYPE = "attr_type"
ATTR_LENGTH = "attr_length"
FIELDS = "fields"
VENDOR_TYPE = "vendor_type"
VENDOR_ID = "vendor_id"
TAG_NUMBER = "tag_number"
TAG_LENGTH = "tag_length"
EXTENSION_ID = "extension_id"
EXTENSION_NAME = "extension_name"
PARSED_BYTE0 = "byte0"
PARSED_BYTE1 = "byte1"
PARSED_BYTE2 = "byte2"
PARSED_BYTE3 = "byte3"

# WPS
WPS_VERSION = "version"
WPS_STATE = "wps_state"
WPS_STATE_VALUE = "wps_state_value"
WPS_RESPONSE_TYPE = "response_type"
WPS_RESPONSE_TYPE_VALUE = "response_type_value"
WPS_UUID = "uuid"
WPS_MANUFACTURER = "manufacturer"
WPS_MODEL = "model"
WPS_MODEL_NUMBER = "model_number"
WPS_SERIAL_NUMBER = "serial_number"
WPS_DEVICE_NAME = "device_name"
WPS_PRIMARY_DEVICE_TYPE = "primary_device_type"
WPS_PRIMARY_DEVICE_TYPE_CATEGORY = "primary_device_type_category"
WPS_PRIMARY_DEVICE_TYPE_SUBCATEGORY = "primary_device_type_subcategory"
WPS_CONFIG_METHODS = "config_methods"
WPS_CONFIG_METHODS_VALUE = "config_methods_value"
WPS_RF_BANDS = "rf_bands"
WPS_RF_BANDS_VALUE = "rf_bands_value"
WPS_VENDOR_EXTENSION = "vendor_extension"
WPS_VERSION2 = "version2"
WPS_REQUEST_TO_ENROLL = "request_to_enroll"

# ===========================
# Constantes para WPS Vendor Extension subelements
# ===========================
WPS_VENDOR_EXT_VERSION2 = 0
WPS_VENDOR_EXT_REQUEST_TO_ENROLL = 1


# WMM/WME
WME_SUBTYPE = "wme_subtype"
WME_VERSION = "wme_version"
WME_QOS_INFO = "qos_info"
WME_AC_PARAMETERS = "ac_parameters"
WME_AC_INDEX = "ac_index"
WME_AIFSN = "aifsn"
WME_ECW_MIN = "ecw_min"
WME_ECW_MAX = "ecw_max"
WME_TXOP_LIMIT = "txop_limit"

# RSN capabilities (primeira versão, usada em vendor_specific)
RSN_CAPS_PRE_AUTH = "pre_auth"
RSN_CAPS_NO_PAIRWISE = "no_pairwise"
RSN_CAPS_PTKSA_REPLAY_COUNTER_LIMIT = "ptksa_replay_counter_limit"
RSN_CAPS_GTKSA_REPLAY_COUNTER_LIMIT = "gtksa_replay_counter_limit"
RSN_CAPS_MFP_REQUIRED = "management_frame_protection_required"
RSN_CAPS_MFP_CAPABLE = "management_frame_protection_capable"
RSN_CAPS_OCVC = "ocvc"

# Rates
RATE_VALUE = "value"
RATE_BASIC = "basic"

# TIM
DTIM_COUNT = "dtim_count"
DTIM_PERIOD = "dtim_period"
DTIM_BITMAP_CONTROL = "bitmap_control"
DTIM_PARTIAL_VIRTUAL_BITMAP = "partial_virtual_bitmap"
DTIM_MULTICAST = "multicast"
DTIM_BITMAP_OFFSET = "bitmap_offset"

# Country
COUNTRY_CODE = "country_code"
COUNTRY_ENVIRONMENT = "environment"
COUNTRY_SUB_ELEMENTS = "sub_elements"

# Constantes para nomes de campos do country sub-element
COUNTRY_FIRST_CHANNEL = "first_channel"
COUNTRY_NUM_CHANNELS = "num_channels"
COUNTRY_MAX_TX_POWER = "max_tx_power"

# ERP
ERP_NON_ERP_PRESENT = "non_erp_present"
ERP_USE_PROTECTION = "use_protection"
ERP_BARKER_PREAMBLE_MODE = "barker_preamble_mode"

# HT Capabilities
HT_CAPS_INFO = "ht_caps_info"
HT_LDPC_CODING_CAPABLE = "ldpc_coding_capable"
HT_SUPPORTED_CHANNEL_WIDTH = "supported_channel_width"
HT_SM_POWER_SAVE = "sm_power_save"
HT_GREEN_FIELD = "green_field"
HT_SHORT_GI_20MHZ = "short_gi_20mhz"
HT_SHORT_GI_40MHZ = "short_gi_40mhz"
HT_TX_STBC = "tx_stbc"
HT_RX_STBC = "rx_stbc"
HT_DELAYED_BLOCK_ACK = "delayed_block_ack"
HT_MAX_AMSDU_LENGTH = "max_amsdu_length"
HT_DSSS_CCK_40MHZ = "dsss_cck_40mhz"
HT_FORTY_MHZ_INTOLERANT = "forty_mhz_intolerant"
HT_LSIG_TXOP_PROTECTION = "lsig_txop_protection"
HT_AMPDU_PARAMS = "ampdu_params"
HT_MAX_RX_AMPDU_LENGTH_EXPONENT = "max_rx_ampdu_length_exponent"
HT_MIN_MPDU_START_SPACING = "min_mpdu_start_spacing"
HT_RX_MCS_BITMASK = "rx_mcs_bitmask"
HT_HIGHEST_SUPPORTED_RATE = "highest_supported_rate"
HT_TX_MCS_INFO = "tx_mcs_info"
HT_TX_MCS_SET_DEFINED = "tx_mcs_set_defined"
HT_TX_RX_MCS_SET_EQUAL = "tx_rx_mcs_set_equal"
HT_MAX_TX_SPATIAL_STREAMS = "max_tx_spatial_streams"
HT_UNEQUAL_MODULATION = "unequal_modulation"
HT_EXT_CAPS = "ht_ext_caps"
HT_PCO_SUPPORT = "pco_support"
HT_PCO_TRANSITION_TIME = "pco_transition_time"
HT_MCS_FEEDBACK = "mcs_feedback"
HT_HTC_SUPPORT = "htc_support"
HT_REVERSE_DIRECTION_RESPONDER = "reverse_direction_responder"
HT_TXBF_CAPS = "txbf_caps"
HT_IMPLICIT_BF_RX = "implicit_bf_rx"
HT_RX_STAGGERED_SOUNDING = "rx_staggered_sounding"
HT_TX_STAGGERED_SOUNDING = "tx_staggered_sounding"
HT_RX_NDP = "rx_ndp"
HT_TX_NDP = "tx_ndp"
HT_ASEL_CAPS = "asel_caps"
HT_ASEL_CAPABLE = "asel_capable"
HT_EXPLICIT_CSI_FEEDBACK_TX_ASEL = "explicit_csi_feedback_tx_asel"
HT_ANTENNA_INDICES_FEEDBACK_TX_ASEL = "antenna_indices_feedback_tx_asel"
HT_EXPLICIT_CSI_FEEDBACK = "explicit_csi_feedback"
HT_ANTENNA_INDICES_FEEDBACK = "antenna_indices_feedback"
HT_RX_ASEL = "rx_asel"

# RM Enabled Capabilities
RM_BYTE0 = "byte0"
RM_BYTE1 = "byte1"
RM_LINK_MEASUREMENT = "link_measurement"
RM_NEIGHBOR_REPORT = "neighbor_report"
RM_PARALLEL_MEASUREMENTS = "parallel_measurements"
RM_REPEATED_MEASUREMENTS = "repeated_measurements"
RM_BEACON_PASSIVE_MEASUREMENT = "beacon_passive_measurement"
RM_BEACON_ACTIVE_MEASUREMENT = "beacon_active_measurement"
RM_BEACON_TABLE_MEASUREMENT = "beacon_table_measurement"
RM_BEACON_MEASUREMENT_REPORTING = "beacon_measurement_reporting"
RM_FRAME_MEASUREMENT = "frame_measurement"
RM_CHANNEL_LOAD_MEASUREMENT = "channel_load_measurement"
RM_NOISE_HISTOGRAM_MEASUREMENT = "noise_histogram_measurement"
RM_STATISTICS_MEASUREMENT = "statistics_measurement"
RM_LCI_MEASUREMENT = "lci_measurement"
RM_LCI_AZIMUTH = "lci_azimuth"
RM_TX_STREAM_CATEGORY_MEASUREMENT = "tx_stream_category_measurement"
RM_TRIGGERED_TX_STREAM_MEASUREMENT = "triggered_tx_stream_measurement"

# Extended Capabilities
EXT_CAPS_BSS_COEXISTENCE = "bss_coexistence"
EXT_CAPS_EXTENDED_CHANNEL_SWITCHING = "extended_channel_switching"
EXT_CAPS_PSMP_CAPABILITY = "psmp_capability"
EXT_CAPS_BSS_TRANSITION = "bss_transition"
EXT_CAPS_INTERWORKING = "interworking"

# QBSS Load
QBSS_LOAD_STATION_COUNT = "station_count"
QBSS_LOAD_CHANNEL_UTILIZATION = "channel_utilization"
QBSS_LOAD_AVAILABLE_ADMISSION_CAPACITY = "available_admission_capacity"

# TPC Report
TCP_REPORT_TX_POWER = "tx_power"
TCP_REPORT_RESERVED = "reserved"

# RSN Information
RSN_INFO_RSN_VERSION = "version"
RSN_INFO_GROUP_CIPHER = "group_cipher"
RSN_INFO_PAIRWISE_CIPHERS = "pairwise_ciphers"
RSN_INFO_AKM_SUITES = "akm_suites"
RSN_INFO_AKM_SUITE_COUNT = "akm_suite_count"
RSN_INFO_CAPABILITIES = "capabilities"
RSN_INFO_PMKIDS = "pmkids"
RSN_INFO_PMKID_COUNT = "pmkid_count"
RSN_INFO_CIPHER_TYPE = "cipher_type"
RSN_INFO_AKM_TYPE = "akm_type"
RSN_INFO_JOINT_MULTI_BAND_RSNA = "joint_multi_band_rsna"
RSN_INFO_PEERKEY_ENABLED = "peerkey_enabled"
RSN_INFO_SPP_AMSDU_CAPABLE = "spp_amsdu_capable"
RSN_INFO_SPP_AMSDU_REQUIRED = "spp_amsdu_required"
RSN_INFO_PBAC = "pbac"
RSN_INFO_EXTENDED_KEY_ID = "extended_key_id"
RSN_INFO_RESERVED_BIT = "reserved"
RSN_INFO_PRE_AUTH = "pre_auth"
RSN_INFO_NO_PAIRWISE = "no_pairwise"
RSN_INFO_PTKSA_REPLAY_COUNTER = "ptksa_replay_counter"
RSN_INFO_GTKSA_REPLAY_COUNTER = "gtksa_replay_counter"
RSN_INFO_MFP_REQUIRED = "mgmt_frame_protection_required"
RSN_INFO_MFP_CAPABLE = "mgmt_frame_protection_capable"
RSN_INFO_OCVC = "ocvc"

# Extended HE
EXT_HE_CAPABILITIES = 35
EXT_HE_OPERATION = 36
EXT_HE_UORA_PARAMETER_SET = 39
EXT_HE_SHORT_BEACON_INTERVAL = 59
EXT_HE_EHT_CAPABILITIES = 108

EXT_HE_CAPABILITIES_NAME = "HE_CAPABILITIES"
EXT_HE_OPERATION_NAME = "HE_OPERATION"
EXT_HE_UORA_PARAMETER_SET_NAME = "UORA_PARAMETER_SET"
EXT_HE_SHORT_BEACON_INTERVAL_NAME = "SHORT_BEACON_INTERVAL"
EXT_HE_EHT_CAPABILITIES_NAME = "EHT_CAPABILITIES"

WPS_ATTRIBUTE_IDS = {
    "version": 0x104A,
    "device_name": 0x1012,
    "device_password_id": 0x1011,
    "config_methods": 0x1008,
    "manufacturer": 0x1021,
    "model_name": 0x1023,
    "model_number": 0x1024,
    "wps_state": 0x1044,
    "uuid_e": 0x1047,
    "rf_bands": 0x103C,
    "vendor_extension": 0x1049,
    "primary_device_type": 0x1054,
    "response_type": 0x103B,
    "serial_number": 0x1022,
}

WPS_CONFIGURATION_STATES = {
    "not_configured": 0x01,
    "configured": 0x02,
}

WPS_RESPONSE_TYPES = {
    "enrollee_info": 0x00,
    "enrollee": 0x01,
    "registrar": 0x02,
    "ap": 0x03,
}

WPS_RF_BANDS = {
    "2.4ghz": 0x01,
    "5ghz": 0x02,
    "2.4ghz_and_5ghz": 0x03,
}

WPS_CONFIG_METHODS = {
    "usb": 0x0001,
    "ethernet": 0x0002,
    "label": 0x0004,
    "display": 0x0008,
    "external_nfc_token": 0x0010,
    "integrated_nfc_token": 0x0020,
    "nfc_interface": 0x0040,
    "push_button": 0x0080,
    "keypad": 0x0100,
}

WPS_DEVICE_CATEGORIES = {
    "computer": 0x0001,
    "input_device": 0x0002,
    "print_scan_fax_copy": 0x0003,
    "camera": 0x0004,
    "storage": 0x0005,
    "network_infrastructure": 0x0006,
    "display": 0x0007,
    "multimedia": 0x0008,
    "gaming": 0x0009,
    "telephone": 0x000a,
    "audio": 0x000b,
    "other": 0x000f,
}

WPS_ATTRIBUTE_NAMES = {v: k for k, v in WPS_ATTRIBUTE_IDS.items()}
WPS_CONFIGURATION_STATE_NAMES = {v: k for k, v in WPS_CONFIGURATION_STATES.items()}
WPS_RESPONSE_TYPE_NAMES = {v: k for k, v in WPS_RESPONSE_TYPES.items()}
WPS_RF_BAND_NAMES = {v: k for k, v in WPS_RF_BANDS.items()}
WPS_CONFIG_METHOD_NAMES = {v: k for k, v in WPS_CONFIG_METHODS.items()}
WPS_DEVICE_CATEGORY_NAMES = {v: k for k, v in WPS_DEVICE_CATEGORIES.items()}
```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/parsers/ie/parse.py
```python
# pktparser/core/layers/l2/ieee802/dot11/parsers/ie/parse.py

import struct
from uuid import UUID
from logging import getLogger
from core.common.parse.utils import (ParseContext, unpack, run_dispatch, bytes_for_oui)
from core.common.parse.definitions import (NAME, VALUE, RAW, DESCRIPTION, PARSED, OUI_FMT)
from pktparsers.core.layers.l2.ieee802.dot11.parsers.ie.definitions import *

logger = getLogger(__name__)

OUI_LENGTH = struct.calcsize(OUI_FMT)

def _parse_wps_attribute(attr_type: int, attr_data: bytes) -> dict:
    result = {}

    if attr_type == WPS_ATTRIBUTE_IDS.get(WPS_VERSION):
        if len(attr_data) >= 1:
            version_byte = attr_data[0]
            version_major = version_byte >> 4
            version_minor = version_byte & 0x0F
            result[WPS_VERSION] = f"{version_major}.{version_minor}"

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_STATE):
        if len(attr_data) >= 1:
            state_hex = attr_data[0]
            state_desc = WPS_CONFIGURATION_STATE_NAMES.get(state_hex, f"unknown_{state_hex:02x}")
            result[WPS_STATE] = state_desc
            result[WPS_STATE_VALUE] = state_hex

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_RESPONSE_TYPE):
        if len(attr_data) >= 1:
            resp_type = attr_data[0]
            resp_desc = WPS_RESPONSE_TYPE_NAMES.get(resp_type, f"unknown_{resp_type:02x}")
            result[WPS_RESPONSE_TYPE] = resp_desc
            result[WPS_RESPONSE_TYPE_VALUE] = resp_type

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_UUID):
        if len(attr_data) == 16:
            result[WPS_UUID] = str(UUID(bytes=attr_data))
        else:
            result[WPS_UUID] = attr_data

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_MANUFACTURER):
        result[WPS_MANUFACTURER] = attr_data.decode('utf-8', errors='ignore').strip('\x00')

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_MODEL):
        result[WPS_MODEL] = attr_data.decode('utf-8', errors='ignore').strip('\x00')

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_MODEL_NUMBER):
        result[WPS_MODEL_NUMBER] = attr_data.decode('utf-8', errors='ignore').strip('\x00')

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_SERIAL_NUMBER):
        result[WPS_SERIAL_NUMBER] = attr_data.decode('utf-8', errors='ignore').strip('\x00')

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_DEVICE_NAME):
        result[WPS_DEVICE_NAME] = attr_data.decode('utf-8', errors='ignore').strip('\x00')

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_PRIMARY_DEVICE_TYPE):
        if len(attr_data) >= 8:
            category = int.from_bytes(attr_data[0:2], 'big')
            oui = bytes_for_oui(attr_data[2:6]).get("oui")
            subtype = int.from_bytes(attr_data[6:8], 'big')
            result[WPS_PRIMARY_DEVICE_TYPE] = f"{category}-{oui}-{subtype}"
            category_desc = WPS_DEVICE_CATEGORY_NAMES.get(category, f"unknown_{category:04x}")
            result[WPS_PRIMARY_DEVICE_TYPE_CATEGORY] = category_desc
            result[WPS_PRIMARY_DEVICE_TYPE_SUBCATEGORY] = subtype

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_CONFIG_METHODS):
        if len(attr_data) >= 2:
            config_mask = int.from_bytes(attr_data[0:2], 'big')
            methods = [
                k.replace('_', ' ').title()
                for k, bit in WPS_CONFIG_METHODS.items()
                if config_mask & bit
            ]
            result[WPS_CONFIG_METHODS] = ", ".join(methods)
            result[WPS_CONFIG_METHODS_VALUE] = config_mask

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_RF_BANDS):
        if len(attr_data) >= 1:
            band_hex = attr_data[0]
            band_desc = WPS_RF_BAND_NAMES.get(band_hex, f"unknown_{band_hex:02x}")
            result[WPS_RF_BANDS] = band_desc
            result[WPS_RF_BANDS_VALUE] = band_hex

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_VENDOR_EXTENSION):
        if len(attr_data) >= 3:
            vendor_id = int.from_bytes(attr_data[0:3], 'big')
            result[VENDOR_ID] = vendor_id

            sub_offset = 3
            while sub_offset + 2 <= len(attr_data):
                subelement_id = attr_data[sub_offset]
                subelement_len = attr_data[sub_offset + 1]
                sub_offset += 2

                if sub_offset + subelement_len > len(attr_data):
                    break

                subelement_data = attr_data[sub_offset:sub_offset + subelement_len]
                sub_offset += subelement_len

                if subelement_id == WPS_VENDOR_EXT_VERSION2:
                    if len(subelement_data) >= 1:
                        version_major = subelement_data[0] >> 4
                        version_minor = subelement_data[0] & 0x0F
                        result[WPS_VERSION2] = f"{version_major}.{version_minor}"
                elif subelement_id == WPS_VENDOR_EXT_REQUEST_TO_ENROLL:
                    if len(subelement_data) >= 1:
                        result[WPS_REQUEST_TO_ENROLL] = bool(subelement_data[0] & 0x01)

    return result

def _wps_extension(tag_length: int, **kwargs) -> dict:
    ctx = ParseContext.current()
    end_offset = ctx.offset + (tag_length - 4)  # 4 = len(OUI) + 1 (vendor type)
    
    attributes = {}
    idx = 1

    while ctx.offset + 4 <= end_offset:
        def _attr_parser(value: tuple, **k) -> dict:
            attr_type, attr_len = value
            
            data_res = unpack(f"{attr_len}s")
            raw_data = data_res[VALUE]
            
            fields = _parse_wps_attribute(attr_type, raw_data)
            
            return {
                ATTR_TYPE: attr_type,
                ATTR_LENGTH: attr_len,
                FIELDS: fields
            }

        attr_entry = unpack(WPS_ATTR_FMT, parser=_attr_parser)
        attributes[idx] = attr_entry
        idx += 1

    return attributes

def _wmm_wme_extension(tag_length: int, **kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        subtype, version, qos_info, reserved = value
        
        ctx = ParseContext.current()
        end_offset = ctx.offset + (tag_length - 8)
        
        ac_params = {}
        idx = 0

        while ctx.offset + 4 <= end_offset:
            def _ac_parser(ac_val: tuple, **ak) -> dict:
                aci_aifsn, ecw, txop = ac_val
                
                ac_id = (aci_aifsn >> 5) & 0x03
                aifsn = aci_aifsn & 0x0F
                ecw_min = ecw & 0x0F
                ecw_max = (ecw >> 4) & 0x0F
                
                return {
                    WME_AC_INDEX: ac_id,
                    WME_AIFSN: aifsn,
                    WME_ECW_MIN: ecw_min,
                    WME_ECW_MAX: ecw_max,
                    WME_TXOP_LIMIT: txop
                }

            ac_entry = unpack(WMM_WME_FMT, parser=_ac_parser)
            key = ac_entry.get(PARSED, {}).get(WME_AC_INDEX, idx)
            ac_params[key] = ac_entry
            idx += 1

        return {
            WME_SUBTYPE: subtype,
            WME_VERSION: version,
            WME_QOS_INFO: qos_info,
            WME_AC_PARAMETERS: ac_params
        }

    return unpack("BBBB", parser=_parser)

def _rsn_capabilities(tag_length: int, **kwargs) -> dict:
    def _parser(value: int, **k) -> dict:
        pre_auth = bool(value & 0x0001)
        no_pairwise = bool(value & 0x0002)
        ptksa_replay = (value >> 2) & 0x03
        gtksa_replay = (value >> 4) & 0x03
        mfp_required = bool(value & 0x0040)
        mfp_capable = bool(value & 0x0080)
        ocvc = bool(value & 0x4000)

        return {
            RSN_CAPS_PRE_AUTH: pre_auth,
            RSN_CAPS_NO_PAIRWISE: no_pairwise,
            RSN_CAPS_PTKSA_REPLAY_COUNTER_LIMIT: ptksa_replay,
            RSN_CAPS_GTKSA_REPLAY_COUNTER_LIMIT: gtksa_replay,
            RSN_CAPS_MFP_REQUIRED: mfp_required,
            RSN_CAPS_MFP_CAPABLE: mfp_capable,
            RSN_CAPS_OCVC: ocvc
        }

    return unpack(RSN_CAPS_FMT, parser=_parser)

SPECIFIC_VENDOR_DISPATCH = {
    OUI_MICROSOFT: {
        MS_VENDOR_WPS: {DESCRIPTION: "Wi-Fi Alliance WPS (Microsoft)", PARSER: _wps_extension},
        MS_VENDOR_WMM_WME: {DESCRIPTION: "Microsoft WMM/WME", PARSER: _wmm_wme_extension},
        MS_VENDOR_WPA: {DESCRIPTION: "Microsoft WPA", PARSER: None}
    },
    OUI_IEEE_80211: {
        RSN_VENDOR_RSN_IE: {DESCRIPTION: "RSN Information", PARSER: _rsn_capabilities},
        RSN_VENDOR_RSN_IE_ALT: {DESCRIPTION: "RSN Information (Alt)", PARSER: _rsn_capabilities},
        RSN_VENDOR_PMKID: {DESCRIPTION: "PMKID", PARSER: None}
    },
    OUI_WFA: {
        WFA_VENDOR_WPS: {DESCRIPTION: "Wi-Fi Alliance WPS", PARSER: None},
        WFA_VENDOR_P2P: {DESCRIPTION: "Wi-Fi Alliance P2P", PARSER: None},
        WFA_VENDOR_HS20: {DESCRIPTION: "Wi-Fi Alliance Hotspot 2.0", PARSER: None},
        WFA_VENDOR_OSEN: {DESCRIPTION: "Wi-Fi Alliance OSEN", PARSER: None}
    },
    OUI_MEDIATEK: {DESCRIPTION: "MediaTek Inc", PARSER: None},
    OUI_BROADCOM: {DESCRIPTION: "Broadcom", PARSER: None},
    OUI_ATHEROS: {DESCRIPTION: "Atheros", PARSER: None}
}

def vendor_specific(tag_length: int, **kwargs) -> dict:
    fmt = f"{OUI_FMT}B"

    def _parser(value: tuple, **kwargs) -> dict:
        oui, vtype = value
        oui = bytes_for_oui(oui)
        
        vendor_sub_table = SPECIFIC_VENDOR_DISPATCH.get(oui["oui"], {})
        entry = vendor_sub_table.get(vtype, {})
        description = entry.get(DESCRIPTION, "Generic Vendor Specific")
        
        remaining_len = tag_length - struct.calcsize(fmt)

        def _fallback(**k):
            return unpack(f"{remaining_len}s")

        data = run_dispatch(
            dispatch_table=vendor_sub_table,
            dispatch_id=vtype,
            fallback=_fallback,
            tag_length=tag_length
        )

        result = {
            **oui,
            VENDOR_TYPE: vtype,
            DESCRIPTION: description,
            DATA: data
        }
        return result

    return unpack(fmt, parser=_parser)

def ssid(tag_length: int, **kwargs) -> dict:
    return unpack(f"{tag_length}s", parser=lambda value: value.decode(errors="ignore"))

def rates(tag_length: int, **kwargs) -> dict:
    ctx = ParseContext.current()
    end = ctx.offset + tag_length

    result = {}
    i = 1

    while ctx.offset < end:
        rate_result = unpack(
            BYTE_FMT,
            parser=lambda value: {
                RATE_VALUE: (value & 0x7F) / 2,
                RATE_BASIC: bool(value & 0x80)
            }
        )
        result[i] = rate_result
        i += 1

    return result

def tim_info(tag_length: int, **kwargs) -> dict:
    if tag_length < TIM_MIN_LEN:
        return {}
    
    def _parser(values: tuple, **kwargs) -> dict:
        dtim_count, dtim_period, bitmap_control = values
        
        multicast = bool(bitmap_control & 0x01)
        bitmap_offset = (bitmap_control >> 1) & 0x7F
        
        ctx = ParseContext.current()
        end = ctx.offset + (tag_length - 3)
        
        partial_virtual_bitmap = b""
        if ctx.offset < end:
            pvb_result = unpack(f"{end - ctx.offset}s")
            partial_virtual_bitmap = pvb_result
        
        return {
            DTIM_COUNT: dtim_count,
            DTIM_PERIOD: dtim_period,
            DTIM_BITMAP_CONTROL: {
                RAW: bitmap_control,
                DTIM_MULTICAST: multicast,
                DTIM_BITMAP_OFFSET: bitmap_offset
            },
            DTIM_PARTIAL_VIRTUAL_BITMAP: partial_virtual_bitmap
        }
    
    return unpack(TIM_FMT, parser=_parser)

def country_code(tag_length: int, **kwargs) -> dict:
    def _parser(value: tuple, **kwargs) -> dict:
        country_str, environment = value
        country_str = country_str.decode(errors="ignore")

        ctx = ParseContext.current()
        end = ctx.offset + (tag_length - COUNTRY_MIN_LEN)

        sub_elements = {}
        i = 0
        while ctx.offset + 3 <= end:
            sub_result = unpack(COUNTRY_SUB_FMT, parser=lambda v, **k: {
                COUNTRY_FIRST_CHANNEL: v[0],
                COUNTRY_NUM_CHANNELS: v[1],
                COUNTRY_MAX_TX_POWER: v[2]
            })
            sub_elements[i] = sub_result
            i += 1

        remaining = end - ctx.offset
        if remaining > 0:
            unpack(f"{remaining}s")

        result = {COUNTRY_CODE: country_str, COUNTRY_ENVIRONMENT: environment}
        if sub_elements:
            result[COUNTRY_SUB_ELEMENTS] = sub_elements
        return result

    if tag_length < COUNTRY_MIN_LEN:
        return unpack(COUNTRY_FMT, parser=lambda v, **k: {
            COUNTRY_CODE: v[0].decode(errors="ignore"),
            COUNTRY_ENVIRONMENT: v[1]
        })

    return unpack(COUNTRY_FMT, parser=_parser)

def erp_info(tag_length: int, **kwargs) -> dict:
    if tag_length < 1:
        return {}
    
    def _parser(value: int, **kwargs) -> dict:
        non_erp_present = bool(value & 0x01)
        use_protection = bool(value & 0x02)
        barker_preamble_mode = bool(value & 0x04)
        
        return {
            ERP_NON_ERP_PRESENT: non_erp_present,
            ERP_USE_PROTECTION: use_protection,
            ERP_BARKER_PREAMBLE_MODE: barker_preamble_mode
        }
    
    return unpack(ERP_FMT, parser=_parser)

def ht_capabilities(tag_length: int, **kwargs) -> dict:
    if tag_length < HT_CAPABILITIES_LEN:
        return {}
    
    def _parser(values: tuple, **kwargs) -> dict:
        (ht_caps_info, ampdu_params, rx_mcs_bitmask, highest_supported_rate, 
                 tx_mcs_info, _reserved1, _reserved2, ht_ext_caps, 
                 txbf_caps, asel_caps, _pad) = values
        
        # HT Capabilities Info
        ldpc_coding_capable = bool(ht_caps_info & 0x0001)
        supported_channel_width = bool(ht_caps_info & 0x0002)
        sm_power_save = (ht_caps_info >> 2) & 0x03
        green_field = bool(ht_caps_info & 0x0010)
        short_gi_20mhz = bool(ht_caps_info & 0x0020)
        short_gi_40mhz = bool(ht_caps_info & 0x0040)
        tx_stbc = bool(ht_caps_info & 0x0080)
        rx_stbc = (ht_caps_info >> 8) & 0x03
        delayed_block_ack = bool(ht_caps_info & 0x0400)
        max_amsdu_length = bool(ht_caps_info & 0x0800)
        dsss_cck_40mhz = bool(ht_caps_info & 0x1000)
        forty_mhz_intolerant = bool(ht_caps_info & 0x4000)
        lsig_txop_protection = bool(ht_caps_info & 0x8000)
        
        # AMPDU Params
        max_rx_ampdu_length_exponent = ampdu_params & 0x03
        min_mpdu_start_spacing = (ampdu_params >> 2) & 0x07
        
        # TX MCS Info
        tx_mcs_set_defined = bool(tx_mcs_info & 0x01)
        tx_rx_mcs_set_equal = bool(tx_mcs_info & 0x02)
        max_tx_spatial_streams = (tx_mcs_info >> 2) & 0x03
        unequal_modulation = bool(tx_mcs_info & 0x10)
        
        # HT Extended Capabilities
        pco_support = bool(ht_ext_caps & 0x0001)
        pco_transition_time = (ht_ext_caps >> 1) & 0x03
        mcs_feedback = (ht_ext_caps >> 4) & 0x03
        htc_support = bool(ht_ext_caps & 0x0400)
        reverse_direction_responder = bool(ht_ext_caps & 0x0800)
        
        # TXBF Capabilities
        implicit_bf_rx = bool(txbf_caps & 0x00000001)
        rx_staggered_sounding = bool(txbf_caps & 0x00000002)
        tx_staggered_sounding = bool(txbf_caps & 0x00000004)
        rx_ndp = bool(txbf_caps & 0x00000008)
        tx_ndp = bool(txbf_caps & 0x00000010)
        
        # ASEL Capabilities
        asel_capable = bool(asel_caps & 0x01)
        explicit_csi_feedback_tx_asel = bool(asel_caps & 0x02)
        antenna_indices_feedback_tx_asel = bool(asel_caps & 0x04)
        explicit_csi_feedback = bool(asel_caps & 0x08)
        antenna_indices_feedback = bool(asel_caps & 0x10)
        rx_asel = bool(asel_caps & 0x20)
        
        return {
            HT_CAPS_INFO: {
                HT_LDPC_CODING_CAPABLE: ldpc_coding_capable,
                HT_SUPPORTED_CHANNEL_WIDTH: supported_channel_width,
                HT_SM_POWER_SAVE: sm_power_save,
                HT_GREEN_FIELD: green_field,
                HT_SHORT_GI_20MHZ: short_gi_20mhz,
                HT_SHORT_GI_40MHZ: short_gi_40mhz,
                HT_TX_STBC: tx_stbc,
                HT_RX_STBC: rx_stbc,
                HT_DELAYED_BLOCK_ACK: delayed_block_ack,
                HT_MAX_AMSDU_LENGTH: max_amsdu_length,
                HT_DSSS_CCK_40MHZ: dsss_cck_40mhz,
                HT_FORTY_MHZ_INTOLERANT: forty_mhz_intolerant,
                HT_LSIG_TXOP_PROTECTION: lsig_txop_protection
            },
            HT_AMPDU_PARAMS: {
                HT_MAX_RX_AMPDU_LENGTH_EXPONENT: max_rx_ampdu_length_exponent,
                HT_MIN_MPDU_START_SPACING: min_mpdu_start_spacing
            },
            HT_RX_MCS_BITMASK: rx_mcs_bitmask,
            HT_HIGHEST_SUPPORTED_RATE: highest_supported_rate,
            HT_TX_MCS_INFO: {
                HT_TX_MCS_SET_DEFINED: tx_mcs_set_defined,
                HT_TX_RX_MCS_SET_EQUAL: tx_rx_mcs_set_equal,
                HT_MAX_TX_SPATIAL_STREAMS: max_tx_spatial_streams,
                HT_UNEQUAL_MODULATION: unequal_modulation
            },
            HT_EXT_CAPS: {
                HT_PCO_SUPPORT: pco_support,
                HT_PCO_TRANSITION_TIME: pco_transition_time,
                HT_MCS_FEEDBACK: mcs_feedback,
                HT_HTC_SUPPORT: htc_support,
                HT_REVERSE_DIRECTION_RESPONDER: reverse_direction_responder
            },
            HT_TXBF_CAPS: {
                HT_IMPLICIT_BF_RX: implicit_bf_rx,
                HT_RX_STAGGERED_SOUNDING: rx_staggered_sounding,
                HT_TX_STAGGERED_SOUNDING: tx_staggered_sounding,
                HT_RX_NDP: rx_ndp,
                HT_TX_NDP: tx_ndp
            },
            HT_ASEL_CAPS: {
                HT_ASEL_CAPABLE: asel_capable,
                HT_EXPLICIT_CSI_FEEDBACK_TX_ASEL: explicit_csi_feedback_tx_asel,
                HT_ANTENNA_INDICES_FEEDBACK_TX_ASEL: antenna_indices_feedback_tx_asel,
                HT_EXPLICIT_CSI_FEEDBACK: explicit_csi_feedback,
                HT_ANTENNA_INDICES_FEEDBACK: antenna_indices_feedback,
                HT_RX_ASEL: rx_asel
            }
        }
    
    return unpack(HT_CAPS_FMT, parser=_parser)

def rm_enable_capabilities(tag_length: int, **kwargs) -> dict:
    if tag_length < RM_CAPABILITIES_LEN:
        return {}
    
    def _parser(values: tuple, **kwargs) -> dict:
        byte0, byte1 = values
        
        byte0_parsed = {
            RM_LINK_MEASUREMENT: bool(byte0 & 0x01),
            RM_NEIGHBOR_REPORT: bool(byte0 & 0x02),
            RM_PARALLEL_MEASUREMENTS: bool(byte0 & 0x04),
            RM_REPEATED_MEASUREMENTS: bool(byte0 & 0x08),
            RM_BEACON_PASSIVE_MEASUREMENT: bool(byte0 & 0x10),
            RM_BEACON_ACTIVE_MEASUREMENT: bool(byte0 & 0x20),
            RM_BEACON_TABLE_MEASUREMENT: bool(byte0 & 0x40),
            RM_BEACON_MEASUREMENT_REPORTING: bool(byte0 & 0x80)
        }
        
        byte1_parsed = {
            RM_FRAME_MEASUREMENT: bool(byte1 & 0x01),
            RM_CHANNEL_LOAD_MEASUREMENT: bool(byte1 & 0x02),
            RM_NOISE_HISTOGRAM_MEASUREMENT: bool(byte1 & 0x04),
            RM_STATISTICS_MEASUREMENT: bool(byte1 & 0x08),
            RM_LCI_MEASUREMENT: bool(byte1 & 0x10),
            RM_LCI_AZIMUTH: bool(byte1 & 0x20),
            RM_TX_STREAM_CATEGORY_MEASUREMENT: bool(byte1 & 0x40),
            RM_TRIGGERED_TX_STREAM_MEASUREMENT: bool(byte1 & 0x80)
        }
        
        return {
            RM_BYTE0: byte0_parsed,
            RM_BYTE1: byte1_parsed
        }
    
    return unpack(RM_CAPS_FMT, parser=_parser)

def extended_capabilities(tag_length: int, **kwargs) -> dict:
    ctx = ParseContext.current()
    end = ctx.offset + tag_length
    
    def _parser_byte0(value: int, **kwargs) -> dict:
        bss_coexistence = bool(value & 0x01)
        extended_channel_switching = bool(value & 0x04)
        psmp_capability = bool(value & 0x10)
        
        return {
            EXT_CAPS_BSS_COEXISTENCE: bss_coexistence,
            EXT_CAPS_EXTENDED_CHANNEL_SWITCHING: extended_channel_switching,
            EXT_CAPS_PSMP_CAPABILITY: psmp_capability
        }
    
    def _parser_byte2(value: int, **kwargs) -> dict:
        return {EXT_CAPS_BSS_TRANSITION: bool(value & 0x08)}
    
    def _parser_byte3(value: int, **kwargs) -> dict:
        return {EXT_CAPS_INTERWORKING: bool(value & 0x80)}
    
    ext_caps = {}
    
    if tag_length >= 1:
        byte0 = unpack(BYTE_FMT, parser=_parser_byte0)
        ext_caps[PARSED_BYTE0] = byte0
    
    if tag_length >= 2:
        unpack(BYTE_FMT)  # Skip byte 1
    
    if tag_length >= 3:
        byte2 = unpack(BYTE_FMT, parser=_parser_byte2)
        ext_caps[PARSED_BYTE2] = byte2
    
    if tag_length >= 4:
        byte3 = unpack(BYTE_FMT, parser=_parser_byte3)
        ext_caps[PARSED_BYTE3] = byte3
    
    # Consume remaining bytes
    remaining = end - ctx.offset
    if remaining > 0:
        unpack(f"{remaining}s")
    
    return ext_caps

def qbss_load_element(tag_length: int, **kwargs) -> dict:
    if tag_length < QBSS_LOAD_LEN:
        return {}
    
    def _parser(values: tuple, **kwargs) -> dict:
        station_count, channel_utilization, available_admission_capacity = values
        
        return {
            QBSS_LOAD_STATION_COUNT: station_count,
            QBSS_LOAD_CHANNEL_UTILIZATION: channel_utilization,
            QBSS_LOAD_AVAILABLE_ADMISSION_CAPACITY: available_admission_capacity
        }
    
    return unpack(QBSS_LOAD_FMT, parser=_parser)

def power_constraint(tag_length: int, **kwargs) -> int:
    return unpack(BYTE_FMT)

def tcp_report(tag_length: int, **kwargs) -> dict:
    def _parser(values: tuple, **kwargs) -> dict:
        tx_power, reserved = values
        
        return {
            TCP_REPORT_TX_POWER: tx_power,
            TCP_REPORT_RESERVED: reserved
        }
    
    return unpack(TPC_REPORT_FMT, parser=_parser)

def current_channel(tag_length: int, **kwargs) -> int:
    return unpack(BYTE_FMT)

def rsn_information(tag_length: int, **kwargs) -> dict:
    if tag_length < RSN_MIN_LEN:
        return {}
    
    ctx = ParseContext.current()
    end = ctx.offset + tag_length
    result = {}
    
    if ctx.offset + 2 <= end:
        result[RSN_INFO_RSN_VERSION] = unpack(RSN_VERSION_FMT)
    
    if ctx.offset + 4 <= end:
        def _group_parser(value: tuple, **kwargs):
            oui, ctype = value
            oui = bytes_for_oui(oui)
            return {
                **oui, 
                RSN_INFO_CIPHER_TYPE: ctype
            }
        result[RSN_INFO_GROUP_CIPHER] = unpack(RSN_CIPHER_FMT, parser=_group_parser)
    
    if ctx.offset + 2 <= end:
        def _pairwise_parser(pairwise_count: int, **kwargs):
            def __parser(value: tuple, **kwargs):
                oui, ctype = value
                oui = bytes_for_oui(oui)
                return {
                    **oui,
                    RSN_INFO_CIPHER_TYPE: ctype
                }
                
            pairwise_ciphers = {}
            for i in range(pairwise_count):
                if ctx.offset + OUI_LENGTH + 1 <= end:
                    pairwise_cipher_result = unpack(RSN_CIPHER_FMT, parser=__parser)
                    pairwise_ciphers[i] = pairwise_cipher_result
            return pairwise_ciphers
            
        result[RSN_INFO_PAIRWISE_CIPHERS] = unpack(RSN_VERSION_FMT, parser=_pairwise_parser)
    
    if ctx.offset + 2 <= end:
        def _akm_parser(akm_count: int, **kwargs):
            def __akm_item_parser(value: tuple, **kwargs):
                oui, a_type = value
                oui = bytes_for_oui(oui)
                return {
                    **oui,
                    RSN_INFO_AKM_TYPE: a_type
                }
            
            akm_suites = {}
            for i in range(akm_count):
                if ctx.offset + 4 <= end:
                    akm_suite_result = unpack(RSN_AKM_FMT, parser=__akm_item_parser)
                    akm_suites[i] = akm_suite_result
            return akm_suites

        result[RSN_INFO_AKM_SUITES] = unpack(RSN_VERSION_FMT, parser=_akm_parser)
        if result[RSN_INFO_AKM_SUITES]:
            result[RSN_INFO_AKM_SUITE_COUNT] = len(result[RSN_INFO_AKM_SUITES])
    
    if ctx.offset + 2 <= end:
        result[RSN_INFO_CAPABILITIES] = unpack(RSN_CAPS_FMT, parser=_parse_rsn_capabilities)
    
    if ctx.offset + 2 <= end:
        def _pmkid_parser(pmkid_count: int, **kwargs):
            pmkids = {}
            for i in range(pmkid_count):
                if ctx.offset + EAPOL_PMKID_LENGTH <= end:
                    pmkid_result = unpack(RSN_PMKID_FMT)
                    pmkids[i] = pmkid_result
            return pmkids

        result[RSN_INFO_PMKIDS] = unpack(RSN_VERSION_FMT, parser=_pmkid_parser)
        if result[RSN_INFO_PMKIDS]:
            result[RSN_INFO_PMKID_COUNT] = len(result[RSN_INFO_PMKIDS])
            
    return result

def _parse_rsn_capabilities(value: int, **kwargs) -> dict:
    pre_auth = bool(value & 0x0001)
    no_pairwise = bool(value & 0x0002)
    ptksa_replay_counter = (value >> 2) & 0x03
    gtksa_replay_counter = (value >> 4) & 0x03
    mgmt_frame_protection_required = bool(value & 0x0040)
    mgmt_frame_protection_capable = bool(value & 0x0080)
    joint_multi_band_rsna = bool(value & 0x0100)
    peerkey_enabled = bool(value & 0x0200)
    spp_amsdu_capable = bool(value & 0x0400)
    spp_amsdu_required = bool(value & 0x0800)
    pbac = bool(value & 0x1000)
    extended_key_id = bool(value & 0x2000)
    ocvc = bool(value & 0x4000)
    reserved = bool(value & 0x8000)
    
    return {
        RSN_INFO_PRE_AUTH: pre_auth,
        RSN_INFO_NO_PAIRWISE: no_pairwise,
        RSN_INFO_PTKSA_REPLAY_COUNTER: ptksa_replay_counter,
        RSN_INFO_GTKSA_REPLAY_COUNTER: gtksa_replay_counter,
        RSN_INFO_MFP_REQUIRED: mgmt_frame_protection_required,
        RSN_INFO_MFP_CAPABLE: mgmt_frame_protection_capable,
        RSN_INFO_JOINT_MULTI_BAND_RSNA: joint_multi_band_rsna,
        RSN_INFO_PEERKEY_ENABLED: peerkey_enabled,
        RSN_INFO_SPP_AMSDU_CAPABLE: spp_amsdu_capable,
        RSN_INFO_SPP_AMSDU_REQUIRED: spp_amsdu_required,
        RSN_INFO_PBAC: pbac,
        RSN_INFO_EXTENDED_KEY_ID: extended_key_id,
        RSN_INFO_OCVC: ocvc,
        RSN_INFO_RESERVED_BIT: reserved
    }

def _get_extension_name(ext_id: int) -> str:
    extensions = {
        EXT_HE_CAPABILITIES: EXT_HE_CAPABILITIES_NAME,
        EXT_HE_OPERATION: EXT_HE_OPERATION_NAME,
        EXT_HE_UORA_PARAMETER_SET: EXT_HE_UORA_PARAMETER_SET_NAME,
        EXT_HE_SHORT_BEACON_INTERVAL: EXT_HE_SHORT_BEACON_INTERVAL_NAME,
        EXT_HE_EHT_CAPABILITIES: EXT_HE_EHT_CAPABILITIES_NAME
    }
    return extensions.get(ext_id)

def tag_extended_he(tag_length: int, **kwargs) -> dict:
    def _parser(value: tuple, **kwargs):
        ext_tag_id, data = value
        logger.debug(f"_parser tag_extended_he\n{value}")
        return {
            EXTENSION_ID: ext_tag_id,
            EXTENSION_NAME: _get_extension_name(ext_tag_id),
            DATA: data
        }

    if tag_length < EXTENDED_HE_MIN_LEN:
        return {}
    
    return unpack(f"{BYTE_FMT}{tag_length - 1}s", parser=_parser)

IE_DISPATCH = {
    TAG_SSID: {
        NAME: TAG_SSID_NAME,
        DESCRIPTION: "SSID (Service Set Identifier)",
        PARSER: ssid
    },
    TAG_SUPPORTED_RATES: {
        NAME: TAG_SUPPORTED_RATES_NAME,
        DESCRIPTION: "Supported Rates",
        PARSER: rates
    },
    TAG_CURRENT_CHANNEL: {
        NAME: TAG_CURRENT_CHANNEL_NAME,
        DESCRIPTION: "Current Channel",
        PARSER: current_channel
    },
    TAG_TIM: {
        NAME: TAG_TIM_NAME,
        DESCRIPTION: "Traffic Indication Map",
        PARSER: tim_info
    },
    TAG_COUNTRY: {
        NAME: TAG_COUNTRY_NAME,
        DESCRIPTION: "Country",
        PARSER: country_code
    },
    TAG_QBSS_LOAD: {
        NAME: TAG_QBSS_LOAD_NAME,
        DESCRIPTION: "QBSS (QoS Enhanced Basic Service Set) Load Element",
        PARSER: qbss_load_element
    },
    TAG_POWER_CONSTRAINT: {
        NAME: TAG_POWER_CONSTRAINT_NAME,
        DESCRIPTION: "Power Constraint",
        PARSER: power_constraint
    },
    TAG_TPC_REPORT: {
        NAME: TAG_TPC_REPORT_NAME,
        DESCRIPTION: "TPC (Transmit Power Control) Report",
        PARSER: tcp_report
    },
    TAG_ERP: {
        NAME: TAG_ERP_NAME,
        DESCRIPTION: "ERP (Extended Rate Physical Layer) Information",
        PARSER: erp_info
    },
    TAG_EXTENDED_SUPPORTED_RATES: {
        NAME: TAG_EXTENDED_SUPPORTED_RATES_NAME,
        DESCRIPTION: "Extended Supported Rates",
        PARSER: rates
    },
    TAG_VENDOR_SPECIFIC: {
        NAME: TAG_VENDOR_SPECIFIC_NAME,
        DESCRIPTION: "Vendor Specific",
        PARSER: vendor_specific
    },
    TAG_HT_CAPABILITIES: {
        NAME: TAG_HT_CAPABILITIES_NAME,
        DESCRIPTION: "HT (High Throughput) Capabilities",
        PARSER: ht_capabilities
    },
    TAG_RM_ENABLED_CAPABILITIES: {
        NAME: TAG_RM_ENABLED_CAPABILITIES_NAME,
        DESCRIPTION: "RM (Radio Measurement) Enabled Capabilities",
        PARSER: rm_enable_capabilities
    },
    TAG_RSN_INFORMATION: {
        NAME: TAG_RSN_INFORMATION_NAME,
        DESCRIPTION: "RSN (Robust Security Network) Information",
        PARSER: rsn_information
    },
    TAG_EXTENDED_CAPABILITIES: {
        NAME: TAG_EXTENDED_CAPABILITIES_NAME,
        DESCRIPTION: "Extended Capabilities",
        PARSER: extended_capabilities
    },
    TAG_EXTENDED_HE: {
        NAME: TAG_EXTENDED_HE_NAME,
        DESCRIPTION: "(Wifi 6) High Efficiency (HE)",
        PARSER: tag_extended_he
    }
}

def ie_dispatch(value: tuple, **kwargs) -> dict:
    def _fallback(tag_length: int, **k):
        return unpack(f"{tag_length}s")

    ie_result = {}
    tag_number, tag_length = value

    ctx = ParseContext.current()
    start_offset = ctx.offset
    expected_end = start_offset + tag_length

    try:
        entry = IE_DISPATCH.get(tag_number, {})
        ie_result = {
            TAG_NUMBER: tag_number,
            TAG_LENGTH: tag_length,
            NAME: entry.get(NAME),
            DESCRIPTION: entry.get(DESCRIPTION)
        }
        ie_result[DATA] = run_dispatch(
            IE_DISPATCH,
            tag_number,
            fallback=_fallback,
            tag_length=tag_length
        )

    except Exception as e:
        logger.debug(f"IE parser error for tag {tag_number} value={value} entry={entry} : {e}")

    finally:
        if ctx.offset != expected_end:
            logger.debug(
                f"IE tag {tag_number} offset drift: expected={expected_end} got={ctx.offset} "
                f"(drift={ctx.offset - expected_end:+d})"
            )
            ctx.offset = min(expected_end, len(ctx.frame))

    return ie_result
```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/parsers/mac_header/definitions.py
```python
DURATION_FMT = "<H"
FS_FMT = "<H"
QOS_FMT = "<H"
```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/parsers/mac_header/mac_header.py
```python
from logging import getLogger
from pktparsers.common.parser import (unpack, read_mac)
from pkparsers.core.layers.l2.ieee802.dot11.definitions import *

logger = getLogger(__name__)

def parser(**kwargs) -> dict:
    logger.debug("MAC Header parse")

    def _parser(fc_val: int, **k) -> dict:
        protocol_version = fc_val & 0b11
        f_type = (fc_val >> 2) & 0b11
        f_subtype = (fc_val >> 4) & 0b1111
        to_ds = (fc_val >> 8) & 1
        from_ds = (fc_val >> 9) & 1
        protected = bool(fc_val & 0x4000)
        
        type_name = FRAME_TYPES.get(f_type)
        subtype_name = FRAME_SUBTYPES.get(f_type, {}).get(f_subtype)
        is_qos = f_type == DATA and bool(f_subtype & 0b1000)

        duration = unpack(DURATION_FMT)
        
        addr1 = read_mac()
        
        addr2 = addr3 = addr4 = seq = qos = None

        if f_type == CTRL:
            if f_subtype in (CTRL_BLOCK_ACK_REQUEST, CTRL_BLOCK_ACK, CTRL_PS_POLL, 
                             CTRL_RTS, CTRL_CF_END, CTRL_CF_END_ACK):
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
            qos = unpack("<H")

        return {
            "fc": {
                "protocol_version": protocol_version,
                "type": f_type,
                "type_name": type_name,
                "subtype": f_subtype,
                "subtype_name": subtype_name,
                "tods": to_ds,
                "fromds": from_ds,
                "protected": protected,
            },
            "duration_id": duration,
            "ra": ra, "ta": ta, "sa": sa, "da": da, "bssid": bssid,
            "sequence_number": seq,
            "qos_control": qos
        }

    result = {}

    try:
        result = unpack("<H", parser=_parser)
    except Exception as e:
        logger.debug(f"MAC Header parser error: {e}")

    return result
```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/parsers/management/management.py
```python
from pktparsers.common.parse.utils import (ParseContext, unpack, run_dispatch)
from pktparsers.core.layers.l2.ieee802.dot11.parsers.common import (fixed_parameters, tagged_parameters)
from pktparsers.core.layers.l2.ieee802.dot11.definitions import *

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

## File: src/pktparsers/core/layers/l2/ieee802/dot11/parsers/body.py
```python
# pktparsers/core/layers/l2/ieee802/dot11/parsers/body.py
from logging import getLogger
from pktparsers.common.parse.utils import ParseContext, unpack, run_dispatch
from pktparsers.common.parse.filter_engine import get_nested
from pktparsers.core.layers.l2.ieee802.dot11.parsers import management, control, data
from pktparsers.core.layers.l2.ieee802.dot11.definitions import *
from pktparsers.core.layers.l2.ieee802.dot11.parsers.mac_header import definitions as mac_hdr_defs

logger = getLogger(__name__)

BODY_DISPATCH = {
    MGMT: management.parser,
    CTRL: control.parser,
    DATA: data.parser,
}

def parser(**kwargs):
    result = {}
    ctx = ParseContext.current()
    fc = get_nested(f"{PROTOCOL_DOT11}.{MAC_HDR}.{mac_hdr_defs.FC}", ctx.result)
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

## File: src/pktparsers/core/layers/l2/ieee802/dot11/parsers/common.py
```python
from logging import getLogger
from core.common.parser import (ParseContext, unpack, read_oui, bitmap_value_for_dict, insert_item)
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

## File: src/pktparsers/core/layers/l2/ieee802/dot11/__init__.py
```python

```

## File: src/pktparsers/core/layers/l2/ieee802/dot11/definitions.py
```python
MGMT = 0
CTRL = 1
DATA = 2

FRAME_TYPES = {
    MGMT: "Management",
    CTRL: "Control",
    DATA: "Data",
}

MGMT_ASSOCIATION_REQUEST = 0
MGMT_ASSOCIATION_RESPONSE = 1
MGMT_REASSOCIATION_REQUEST = 2
MGMT_REASSOCIATION_RESPONSE = 3
MGMT_PROBE_REQUEST = 4
MGMT_PROBE_RESPONSE = 5
MGMT_TIMING_ADVERTISEMENT = 6
MGMT_BEACON = 8
MGMT_ATIM = 9
MGMT_DISASSOCIATION = 10
MGMT_AUTHENTICATION = 11
MGMT_DEAUTHENTICATION = 12
MGMT_ACTION = 13
MGMT_ACTION_NO_ACK = 14

CTRL_BLOCK_ACK_REQUEST = 8
CTRL_BLOCK_ACK = 9
CTRL_PS_POLL = 10
CTRL_RTS = 11
CTRL_CTS = 12
CTRL_ACK = 13
CTRL_CF_END = 14
CTRL_CF_END_ACK = 15

DATA_DATA = 0
DATA_DATA_CF_ACK = 1
DATA_DATA_CF_POLL = 2
DATA_DATA_CF_ACK_CF_POLL = 3
DATA_NULL = 4
DATA_CF_ACK = 5
DATA_CF_POLL = 6
DATA_CF_ACK_CF_POLL = 7
DATA_QOS_DATA = 8
DATA_QOS_DATA_CF_ACK = 9
DATA_QOS_DATA_CF_POLL = 10
DATA_QOS_DATA_CF_ACK_CF_POLL = 11
DATA_QOS_NULL = 12
DATA_RESERVED = 13
DATA_QOS_CF_POLL = 14
DATA_QOS_CF_ACK_CF_POLL = 15

NULL_DATA_SUBTYPES = [
    DATA_NULL,
    DATA_CF_ACK,
    DATA_CF_POLL,
    DATA_CF_ACK_CF_POLL,
    DATA_QOS_NULL,
    DATA_RESERVED,
    DATA_QOS_CF_POLL,
    DATA_QOS_CF_ACK_CF_POLL
]

FRAME_SUBTYPES = {
    MGMT: {
        MGMT_ASSOCIATION_REQUEST: "Association Request",
        MGMT_ASSOCIATION_RESPONSE: "Association Response",
        MGMT_REASSOCIATION_REQUEST: "Reassociation Request",
        MGMT_REASSOCIATION_RESPONSE: "Reassociation Response",
        MGMT_PROBE_REQUEST: "Probe Request",
        MGMT_PROBE_RESPONSE: "Probe Response",
        MGMT_TIMING_ADVERTISEMENT: "Timing Advertisement",
        MGMT_BEACON: "Beacon",
        MGMT_ATIM: "ATIM",
        MGMT_DISASSOCIATION: "Disassociation",
        MGMT_AUTHENTICATION: "Authentication",
        MGMT_DEAUTHENTICATION: "Deauthentication",
        MGMT_ACTION: "Action",
        MGMT_ACTION_NO_ACK: "Action No Ack",
    },
    CTRL: {
        CTRL_BLOCK_ACK_REQUEST: "Block Ack Request",
        CTRL_BLOCK_ACK: "Block Ack",
        CTRL_PS_POLL: "PS-Poll",
        CTRL_RTS: "RTS",
        CTRL_CTS: "CTS",
        CTRL_ACK: "ACK",
        CTRL_CF_END: "CF-End",
        CTRL_CF_END_ACK: "CF-End+CF-Ack",
    },
    DATA: {
        DATA_DATA: "Data",
        DATA_DATA_CF_ACK: "Data+CF-Ack",
        DATA_DATA_CF_POLL: "Data+CF-Poll",
        DATA_DATA_CF_ACK_CF_POLL: "Data+CF-Ack+CF-Poll",
        DATA_NULL: "Null",
        DATA_CF_ACK: "CF-Ack",
        DATA_CF_POLL: "CF-Poll",
        DATA_CF_ACK_CF_POLL: "CF-Ack+CF-Poll",
        DATA_QOS_DATA: "QoS Data",
        DATA_QOS_DATA_CF_ACK: "QoS Data+CF-Ack",
        DATA_QOS_DATA_CF_POLL: "QoS Data+CF-Poll",
        DATA_QOS_DATA_CF_ACK_CF_POLL: "QoS Data+CF-Ack+CF-Poll",
        DATA_QOS_NULL: "QoS Null",
        DATA_RESERVED: "Reserved",
        DATA_QOS_CF_POLL: "QoS CF-Poll",
        DATA_QOS_CF_ACK_CF_POLL: "QoS CF-Ack+CF-Poll",
    },
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

## File: src/pktparsers/core/layers/l2/ieee802/dot11/parse.py
```python
# pktparsers/core/layers/l2/ieee802/dot11/parse.py
from logging import getLogger
from pktparsers.common.parse.utils import (ParseContext, insert_item, detect_fcs)
from pktparsers.core.layers.l2.ieee802.dot11.parsers import (mac_header, body)
from pktparsers.core.layers.l2.ieee802.dot11.definitions import *

logger = getLogger(__name__)

def parse() -> dict:
    ctx = ParseContext.current()
    if ctx is None:
        raise RuntimeError("parse() called without active ParseContext")

    insert_item(ctx.result, DOT11, {})
    insert_item(ctx.result[DOT11], FCS, detect_fcs())

    if ctx.offset >= len(ctx.frame):
        logger.debug("Empty dot11 frame body")
        return ctx.result[DOT11]

    insert_item(ctx.result[DOT11], MAC_HDR, mac_header.parser())
    insert_item(ctx.result[BODY], BODY, body.parser())

    return ctx.result[DOT11]
```

## File: src/pktparsers/core/layers/l2/ieee802/dot1x/eap/parse.py
```python

```

## File: src/pktparsers/core/layers/l2/ieee802/dot1x/eapol/analyzers/summary.py
```python
def summarize(parser_result: dict) -> dict:
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

## File: src/pktparsers/core/layers/l2/ieee802/dot1x/eapol/definitions.py
```python
from pktparsers.common.parse.definitions import (
    VALUE,
    DESCRIPTION,
)

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

## File: src/pktparsers/core/layers/l2/ieee802/dot1x/eapol/parse.py
```python
# core/layers/l2/ieee802/dot1x/eapol/parse.py

from pktparsers.common.parse.definitions import (VALUE, DESCRIPTION)

from pktparsers.core.layers.l2.ieee802.dot1x.eapol.definitions import *

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
            DOT1X_VERSION: auth_ver,
            DOT1X_TYPE: eapol_type,
            DOT1X_HEADER_LEN: length,
            KEY_DESCRIPTOR_TYPE: desc_type,
            KEY_INFORMATION: {
                KEY_DESCRIPTOR_VERSION: descriptor_version,
                KEY_TYPE: key_type,
                KEY_INDEX: key_index,
                KEY_INSTALL: install_bit,
                KEY_ACK: ack_bit,
                KEY_MIC: mic_bit,
                KEY_SECURE: secure_bit,
                KEY_ERROR: error_bit,
                KEY_REQUEST: request_bit,
                ENCRYPTED_KEY_DATA: encrypted_key_data,
                SMK_MESSAGE: smk_message,
            },
            KEY_LENGTH: key_len,
            KEY_REPLAY_COUNTER: replay,
            KEY_NONCE: nonce,
            KEY_IV: iv,
            KEY_RSC: rsc,
            KEY_ID: key_id,
            KEY_MIC: mic,
            KEY_DATA_LENGTH: key_data_len,
        }

        if key_data_len > 0:
            fmt = f"{key_data_len}s"

            if not encrypted_key_data:
                result[KEY_DATA] = unpack(
                    fmt,
                    parser=tagged_parameters,
                )
            else:
                result[KEY_DATA] = unpack(fmt)

        return result

    logger.debug("EAPOL Parser")

    result = {}

    try:
        result = unpack(
            FMT,
            parser=_parser,
        )

    except Exception as e:
        logger.debug(f"EAPOL Parser error: {e}")

    return result
```

## File: src/pktparsers/core/layers/l2/ieee802/dot1x/radius/parse.py
```python

```

## File: src/pktparsers/core/layers/l2/ieee802/dot1x/__init__.py
```python

```

## File: src/pktparsers/core/layers/l2/ieee802/dot2/llc/definitions.py
```python
DSAP = "dsap"
SSAP = "ssap"
CONTROL_FIELD = "control_field"
PID = "pid"

DSAP_FMT = "B"
SSAP_FMT = "B"
CONTROL_FIELD_FMT = "B"
PID_FMT = "H"
```

## File: src/pktparsers/core/layers/l2/ieee802/dot2/llc/parse.py
```python
# l2/ieee802/llc/parser.py

from logging import getLogger
from pktparsers.common.parse.utils import (unpack, run_dispatch, bytes_for_oui) 
from pktparsers.core.registry import get_protocol
from pktparsers.core.layers.l2 import (OUI, OUI_FMT)
from pktparsers.core.layers.l2.ieee802.definitions import ETHERTYPE_DISPATCH
from pktparsers.core.layers.l2.ieee802.dot2.llc.definitions import *

logger = getLogger(__name__)

def parser(**kwargs) -> dict:
    logger.debug(f"LLC parse")

    def _parser(value: tuple, **kwargs) -> dict:
        dsap, ssap, ctrl, oui, pid = value
        
        oui = bytes_for_oui(oui)

        pid_name = ETHERTYPE_DISPATCH.get(pid)
        entry: ProtocolEntry = get_protocol(pid_name)
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

    fmt = f"!{DSAP_FMT}{SSAP_FMT}{CONTROL_FMT}{OUI_FMT}{PID_FMT}"
    return unpack(fmt, parser=_parser)
```

## File: src/pktparsers/core/layers/l2/ieee802/dot3/analyzers/definitions.py
```python

```

## File: src/pktparsers/core/layers/l2/ieee802/dot3/analyzers/summary.py
```python

```

## File: src/pktparsers/core/layers/l2/ieee802/dot3/dlt/en10mb/parse.py
```python

```

## File: src/pktparsers/core/layers/l2/ieee802/dot3/parsers/body.py
```python
# dot3/parse.py
from logging import getLogger
from pktparsers.common.parse.utils import unpack, read_mac
from pktparsers.common.parse.filter_engine import get_nested
from pktparsers.core.layers.l2.ieee802.dot3.definitions import *
from pktparsers.core.layers.l3.ip.parse import parse as ip_parse
from pktparsers.core.layers.l3.arp.parse import parse as arp_parse
from pktparsers.core.layers.l2.ieee802.dot1x.parsers.eapol import parser as eapol_parse
from pktparsers.core.layers.l2.ieee802.dot2.parse import PAYLOAD_DISPATCH

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

## File: src/pktparsers/core/layers/l2/ieee802/dot3/parsers/ethernet_header.py
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

## File: src/pktparsers/core/layers/l2/ieee802/dot3/definitions.py
```python
# core/layers/l2/ieee802/dot3/definitions.py

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_EAPOL = 0x888E
ETHERTYPE_MESH_CTRL = 0x888F
ETHERTYPE_TDLS = 0x890D
ETHERTYPE_WAPI = 0x88B4
ETHERTYPE_FAST_BSS_TRANSITION = 0x88B5
ETHERTYPE_DLS = 0x88B6
ETHERTYPE_RAS = 0x8902
ETHERTYPE_WMM = 0x88C0
ETHERTYPE_QOS_NULL = 0x8903
```

## File: src/pktparsers/core/layers/l2/ieee802/dot3/parse.py
```python
# pktparsers/core/layers/l2/ieee802/dot11/parse.py
from logging import getLogger
from pktparsers.common.parse.utils import ParseContext, insert_item, detect_fcs
from pktparsers.common.parse.definitions import *
from pktparsers.core.layers.l2.ieee802.dot3.parsers import ethernet_header, body
from pktparsers.core.layers.l2.ieee802.dot3.definitions import *

logger = getLogger(__name__)

def parse() -> dict:
    ctx = ParseContext.current()
    if ctx is None:
        raise RuntimeError("parse() called without active ParseContext")

    insert_item(ctx.result, DOT3, {})
    insert_item(ctx.result[DOT3], FCS, detect_fcs())

    if ctx.offset >= len(ctx.frame):
        logger.debug("Empty dot3 frame body")
        return ctx.result[DOT3]

    insert_item(ctx.result[DOT3], ETHER_HDR, ethernet_header.parser())
    insert_item(ctx.result[BODY], BODY, body.parser())

    return ctx.result[DOT3]
```

## File: src/pktparsers/core/layers/l2/ieee802/__init__.py
```python

```

## File: src/pktparsers/core/layers/l2/ieee802/__main__.py
```python
# for tests

IEEE802_11_FRAMES = {
  "raw": ["ffffffffffffa4f933ed5b75080045000156b50e00004011c48900000000ffffffff0044004301426781010106006ef3d0d803b9000000000000000000000000000000000000a4f933ed5b750000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000063825363350101370701031c21333a3b390205d03c316468637063642d31302e312e303a4c696e75782d362e362e3132365f313a7838365f36343a47656e75696e65496e74656c740101910101ff"]
}



def main():
    from core.layers.l2.ieee802.dot11.parse import parse
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

## File: src/pktparsers/core/layers/l2/ieee802/definitions.py
```python
# core/layers/l2/ieee802/definitions.py

from pktparsers.core.layers.l2.ieee802.dot3.definitions import *
from pktparsers.common.parse.definitions import *

IEEE80211_FCS_LEN = 4

ETHERTYPE_DISPATCH = {
    ETHERTYPE_IPV4: PROTOCOL_IPV4,
    ETHERTYPE_ARP: PROTOCOL_ARP,
    ETHERTYPE_IPV6: PROTOCOL_IPV6,
    ETHERTYPE_EAPOL: PROTOCOL_EAPOL,
    ETHERTYPE_MESH_CTRL: PROTOCOL_MESH_CTRL,
    ETHERTYPE_TDLS: PROTOCOL_TDLS,
    ETHERTYPE_WAPI: PROTOCOL_WAPI,
    ETHERTYPE_FAST_BSS_TRANSITION: PROTOCOL_FAST_BSS_TRANSITION,
    ETHERTYPE_DLS: PROTOCOL_DLS,
    ETHERTYPE_RAS: PROTOCOL_RAS,
    ETHERTYPE_WMM: PROTOCOL_WMM,
    ETHERTYPE_QOS_NULL: PROTOCOL_QOS_NULL,
}
```

## File: src/pktparsers/core/layers/l3/arp/parse.py
```python
# l3/parsers/parsers.py — versão correta
import socket
from logging import getLogger
from pktparsers.common.parse.utils import unpack, ParseContext

logger = getLogger(__name__)

def arp(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        hw_type, proto_type, hw_size, proto_size, opcode, src_mac, src_ip, dst_mac, dst_ip = value
        return {
            "hw_type":       hw_type,
            "protocol_type": proto_type,
            "hw_size":       hw_size,
            "protocol_size": proto_size,
            "opcode":        opcode,
            "src_mac":       src_mac,
            "src_ip":        socket.inet_ntoa(src_ip),
            "dst_mac":       dst_mac,
            "dst_ip":        socket.inet_ntoa(dst_ip),
        }
    return unpack("!HHBBH6s4s6s4s", parser=_parser)
```

## File: src/pktparsers/core/layers/l3/ip/analyzers/definitions.py
```python

```

## File: src/pktparsers/core/layers/l3/ip/analyzers/summary.py
```python

```

## File: src/pktparsers/core/layers/l3/ip/dlt/raw/parse.py
```python

```

## File: src/pktparsers/core/layers/l3/ip/definitions.py
```python
# pktparsers/core/layers/l3/ip/definitions.py

from pktparsers.common.parse.definitions import (IPV4_FMT, PAYLOAD, FLAGS, VERSION)

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

## File: src/pktparsers/core/layers/l3/ip/parse.py
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

## File: src/pktparsers/core/layers/l3/__init__.py
```python

```

## File: src/pktparsers/core/layers/l4/__init__.py
```python

```

## File: src/pktparsers/core/layers/l7/__init__.py
```python

```

## File: src/pktparsers/core/layers/__init__.py
```python

```

## File: src/pktparsers/core/__init__.py
```python

```

## File: src/pktparsers/core/crypt.py
```python
@dataclass
class CredentialsConfig:
    protocol: dict[str, Any]
```

## File: src/pktparsers/core/definitions.py
```python
# pktparsers/common/parse/defintions.py

# Contains dataclasses or global constants of the project, used by parsing functions or related to parsing. Constants such as: names of keys from parser result dictionaries.
# Stores standard struct formats and generic key constants used by parsers.

from dataclasses import dataclass

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

EUI48_FMT = "6s"
EUI64_FMT = "8s"
OUI_FMT = "3s"
IPV4_FMT = "4s"
IPV6_FMT = "16s"

PARSED = "parsed"
COUNTER = "counter"
SUMMARY = "summary"
VALUE = "value"
METADATA = "_metadata_"
RAW = "raw"
TOKENS = "tokens"
OUI = "oui"
MAC = "mac"
NAME = "name"
DESCRIPTION = "description"
PAYLOAD = "payload"
VENDOR = "vendor"
ADDRESS = "addr"
SOURCE = "src"
DESTINATION = "dst"
FLAGS = "flags"
VERSION = "version"

L2 = "l2"
L3 = "l3"
L4 = "l4"
L7 = "l7"

DEVICES = "devices"
ANNOTATIONS = "annotations"
RELATIONSHIPS = "relationships"

IEEE802_11 = "ieee802_11"
IEEE802_3 = "ieee802_3"
IEEE802_1X = "ieee802_1x"
ARP = "arp"
IP = "ip"
IPV4 = "ipv4"
IPV6 = "ipv6"
ICMP = "icmp"
ICMPV6 = "icmpv6"
TCP = "tcp"
UDP = "udp"
LLC = "llc"
SNAP = "snap"
EAPOL = "eapol"
EAP = "eap"
RADIUS = "radius"
MESH_CTRL = "mesh_ctrl"
TDLS = "tdls"
WAPI = "wapi"
FAST_BSS_TRANSITION = "fast_bss_transition"
DLS = "dls"
RAS = "robust_av_streaming"
WMM = "wmm"
QOS_NULL = "qos_null"
TLS = "tls"
IPSEC = "ipsec"

@dataclass
class ProtocolConfig:
    credentials: Any # específica daquele protocolo ou DLT específica.
    options: Any # específico daquele protocolo.

@dataclass
class DltConfig:
    credentials: Any # específica daquele protocolo ou DLT específica.
    options: Any # específico daquele protocolo ou DLT.
```

## File: src/pktparsers/core/dissect.py
```python
# pktparsers/core/dissector.py

"""
Core dissector: Dissector, DissectConfig, AnalysisConfig

Exemplo:
    with Dissector("DLT_IEEE802_11_RADIO") as dissector:
        result = dissector.dissect(raw_packet_bytes)
        print(result[PARSED])
        print(result["traffic_summary"])
"""

import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any
from logging import getLogger
from pktparsers.core.parsing import insert_item
from pktparsers.core.registry import get_dlt_parser
from pktparsers.core.context import TrafficContext
from pktparsers.core.definitions import TIMESTAMP, PARSED, RAW, COUNTER, TRAFFIC_SUMMARY

logger = getLogger(__name__)

@dataclass
class AnalysisConfig:
    """Configuration for traffic analysis and annotation"""
    traffic_summary: bool = True
    device_tracking: bool = True
    relationship_tracking: bool = True

@dataclass
class CredentialsConfig:
    """Configuration for credential extraction (encryption keys, etc.)"""
    dlt: dict[str, Any] = field(default_factory=dict)
    protocol: dict[str, Any] = field(default_factory=dict)

@dataclass
class ParseConfig:
    """Configuration for parsing specific protocols"""
    dlt: dict[str, Any] = field(default_factory=dict)
    protocol: dict[str, Any] = field(default_factory=dict)

@dataclass
class DissectConfig:
    """Master configuration for Dissector"""
    parse: ParseConfig = field(default_factory=ParseConfig)
    credentials: CredentialsConfig = field(default_factory=CredentialsConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)

@dataclass
class DissectConfig:
    parse: ParseConfig = field(default_factory=ParseConfig)
    credentials: CredentialsConfig = field(default_factory=CredentialsConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)

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
    
    def __init__(self, dlt: str | int, config: DissectConfig = None):
        """
        Args:
            dlt: DLT type as string ("DLT_IEEE802_11_RADIO") or int (127)
            config: DissectConfig instance (default: empty config)
        """
        self.dlt = dlt
        self.config = config or DissectConfig()
        self.parser = get_dlt_parser(dlt)
        self.traffic_ctx = TrafficContext()
        self.counter = 0
        self._token = None

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

    @classmethod
    def get_credentials(cls, protocol: str, key: str = None) -> dict | None:
        ctx = cls.current()
        if not ctx:
            return None
        creds = ctx.config.credentials.get(protocol, {})
        return creds.get(key) if key else creds

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
            parsed = self.parser(packet, offset)
            
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
```

## File: src/pktparsers/core/filter_engine.py
```python
import re
import operator

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

    if isinstance(current, dict) and "parsed" in current:
        current = current["parsed"]

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

        if isinstance(current, dict) and "parsed" in current:
            next_key = keys[i + 1] if i + 1 < len(keys) else None
            if next_key is None or str(next_key).lower() not in ("parsed", "value", "_metadata_"):
                current = current["parsed"]

        i += 1

    if isinstance(current, bytes):
        return current.hex()

    if isinstance(current, dict) and "parsed" in current:
        if all(k in ('parsed', 'value', '_metadata_') for k in current.keys()):
            return current.get('parsed', default)

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
        if isinstance(entry, dict) and "parsed" in entry and "value" in entry:
            candidate = entry["parsed"]

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

## File: src/pktparsers/core/parsing.py
```python
import json
import re
import binascii
import struct
from logging import getLogger
from dataclasses import dataclass
from functools import lru_cache
from contextvars import ContextVar
from contextlib import contextmanager
from pktparsers.core.definitions import *

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

bytes_for_mac = lambda mac : mac_vendor_resolver.mac_resolver(mac)
bytes_for_oui = lambda oui : mac_vendor_resolver.oui_resolver(oui)

def read_mac() -> dict:
    return unpack(EUI48_FMT, parser=bytes_for_mac)

def read_oui() -> dict:
    return unpack(OUI_FMT, parser=bytes_for_oui)

def random_mac():
    mac = [random.randint(0x00, 0xFF) for _ in range(6)]
    return ':'.join(f"{hex_byte:02x}" for hex_byte in mac)

mac_for_bytes = lambda mac : bytes(int(hex_byte, 16) for hex_byte in mac.split(":"))

def insert_item(container: dict, key: str | int, val):
    if key not in container:
        container[key] = val
        return
    if not isinstance(container[key], dict) or not all(k.isdigit() for k in container[key]):
        container[key] = {"1": container[key]}
    idx = str(len(container[key]) + 1)
    container[key][idx] = val

"""
Context manager for parsing.
ParseContext: maintains offset, frame bytes, and result dict during parsing
"""
_parse_context = ContextVar("_parse_context")
class ParseContext:
    """
    Context manager for packet parsing.
    Maintains:
        - frame: raw packet bytes
        - offset: current position in frame
        - result: accumulated parse result dict
    """
    
    def __init__(self, frame: bytes, start_offset: int = 0):
        self.frame = frame
        self.offset = start_offset
        self.result = {}
        self._token = None

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

    sizes = sizes[0] if len(sizes) == 1 else sizes
    tokens = tokens[0] if len(tokens) == 1 else tokens

    return sizes, tuple(tokens), s

def _add_metadata(raw: bytes, start_offset: int, end_offset: int, fmt: str | dict, tokens: str | dict, sizes: int | dict, size: int):
    raw_hex = raw[start_offset:end_offset].hex()
    length = end_offset - start_offset
    return {
        METADATA: {
            "start": start_offset,
            "end": end_offset,
            "length": length,
            RAW: raw_hex,
            "fmt": fmt,
            TOKENS: tokens,
            "sizes": sizes,
            "size": size
        }
    }

def unpack(fmt: str = None, parser: callable = None, summarizer: str | callable = None, **kwargs) -> dict:
    def value_to_dict(value):
        return {i: v for i, v in enumerate(value)} if isinstance(value, tuple) else value

    result = {}

    ctx = ParseContext.current()
    raw = ctx.frame
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

    value = value[0] if len(value) == 1 else value

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
    logger.debug(f"run dispatch")

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

def detect_fcs(frame: bytes, offset: int) -> bytes | None:
    logger.debug("detect_fcs function")
    flen = len(frame)
    logger.debug(f"detect_fcs function: frame:{frame} offset={offset} flen={flen}")

    if offset is None or offset < 0 or offset >= flen:
        return None

    payload_len = flen - offset
    if payload_len < IEEE80211_FCS_LEN:
        return None

    fcs_start = flen - IEEE80211_FCS_LEN
    fcs_bytes = frame[fcs_start:flen]
    candidate_fcs = int.from_bytes(fcs_bytes, "little")
    data_for_crc = frame[offset:fcs_start]
    calc_crc = binascii.crc32(data_for_crc) & 0xFFFFFFFF

    if calc_crc == candidate_fcs:
        ctx.frame = frame[:fcs_start]
        return fcs_bytes.hex()
    else:
        return None

def fail(result: dict, expected_size: int, e: str = "Parser error", debug_msg: str = "Parse error"):
    logger.debug("fail function")
    ctx = ParseContext.current()
    insert_item(result, FAIL, e)
    frame_len = len(ctx.frame)
    if expected_size is not None:
        ctx.offset = min(expected_size, frame_len)
    logger.debug(f"{debug_msg} frame_len={frame_len} ctx.offset={ctx.offset} expected_size={expected_size} result={result}")
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

wireshark_format = lambda packet_bytes : ":".join(f"{byte:02x}" for byte in packet_bytes)

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
```

## File: src/pktparsers/core/registry.py
```python
# pktparsers/core/registry.py

from pktparsers.core.layers.l2.ieee802 import dot11
from pktparsers.core.layers.l2.ieee802.dot11.dlt import ieee802_11_radio as dot11_radio
from pktparsers.core.definitions import *

@dataclass
class DltEntry:
    value: int
    parser: Callable
    summarizer: Callable | None = None
    analyzer: Callable | None = None
    encryptor: Callable | None = None
    decryptor: Callable | None = None
    config: DltConfig = None

@dataclass
class ProtocolEntry:
    name: str
    description: str
    parser: Callable
    summarier: Callable | None = None
    analyzer: Callable | None = None
    encryptor: Callable | None = None
    decryptor: Callable | None = None
    config: ProtocolConfig = None

DLT = {
    DLT_IEEE802_11_RADIO: DltEntry(
        name="DLT_IEEE802_11_RADIO",
        parser=dot11_radio.parse,
        summarizer=dot11_radio.analyzers.summary.summarize,
        analyzer=dot11_radio.analyzers.summary.analyzers,
        config=dot11_radio.definitions.config,
    ),

    DLT_IEEE802_11: DltEntry(
        name="DLT_IEEE802_11",
        parser=dot11.parse,
        summarizer=dot11_summary.summarize,
        analyzer=dot11_summary.analyze,
        config=dot11.definitions.config,
    ),

    DLT_EN10MB: DltEntry(
        name="DLT_EN10MB",
        parser=dot3.parse,
        summarizer=dot3_summary.summarize,
        analyzer=dot3_summary.analyze,
        config=dot3.definitions.config,
    ),
}

PROTOCOL = {
    DOT11: ProtocolEntry(
        description="IEEE 802.11",
        parser=dot11.parse,
        summarizer=dot11_summary.summarize,
        analyzer=dot11_summary.analyze,
        config=dot11.definitions.config,
    ),

    DOT3: ProtocolEntry(
        description="IEEE 802.3 Ethernet",
        parser=dot3.parse,
        summarizer=dot3_summary.summarize,
        analyzer=dot3_summary.analyze,
        config=dot3.definitions.config,
    ),

    DOT1X: ProtocolEntry(
        description="IEEE 802.1X",
        config=dot1x.definitions.config,
    ),

    LLC: ProtocolEntry(
        description="Logical Link Control",
        parser=llc.parse,
        summarizer=llc_summary.summarize,
        analyzer=llc_summary.analyze,
        config=llc.definitions.config,
    ),

    SNAP: ProtocolEntry(
        description="Subnetwork Access Protocol",
        parser=snap.parse,
        summarizer=snap_summary.summarize,
        analyzer=snap_summary.analyze,
        config=snap.definitions.config,
    ),

    ARP: ProtocolEntry(
        description="Address Resolution Protocol",
        parser=arp.parse,
        summarizer=arp_summary.summarize,
        analyzer=arp_summary.analyze,
        config=arp.definitions.config,
    ),

    IP: ProtocolEntry(
        description="Internet Protocol",
        parser=ip.parse,
        summarizer=ip_summary.summarize,
        analyzer=ip_summary.analyze,
        config=ip.definitions.config,
    ),

    IPV4: ProtocolEntry(
        description="Internet Protocol Version 4",
        parser=ipv4.parse,
        summarizer=ipv4_summary.summarize,
        analyzer=ipv4_summary.analyze,
        config=ipv4.definitions.config,
    ),

    IPV6: ProtocolEntry(
        description="Internet Protocol Version 6",
        parser=ipv6.parse,
        summarizer=ipv6_summary.summarize,
        analyzer=ipv6_summary.analyze,
        config=ipv6.definitions.config,
    ),

    ICMP: ProtocolEntry(
        description="Internet Control Message Protocol",
        parser=icmp.parse,
        summarizer=icmp_summary.summarize,
        analyzer=icmp_summary.analyze,
        config=icmp.definitions.config,
    ),

    ICMPV6: ProtocolEntry(
        description="Internet Control Message Protocol Version 6",
        parser=icmpv6.parse,
        summarizer=icmpv6_summary.summarize,
        analyzer=icmpv6_summary.analyze,
        config=icmpv6.definitions.config,
    ),

    TCP: ProtocolEntry(
        description="Transmission Control Protocol",
        parser=tcp.parse,
        summarizer=tcp_summary.summarize,
        analyzer=tcp_summary.analyze,
        config=tcp.definitions.config,
    ),

    UDP: ProtocolEntry(
        description="User Datagram Protocol",
        parser=udp.parse,
        summarizer=udp_summary.summarize,
        analyzer=udp_summary.analyze,
        config=udp.definitions.config,
    ),

    EAPOL: ProtocolEntry(
        description="EAP over LAN",
        parser=eapol.parse,
        summarizer=eapol_summary.summarize,
        analyzer=eapol_summary.analyze,
        config=eapol.definitions.config,
    ),

    EAP: ProtocolEntry(
        description="Extensible Authentication Protocol",
        parser=eap.parse,
        summarizer=eap_summary.summarize,
        analyzer=eap_summary.analyze,
        config=eap.definitions.config,
    ),

    RADIUS: ProtocolEntry(
        description="Remote Authentication Dial-In User Service",
        parser=radius.parse,
        summarizer=radius_summary.summarize,
        analyzer=radius_summary.analyze,
        config=radius.definitions.config,
    ),

    MESH_CTRL: ProtocolEntry(
        description="Mesh Control",
    ),

    TDLS: ProtocolEntry(
        description="Tunneled Direct Link Setup",
    ),

    WAPI: ProtocolEntry(
        description="WLAN Authentication and Privacy Infrastructure",
    ),

    FAST_BSS_TRANSITION: ProtocolEntry(
        description="Fast BSS Transition",
    ),

    DLS: ProtocolEntry(
        description="Direct Link Setup",
    ),

    RAS: ProtocolEntry(
        description="Robust Audio Video Streaming",
    ),

    WMM: ProtocolEntry(
        description="Wi-Fi Multimedia",
    ),

    QOS_NULL: ProtocolEntry(
        description="QoS Null",
    ),
}

def get_protocol(protocol_name: str) -> ProtocolEntry | None:
    return PROTOCOLS.get(protocol_name)

def get_protocol_parser(protocol_name: str):
    protocol = get_protocol(protocol_name)
    if not protocol:
        return None
    return protocol.parser

def get_dlt(dlt: str | int) -> DltEntry | None:
    if isinstance(dlt, str):
        entry = next((v for v in DLT.values() if v.name == dlt), None)
    return DLT.get(dlt)

def get_dlt_parser(dlt: str | int):
    return get_dlt(dlt).parser
```

## File: src/pktparsers/core/traffic.py
```python
# pktparsers/core/traffic.py

import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Optional

def make_device_entry() -> dict:
    return {
        "first_seen": time.time(),
        "last_seen":  time.time(),
        "protocols_data": {},
        "annotations": {},
    }

def make_traffic_summary() -> dict:
    return {
        "devices": {},
        "annotations": {},
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

## File: src/pktparsers/io/src_pktparsers_io___init__.py
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

## File: src/pktparsers/tui/widgets/fieldeditor.py
```python

```

## File: src/pktparsers/tui/widgets/hexview.py
```python

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

## File: src/pktparsers/tui/app.py
```python

```

## File: src/pktparsers/tui/main.py
```python

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

## File: src/pktparsers/__main__.py
```python
from pktparsers.cli.main import main
main()
```

## File: tests/bitmap_key_information.py
```python
key_information = 0x13ca

bitmap_key_information = {
  "Key descriptor version": (0, 2),
  "Key type": (3, 1),
  "Key index": (4, 2),
  "Install": (6, 1),
  "Key ACK": (7, 1),
  "Key MIC": (8, 1),
  "Secure": (9, 1),
  "Error": (10, 1),
  "Request": (11, 1),
  "Encrypted key data": (12, 1),
  "SMK message": (13, 1)
}

flags_key_information = {
  "Key descriptor version": {1: "HMAC-MD5 (WPA)", 2: "AES/HMAC-SHA1 (WPA2/WPA3)"},
  "Key type": {0: "Group (GTK)", 1: "Pairwise (PTK)"},
}

def parser_bitmap_key_information(key_information, key_information_list):
    key_information_result = {}
    for key, (bit_position, bits_len) in key_information_list.items():
        bits_mask = (1 << bits_len) - 1
        value = (key_information >> bit_position) & bits_mask
        if key in flags_key_information and value in flags_key_information[key]:
           key_information_result[key] = f"{value} {flags_key_information[key][value]}"
        else:
            key_information_result[key] = value

    return key_information_result

print(parser_bitmap_key_information(key_information, bitmap_key_information))

"""
def parser_bitmaps(bitmap_value, bitmap_list):
    for key, value in bitmap_list:
        if  == 
"""

# 0001001111001010
# 2 == 010

# 0001001111001010

#0010
#0001
#0000
#
```

## File: tests/tests.py
```python
# pktparsers/tests/tests.py

import json
import time
import socket
import threading
from pathlib import Path
from logging import getLogger
from cli_core.files import iter_from_json
from cli_core.log import setup_logging
from pktparsers.dissector import Dissector, DissectConfig
from pktparsers.common.parse.filter_engine import apply_filters, get_nested
from pktparsers.common.parse.utils import raw_packet_extractor
from pktparsers.common.io import (
    read,
    write,
    merge_packets,
    read_filters,
    write_filters,
    PacketWriter,
    supported_formats,
    _detect_format,
)

logger = getLogger(__name__)

ENABLE_SYSTEM_TESTS = False
INTERACTIVE_MODE    = True
RUN_ALL             = False

# Adjust paths to match your environment
FRAMES_DOT11_RADIO_JSON  = Path("~/Documents/pktparsers/pktparsers/tests/frames_dot11_radio.json").expanduser()
FRAMES_DOT11_RADIO_PCAP  = Path("~/Documents/pktparsers/pktparsers/tests/frames_dot11_radio.pcap").expanduser()
FRAMES_DOT11_RADIO_PCAPNG = Path("~/Documents/pktparsers/pktparsers/tests/frames_dot11_radio.pcapng").expanduser()
FRAMES_DOT11_RADIO_ERF   = Path("~/Documents/pktparsers/pktparsers/tests/frames_dot11_radio.erf").expanduser()

FILTERS_JSON  = Path("/tmp/pktparsers_test_filters.json")
FILTERS_JSONL = Path("/tmp/pktparsers_test_filters.jsonl")

OUTPUT_PCAP   = Path("/tmp/pktparsers_test_out.pcap")
OUTPUT_PCAPNG = Path("/tmp/pktparsers_test_out.pcapng")
OUTPUT_ERF    = Path("/tmp/pktparsers_test_out.erf")
OUTPUT_JSONL  = Path("/tmp/pktparsers_test_out.jsonl")
OUTPUT_JSON   = Path("/tmp/pktparsers_test_out.json")
OUTPUT_MERGED = Path("/tmp/pktparsers_test_merged.pcap")

LIVE_IFACE = "wlan0"  # adjust to your monitor-mode interface
DLT_RADIO  = "DLT_IEEE802_11_RADIO"
DLT_EN10MB = 1

FORMAT_TO_PATH = [
    ("pcap",   OUTPUT_PCAP),
    ("pcapng", OUTPUT_PCAPNG),
    ("erf",    OUTPUT_ERF),
    ("jsonl",  OUTPUT_JSONL),
    ("json",   OUTPUT_JSON),
]

# ---------------------------------------------------------------------------
# Test runner helpers
# ---------------------------------------------------------------------------

def should_run_test(name: str) -> bool:
    global RUN_ALL
    if not INTERACTIVE_MODE or RUN_ALL:
        return True
    choice = input(f"Run test '{name}'? [y/n/a]: ").strip().lower()
    if choice == "a":
        RUN_ALL = True
        return True
    return choice in ("y", "yes")


def run_test(name: str, func, *args, **kwargs):
    if not should_run_test(name):
        logger.info(f"[SKIPPED] {name}")
        return None
    logger.info(f"\n[TEST START] {name}")
    try:
        result = func(*args, **kwargs)
        logger.info(f"[TEST OK] {name} → {result}")
        return result
    except Exception as e:
        logger.error(f"[TEST FAIL] {name}: {e}", exc_info=True)
    finally:
        logger.info(f"[TEST END] {name}\n")


def run_blocking_test(name: str, func, timeout: float = 10, **kwargs):
    if not should_run_test(name):
        logger.info(f"[SKIPPED] {name}")
        return
    logger.info(f"\n[TEST START] {name}")
    stop_event = threading.Event()

    def target():
        try:
            func(timeout=timeout, stop_event=stop_event, **kwargs)
        except Exception as e:
            logger.error(f"[THREAD ERROR] {name}: {e}", exc_info=True)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    try:
        thread.join(timeout)
        if thread.is_alive():
            logger.warning(f"[TIMEOUT] {name} exceeded {timeout}s, stopping...")
            stop_event.set()
            thread.join(2)
    except KeyboardInterrupt:
        logger.warning(f"[INTERRUPTED] {name} (Ctrl+C)")
        stop_event.set()
        thread.join(2)
    logger.info(f"[TEST END] {name}\n")


# Dissector tests

def test_dissect_from_json(packets_file: Path, dlt: str | int) -> int:
    """
    Read raw packets from a json/jsonl file via iter_from_json + raw_packet_extractor,
    dissect each one, and log a short excerpt of the result.

    Returns the number of packets successfully dissected.
    """
    with Dissector(dlt) as dissector:
        for _hex, raw in iter_from_json(packets_file, raw_packet_extractor()):
            result = dissector.dissect(raw)
            excerpt = json.dumps(result, default=str)[:160]
            logger.info(f"  [dissect #{dissector.counter}] {excerpt}...")
        logger.info(f"  Dissected {dissector.counter} packet(s) from {packets_file.name}")
    return count

def test_get_nested(parsed: dict):
    """Exercise get_nested against a set of known dot11-radio paths."""
    paths = [
        "rt_hdr.dbm_antenna_signal",
        "rt_hdr.channel.channel",
        "dot11.mac_hdr.fc.type_name",
        "dot11.mac_hdr.sa.addr",
        "dot11.mac_hdr.bssid.addr",
        "dot11.body.fp.beacon_interval",
    ]
    logger.info("  [get_nested] results:")
    for p in paths:
        val = get_nested(p, parsed)
        logger.info(f"    {p:50s} = {val!r}")

def test_apply_filters(parsed: dict):
    """Run a small set of store/display filter pairs against a parsed frame."""
    cases = [
        ("dot11.mac_hdr.fc.type == 0",       "dot11.mac_hdr.fc.type_name"),
        ("rt_hdr.dbm_antenna_signal > -80",  "rt_hdr.dbm_antenna_signal"),
        ("dot11.mac_hdr.fc.type != 99",      "dot11.mac_hdr.sa.addr,dot11.mac_hdr.bssid.addr"),
    ]
    logger.info("  [apply_filters] results:")
    for store_f, display_f in cases:
        store_ok, display = apply_filters(store_f, display_f, parsed)
        logger.info(f"    store='{store_f}' → {store_ok}  |  display='{display_f}' → {display!r}")


def test_dissect_and_filter(packets_file: Path, dlt: str | int):
    """
    Dissect packets from a json/jsonl file and run filter tests against the
    first successfully parsed result.
    """
    first_result = None
    with Dissector(dlt) as dissector:
        for _hex, raw in iter_from_json(packets_file, raw_packet_extractor()):
            first_result = dissector.dissect(raw)
            break

    if first_result is None:
        logger.warning("  No packets found in file — skipping filter tests")
        return

    test_get_nested(first_result)
    test_apply_filters(first_result)


# ---------------------------------------------------------------------------
# IO — read() tests
# ---------------------------------------------------------------------------

def test_read_format(path: Path, dlt: str | int = None, label: str = None) -> int:
    """
    Read any supported format via io.read() and count the yielded results.
    For pcap/pcapng/erf the file must exist; for json/jsonl no dlt is needed.
    """
    label = label or path.suffix.lstrip(".")
    if not path.exists():
        logger.warning(f"  [{label}] file not found, skipping: {path}")
        return 0

    count = 0
    for result in read(path):
        count += 1
        if count == 1:
            excerpt = json.dumps(result, default=str)[:160]
            logger.info(f"  [{label}] first result: {excerpt}...")

    logger.info(f"  [{label}] total results: {count}")
    return count


# ---------------------------------------------------------------------------
# IO — write() / PacketWriter tests
# ---------------------------------------------------------------------------

def test_write_single(packets_file: Path, dlt: str | int):
    """
    Extract raw bytes from a json/jsonl source and write them one at a time
    via io.write() for every binary output format.
    """
    packets: list[bytes] = []
    for _hex, raw in iter_from_json(packets_file, raw_packet_extractor()):
        packets.append(raw)
        if len(packets) >= 5:
            break

    if not packets:
        logger.warning("  No raw packets available for write test")
        return

    dlt_int = dlt if isinstance(dlt, int) else DLT_IEEE802_11_RADIO

    for fmt, out_path in FORMAT_TO_PATH:
        write(packets[0], out_path, fmt=fmt, dlt=dlt_int)
        logger.info(f"  [write single/{fmt}] wrote to {out_path}")


def test_packet_writer(packets_file: Path, dlt: str | int, max_bytes: int = None):
    """
    Write packets incrementally via PacketWriter.
    Tests both the normal case and the max_bytes size cap.
    """
    packets: list[bytes] = []
    for _hex, raw in iter_from_json(packets_file, raw_packet_extractor()):
        packets.append(raw)

    if not packets:
        logger.warning("  No raw packets available for PacketWriter test")
        return

    dlt_int = dlt if isinstance(dlt, int) else DLT_IEEE802_11_RADIO

    for fmt, out_path in FORMAT_TO_PATH:
        written = 0
        with PacketWriter(out_path, fmt=fmt, dlt=dlt_int, max_bytes=max_bytes) as pw:
            for raw in packets:
                if not pw.write({"raw": raw.hex()}):
                    logger.info(f"  [PacketWriter/{fmt}] size cap reached after {written} packet(s)")
                    break
                written += 1

        logger.info(f"  [PacketWriter/{fmt}] wrote {written} packet(s) to {out_path}")

        # Verify the file is readable back through io.read()
        if fmt in ("jsonl", "json") and out_path.exists():
            back = list(read(out_path))
            logger.info(f"  [PacketWriter/{fmt}] read back {len(back)} object(s)")

def test_packet_writer_size_cap(packets_file: Path, dlt: str | int):
    """Dedicated test: verify PacketWriter stops at the given max_bytes limit."""
    # Use a very small cap (1 KB) to trigger the limit quickly
    test_packet_writer(packets_file, dlt, max_bytes=1024)

# ---------------------------------------------------------------------------
# IO — merge_packets() test
# ---------------------------------------------------------------------------

def test_merge_packets(src: Path, dst_format: str = "pcap"):
    """
    Merge a source file into a new file of dst_format via merge_packets().
    Verifies the output is readable.
    """
    if not src.exists():
        logger.warning(f"  [merge] source not found, skipping: {src}")
        return

    merge_packets(src, OUTPUT_MERGED.with_suffix(f".{dst_format}"), dst_format)
    out = OUTPUT_MERGED.with_suffix(f".{dst_format}")
    logger.info(f"  [merge] {src.name} → {out.name}")

    if out.exists() and dst_format in ("jsonl", "json"):
        count = sum(1 for _ in read(out))
        logger.info(f"  [merge] read back {count} object(s)")


# ---------------------------------------------------------------------------
# IO — filter helpers test
# ---------------------------------------------------------------------------

def test_filter_io():
    """
    Exercise write_filters / read_filters round-trip for both .json and .jsonl.
    """
    store_f   = "dot11.mac_hdr.fc.type == 0"
    display_f = "dot11.mac_hdr.sa.addr"

    write_filters(FILTERS_JSON,  simple_path=True,  store_filter=store_f, display_filter=display_f)
    write_filters(FILTERS_JSONL, simple_path=False, store_filter=store_f, display_filter=display_f)

    loaded_json  = read_filters(FILTERS_JSON)
    loaded_jsonl = read_filters(FILTERS_JSONL)

    logger.info(f"  [filter_io] json  round-trip: {loaded_json}")
    logger.info(f"  [filter_io] jsonl round-trip: {loaded_jsonl}")

    assert loaded_json.get("store")   == store_f,   "json store mismatch"
    assert loaded_json.get("display") == display_f, "json display mismatch"
    assert isinstance(loaded_jsonl, list) and loaded_jsonl[0].get("store") == store_f


# ---------------------------------------------------------------------------
# System test — live capture
# ---------------------------------------------------------------------------

def test_live_capture(
    stop_event: threading.Event = None,
    timeout: float = 10,
    store_filter: str = None,
    output_path: Path = None,
    output_fmt: str = "jsonl",
):
    """
    Live capture on a raw AF_PACKET socket, dissect each frame, optionally
    filter and store matches via PacketWriter.

    Requires a monitor-mode interface and root privileges.
    """
    dlt     = DLT_RADIO
    dlt_int = 127
    sock    = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((LIVE_IFACE, 0))
    sock.settimeout(1.0)

    writer = None
    if output_path:
        writer = PacketWriter(output_path, fmt=output_fmt, dlt=dlt_int).__enter__()

    start = time.time()
    count = stored = 0
    try:
        with Dissector(dlt) as dissector:
            while not (stop_event and stop_event.is_set()):
                if time.time() - start >= timeout:
                    break
                try:
                    raw, _ = sock.recvfrom(65535)
                except socket.timeout:
                    continue

                result = dissector.dissect(raw)
                count += 1

                store_ok, display = apply_filters(store_filter, None, result)
                excerpt = json.dumps(result, default=str)[:120]
                logger.info(f"  [live #{count}] store={store_ok} {excerpt}...")

                if store_ok and writer:
                    if not writer.write(result):
                        logger.info("  [live] output size cap reached, stopping")
                        break
                    stored += 1

    finally:
        sock.close()
        if writer:
            writer.__exit__(None, None, None)
        logger.info(f"  [live] captured={count} stored={stored}")


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

def run_tests():
    # --- Dissector ---
    run_test(
        "dissect packets from json (dot11 radio)",
        test_dissect_from_json,
        FRAMES_DOT11_RADIO_JSON,
        DLT_RADIO,
    )

    run_test(
        "dissect + get_nested + apply_filters (dot11 radio)",
        test_dissect_and_filter,
        FRAMES_DOT11_RADIO_JSON,
        DLT_RADIO,
    )

    # --- io.read() ---
    run_test("read json",   test_read_format, FRAMES_DOT11_RADIO_JSON)
    run_test("read pcap",   test_read_format, FRAMES_DOT11_RADIO_PCAP,   dlt=DLT_RADIO, label="pcap")
    run_test("read pcapng", test_read_format, FRAMES_DOT11_RADIO_PCAPNG, dlt=DLT_RADIO, label="pcapng")
    run_test("read erf",    test_read_format, FRAMES_DOT11_RADIO_ERF,    dlt=DLT_RADIO, label="erf")

    # --- io.write() ---
    run_test(
        "write single packet (all formats)",
        test_write_single,
        FRAMES_DOT11_RADIO_JSON,
        DLT_RADIO,
    )

    # --- PacketWriter ---
    run_test(
        "PacketWriter incremental write (all formats)",
        test_packet_writer,
        FRAMES_DOT11_RADIO_JSON,
        DLT_IEEE802_RADIO,
    )

    run_test(
        "PacketWriter size cap (max_bytes=1024)",
        test_packet_writer_size_cap,
        FRAMES_DOT11_RADIO_JSON,
        DLT_RADIO,
    )

    # --- merge_packets ---
    run_test("merge json → pcap",   test_merge_packets, FRAMES_DOT11_RADIO_JSON,  dst_format="pcap")
    run_test("merge json → jsonl",  test_merge_packets, FRAMES_DOT11_RADIO_JSON,  dst_format="jsonl")
    run_test("merge pcap → jsonl",  test_merge_packets, FRAMES_DOT11_RADIO_PCAP,  dst_format="jsonl")

    # --- filter IO helpers ---
    run_test("filter write/read round-trip", test_filter_io)

    if ENABLE_SYSTEM_TESTS:
        logger.warning("SYSTEM TESTS ENABLED — requires monitor interface and root")
        run_blocking_test(
            "live capture 10s (no filter, no output)",
            test_live_capture,
            timeout=10,
        )
        run_blocking_test(
            "live capture 10s (store beacon frames → jsonl)",
            test_live_capture,
            timeout=10,
            store_filter="dot11.mac_hdr.fc.type == 0",
            output_path=Path("/tmp/pktparsers_live_beacons.jsonl"),
            output_fmt="jsonl",
        )
    else:
        logger.info("System tests disabled (set ENABLE_SYSTEM_TESTS = True to enable)")


def main():
    setup_logging(verbose=True, output_fullpath="/tmp/pktparsers_tests.log")
    run_tests()


if __name__ == "__main__":
    main()
```
