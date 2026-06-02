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
