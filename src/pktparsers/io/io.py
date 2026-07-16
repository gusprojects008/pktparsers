# pktparsers/common/io.py
import json
import struct
import time
import dpkt
from pathlib import Path
from typing import Generator
from pktparser.core.filter_engine import FilterConfig
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

@dataclass 
class Config:
    filters: FilterConfig | None = None
    output: OutputConfig | None = None

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
