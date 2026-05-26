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