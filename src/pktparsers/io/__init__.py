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