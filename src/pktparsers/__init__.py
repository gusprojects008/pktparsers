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
