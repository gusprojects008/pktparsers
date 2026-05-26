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