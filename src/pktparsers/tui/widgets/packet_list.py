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
