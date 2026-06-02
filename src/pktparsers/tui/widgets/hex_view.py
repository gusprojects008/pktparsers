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
