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
