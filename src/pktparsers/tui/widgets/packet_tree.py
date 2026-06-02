# pktparsers/tui/widgets/packet_tree.py

from textual.widgets import Tree
from textual.widgets.tree import TreeNode
from pktparsers.core.definitions.parsing import METADATA, PARSED, VALUE
from pktparsers.core.definitions.analysis import SUMMARY

class PacketTree(Tree):
    """
    Renderiza um dict parsed (resultado de Dissector.dissect) como árvore.
    
    Cada nó carrega o sub-dict correspondente para:
      - Highlight sincronizado com HexView (via _metadata_.start/end)
      - Context menu com Copy/As filter
      - Edição de campo (se FieldEditor estiver ativo)
    """
    
    def load_packet(self, parsed: dict) -> None:
        self.clear()
        self._build_node(self.root, parsed)
        self.root.expand()

    def _build_node(self, node: TreeNode, data: dict, key: str = "root") -> None:
        meta     = data.get(METADATA, {})
        parsed   = data.get(PARSED)
        value    = data.get(VALUE)
        summary  = data.get(SUMMARY)

        label = self._make_label(key, parsed, value, summary, meta)
        child = node.add(label, data=data)

        if isinstance(parsed, dict):
            for k, v in parsed.items():
                if isinstance(v, dict):
                    self._build_node(child, v, k)
                else:
                    child.add_leaf(f"{k}: {v}", data={VALUE: v})

    def _make_label(self, key, parsed, value, summary, meta) -> str:
        if summary:
            return f"{key}  [{summary}]"
        if value is not None and not isinstance(value, dict):
            return f"{key}: {value}"
        return key

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        data = event.node.data
        if not data:
            return
        meta = data.get(METADATA, {})
        # Emite mensagem para HexView sincronizar highlight
        self.post_message(self.FieldFocused(
            start=meta.get("start", 0),
            end=meta.get("end", 0),
            field_data=data,
        ))

    class FieldFocused(Message):
        def __init__(self, start: int, end: int, field_data: dict) -> None:
            self.start      = start
            self.end        = end
            self.field_data = field_data
            super().__init__()
