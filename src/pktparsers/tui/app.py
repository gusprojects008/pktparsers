def on_packet_tree_field_focused(self, event: PacketTree.FieldFocused) -> None:
    self.query_one(HexView).set_highlight(event.start, event.end)
