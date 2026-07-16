# pktparsers/tui/screens/credentials_config.py

class CredentialsConfigScreen(ModalScreen):
    """
    Modal de edição de credentials de um protocolo de autenticação.
    Gerado a partir de config["protocol"][protocol_name]["crypt"].
    """

    def __init__(self, protocol_name: str, crypt_config: dict) -> None:
        self._protocol   = protocol_name
        self._crypt_cfg  = crypt_config
        super().__init__()

    def compose(self):
        keys = self._crypt_cfg.get(CREDENTIALS, {}).get("keys", [])

        yield Label(f"Credentials — {self._protocol}")

        # Lista de keys existentes — cada uma editável/removível
        for i, key_entry in enumerate(keys):
            yield Horizontal(
                Input(value=key_entry.get("value", ""), id=f"key-value-{i}"),
                Select([(t, t) for t in self._supported_types()], value=key_entry.get("type"), id=f"key-type-{i}"),
                Button("✕", id=f"remove-{i}"),
            )

        yield Horizontal(
            Button("+ Add key",            id="btn-add-key"),
            Button("Load from capture…",   id="btn-load-capture"),
            Button("Save",                 id="btn-save"),
        )

    def _supported_types(self) -> list[str]:
        # Lido do make_config() do protocolo — sem hardcode aqui
        return self._crypt_cfg.get("supported_key_types", ["psk", "pmk", "tk"])

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-load-capture":
            # Abre FileSelector → on_file_selected chama analyze_capture_for_credentials()
            self.app.push_screen(FileSelectorScreen(callback=self._on_capture_selected))

    def _on_capture_selected(self, path: Path) -> None:
        from pktparsers.core.crypt import analyze_capture_for_credentials
        keys = analyze_capture_for_credentials(path, self._protocol)
        # Popula a lista de keys automaticamente
        self._crypt_cfg[CREDENTIALS]["keys"].extend(keys)
        self.refresh()
