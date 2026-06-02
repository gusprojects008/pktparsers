# pktparsers/tui/screens/dissect_config.py

from textual.screen import ModalScreen
from textual.widgets import ListView, ListItem, Label, Switch, Input

class DissectConfigScreen(ModalScreen):
    """
    Modal gerado dinamicamente a partir de AppConfig.dissect.
    Não tem nenhuma referência hardcoded a protocolos específicos.
    """

    def __init__(self, app_config: "AppConfig") -> None:
        self._app_config = app_config
        super().__init__()

    def compose(self):
        # Itera dlt configs e protocol configs do AppConfig
        # Cada chave do config dict vira um widget baseado no tipo do valor:
        #   bool  → Switch
        #   str   → Input
        #   dict  → sub-seção expandível
        for section, configs in self._app_config.dissect.items():
            yield Label(section)
            yield from self._widgets_for(configs)

    def _widgets_for(self, cfg: dict):
        for key, val in cfg.items():
            if isinstance(val, bool):
                yield Switch(value=val, id=key)
            elif isinstance(val, str):
                yield Input(value=val, placeholder=key, id=key)
            elif isinstance(val, dict):
                yield Label(f"  {key}")
                yield from self._widgets_for(val)
