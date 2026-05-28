# pktparsers/app/app.py

import json
from pathlib import Path

def save_app_config(config: AppConfig, path: Path) -> None:
    """Salva AppConfig em JSON. PTKs efêmeros NÃO são salvos."""
    data = _strip_ephemeral(config.dissect)
    path.write_text(json.dumps({"dissect": data, "output": config.output}, indent=2))

def load_app_config(path: Path) -> AppConfig:
    data = json.loads(path.read_text())
    return AppConfig(
        dissect=data.get("dissect", {}),
        output=data.get("output", {}),
    )

def _strip_ephemeral(dissect: dict) -> dict:
    """Remove PTKs derivados em tempo de execução antes de salvar em disco."""
    import copy
    d = copy.deepcopy(dissect)
    dot11 = d.get("dlt", {}).get("DLT_IEEE802_11_RADIO", {}).get("crypt", {}).get("dot11", {})
    for bssid_entry in dot11.values():
        for client in bssid_entry.get("clients", {}).values():
            client.pop("ptk", None)     # PTK: efêmero, não persiste
            client.pop("anonce", None)  # nonces: específicos da sessão
            client.pop("snonce", None)
    return d
