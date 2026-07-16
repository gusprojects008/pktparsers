# pktparsers/app/app.py

from dataclasses import dataclass, field
from pktparsers import io
from pktparsers import dissect
from cli_core.app import Config as AppConfig

@dataclass
class Config:
    """
    Configuração raiz do pktparsers como framework.
    Gerada por make_config() e serializada/carregada como JSON.
    
    Separação de responsabilidades:
      - Config é o contrato serializado (pode ir para disco)
      - DissectConfig é gerado a partir dela no momento de uso
      - AppContext (app/context.py) gerencia paths e I/O de disco
    """
    dissect: dict = field(default_factory=dict)   # → gera DissectConfig
    output:  dict = field(default_factory=dict)   # → gera OutputConfig

def make_config() -> AppConfig:
    dissectors_config = dissect.make_config()
    output_config = io.make_config()
    config = AppConfig()
    config.dissect = dissectors_config
    config.output_config = output_config
    return config
