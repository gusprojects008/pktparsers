# pktparsers/app/app.py

import json
import copy
from dataclasses import dataclass, field
from pktparsers.io import OutputConfig
from pktparsers.core.definitions import (
    GLOBAL,
    CRYPT,
    PARSE,
    ANALYSIS,
    DLT,
    PROTOCOL
)
from pktparsers.core import registry
from pktparsers.core.analysis import make_config as make_analysis_config
from pktparsers.core.parsing import make_config as make_parse_config
from pktparsers.core.crypt import make_config as make_crypt_config
from pathlib import Path

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
    """
    Gera AppConfig lendo os CONFIGs registrados em registry.DLT e registry.PROTOCOL.
    
    Cada entry que tiver um CONFIG definido contribui com sua estrutura.
    Entries sem CONFIG (MESH_CTRL, TDLS etc.) são ignoradas silenciosamente.
    """
    dlt_configs = {
        entry.name: entry.config
        for entry in registry.DLT.values()
        if entry.config is not None
    }

    protocol_configs = {
        name: entry.config
        for name, entry in registry.PROTOCOL.items()
        if entry.config is not None
    }

    return AppConfig(
        dissect={
            GLOBAL: {
                CRYPT: make_crypt_config(),
                PARSE: make_parse_config(),
                ANALYSIS: make_analysis_config(),
            },
            DLT:      dlt_configs,
            PROTOCOL: protocol_configs,
        },
        output={},
    )
