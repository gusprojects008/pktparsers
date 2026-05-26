from dataclasses import dataclass
from pktparsers.io import OutputConfig

class PktparsersConfig:
    dissect_cfg: DissectConfig = DissectConfig()
    output_cfg: OutputConfig = OutputConfig()
