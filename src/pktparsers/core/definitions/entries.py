from dataclasses import dataclass

@dataclass
class DissectorEntry:
    address_extractor: callable
    name: str
    parser: Callable
    layer: str
    description: str
    summarizer: Callable | None = None
    analyzer: Callable | None = None
    encryptor: Callable | None = None
    decryptor: Callable | None = None
    config: dict | None = None

CRYPT  = "crypt"
PARSE  = "parse"
GLOBAL = "global"
ANALYSIS = "analysis"
PROTOCOL = "protocol"

L2 = "l2"
L3 = "l3"
L4 = "l4"
L7 = "l7"
