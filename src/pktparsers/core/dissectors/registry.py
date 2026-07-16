# pktparsers/core/registry.py

# core/registry.py — agrega tudo, mantém flat
from pktparsers.core.dissectors.ieee802 import registry as ieee802_registry
from pktparsers.core.dissectors.inet    import registry as inet_registry
from pktparsers.core.dissectors.bluetooth import registry as bt_registry
# protocolos, dlts ou padrões simples, que não possuem sub-protocolos, ou que não estão associados à nenhum domínio/família como inet ou ieee80211, são registrados diretamente na tabela, como o no caso de ARP
from pktparsers.core.dissectors.arp import parse as arp_parse
import pktparsers.core.definitions.protocol as proto
import pktparsers.core.definitions.entries as (L2, L3, L4, L7)

DISSECTORS: dict[int str, DissectorEntry] = {
    **ieee802_registry.DISSECTORS,
    **ieee802_registry.DISSECTORS,
    **inet_registry.DISSECTORS,
    **bt_registry.DISSECTORS,
    # arp diretamente aqui
    proto.ARP: DissectorEntry(
        description="Address Resolution Protocol",
        kind=PROTOCOL,
        layer=L3,
        parser=arp_parse.arp,
        config=None,
    ),
}

def get_dissector(identifier):
    if isinstance(identifier, int):
        identifier = DLTS.get(identifier)
    return DISSECTORS.get(identifier)

# used by dissectors in dissectors/raw/
def register(dissector_id: int | str, entry: DissectorEntry): # dissector_id it could be a protocol name or a DLT value.
    DISSECTORS[dissector_id] = entry
    return DISSECTORS
