# pktparsers/core/registry.py

# core/registry.py — agrega tudo, mantém flat
from pktparsers.core.dissectors.ieee802 import registry as ieee802_registry
from pktparsers.core.dissectors.inet    import registry as inet_registry
from pktparsers.core.dissectors.bluetooth import registry as bt_registry
# protocolos, dlts ou padrões simples, que não possuem sub-protocolos, ou que não estão associados à nenhum domínio/família como inet ou ieee80211, são registrados diretamente na tabela, como o no caso de ARP
from pktparsers.core.dissectors.arp import parse as arp_parse
import pktparsers.core.definitions.protocol as proto
import pktparsers.core.definitions.entries as (L2, L3, L4, L7)

DLT: dict[int, DissectorEntry] = {
    **ieee802_registry.DLT,
    **inet_registry.DLT,
    **bt_registry.DLT,
}

PROTOCOL: dict[str, DissectorEntry] = {
    **ieee802_registry.PROTOCOL,
    **inet_registry.PROTOCOL,
    **bt_registry.PROTOCOL,
    # arp diretamente aqui
    proto.ARP: DissectorEntry(
        description="Address Resolution Protocol",
        layer=L3,
        parser=arp_parse.arp,
        config=None,
    ),
}

def get_protocol(protocol_name: str) -> DissectorEntry | None:
    return PROTOCOL.get(protocol_name)


def get_protocol_parser(protocol_name: str):
    protocol = get_protocol(protocol_name)

    if not protocol:
        return None

    return protocol.parser


def get_dlt(dlt_value: str | int) -> DissectorEntry | None:
    if isinstance(dlt_value, str):
        return next(
            (entry for entry in DLT.values() if entry.name == dlt_value),
            None,
        )

    return DLT.get(dlt_value)


def get_dlt_parser(dlt_value: str | int):
    dlt_entry = get_dlt(dlt_value)

    if not dlt_entry:
        return None

    return dlt_entry.parser
