# pktparsers/core/registry.py

from pktparsers.core.layers.l2.ieee802 import dot11
from pktparsers.core.layers.l2.ieee802.dot11.dlt import ieee802_11_radio as dot11_radio
from pktparsers.core.definitions import *

@dataclass
class DltEntry:
    value: int
    parser: Callable
    summarizer: Callable | None = None
    analyzer: Callable | None = None
    encryptor: Callable | None = None
    decryptor: Callable | None = None
    config: DltConfig = None

@dataclass
class ProtocolEntry:
    description: str
    parser: Callable
    summarier: Callable | None = None
    analyzer: Callable | None = None
    encryptor: Callable | None = None
    decryptor: Callable | None = None
    config: ProtocolConfig = None

DLT = {
    DLT_IEEE802_11_RADIO: DltEntry(
        name="DLT_IEEE802_11_RADIO",
        parser=dot11_radio.parse,
        summarizer=dot11_radio.analyzers.summary.summarize,
        analyzer=dot11_radio.analyzers.summary.analyzers,
        config=dot11_radio.definitions.config,
    ),

    DLT_IEEE802_11: DltEntry(
        name="DLT_IEEE802_11",
        parser=dot11.parse,
        summarizer=dot11_summary.summarize,
        analyzer=dot11_summary.analyze,
        config=dot11.definitions.config,
    ),

    DLT_EN10MB: DltEntry(
        name="DLT_EN10MB",
        parser=dot3.parse,
        summarizer=dot3_summary.summarize,
        analyzer=dot3_summary.analyze,
        config=dot3.definitions.config,
    ),
}

PROTOCOL = {
    IEE802_11: ProtocolEntry(
        description="IEEE 802.11",
        parser=dot11.parse,
        summarizer=dot11_summary.summarize,
        analyzer=dot11_summary.analyze,
        config=dot11.definitions.config,
    ),

    IEE802_3: ProtocolEntry(
        description="IEEE 802.3 Ethernet",
        parser=dot3.parse,
        summarizer=dot3_summary.summarize,
        analyzer=dot3_summary.analyze,
        config=dot3.definitions.config,
    ),

    IEE802_1X: ProtocolEntry(
        description="IEEE 802.1X",
        config=dot1x.definitions.config,
    ),

    LLC: ProtocolEntry(
        description="Logical Link Control",
        parser=llc.parse,
        summarizer=llc_summary.summarize,
        analyzer=llc_summary.analyze,
        config=llc.definitions.config,
    ),

    SNAP: ProtocolEntry(
        description="Subnetwork Access Protocol",
        parser=snap.parse,
        summarizer=snap_summary.summarize,
        analyzer=snap_summary.analyze,
        config=snap.definitions.config,
    ),

    ARP: ProtocolEntry(
        description="Address Resolution Protocol",
        parser=arp.parse,
        summarizer=arp_summary.summarize,
        analyzer=arp_summary.analyze,
        config=arp.definitions.config,
    ),

    IP: ProtocolEntry(
        description="Internet Protocol",
        parser=ip.parse,
        summarizer=ip_summary.summarize,
        analyzer=ip_summary.analyze,
        config=ip.definitions.config,
    ),

    IPV4: ProtocolEntry(
        description="Internet Protocol Version 4",
        parser=ipv4.parse,
        summarizer=ipv4_summary.summarize,
        analyzer=ipv4_summary.analyze,
        config=ipv4.definitions.config,
    ),

    IPV6: ProtocolEntry(
        description="Internet Protocol Version 6",
        parser=ipv6.parse,
        summarizer=ipv6_summary.summarize,
        analyzer=ipv6_summary.analyze,
        config=ipv6.definitions.config,
    ),

    ICMP: ProtocolEntry(
        description="Internet Control Message Protocol",
        parser=icmp.parse,
        summarizer=icmp_summary.summarize,
        analyzer=icmp_summary.analyze,
        config=icmp.definitions.config,
    ),

    ICMPV6: ProtocolEntry(
        description="Internet Control Message Protocol Version 6",
        parser=icmpv6.parse,
        summarizer=icmpv6_summary.summarize,
        analyzer=icmpv6_summary.analyze,
        config=icmpv6.definitions.config,
    ),

    TCP: ProtocolEntry(
        description="Transmission Control Protocol",
        parser=tcp.parse,
        summarizer=tcp_summary.summarize,
        analyzer=tcp_summary.analyze,
        config=tcp.definitions.config,
    ),

    UDP: ProtocolEntry(
        description="User Datagram Protocol",
        parser=udp.parse,
        summarizer=udp_summary.summarize,
        analyzer=udp_summary.analyze,
        config=udp.definitions.config,
    ),

    EAPOL: ProtocolEntry(
        description="EAP over LAN",
        parser=eapol.parse,
        summarizer=eapol_summary.summarize,
        analyzer=eapol_summary.analyze,
        config=eapol.definitions.config,
    ),

    EAP: ProtocolEntry(
        description="Extensible Authentication Protocol",
        parser=eap.parse,
        summarizer=eap_summary.summarize,
        analyzer=eap_summary.analyze,
        config=eap.definitions.config,
    ),

    RADIUS: ProtocolEntry(
        description="Remote Authentication Dial-In User Service",
        parser=radius.parse,
        summarizer=radius_summary.summarize,
        analyzer=radius_summary.analyze,
        config=radius.definitions.config,
    ),

    MESH_CTRL: ProtocolEntry(
        description="Mesh Control",
    ),

    TDLS: ProtocolEntry(
        description="Tunneled Direct Link Setup",
    ),

    WAPI: ProtocolEntry(
        description="WLAN Authentication and Privacy Infrastructure",
    ),

    FAST_BSS_TRANSITION: ProtocolEntry(
        description="Fast BSS Transition",
    ),

    DLS: ProtocolEntry(
        description="Direct Link Setup",
    ),

    RAS: ProtocolEntry(
        description="Robust Audio Video Streaming",
    ),

    WMM: ProtocolEntry(
        description="Wi-Fi Multimedia",
    ),

    QOS_NULL: ProtocolEntry(
        description="QoS Null",
    ),
}

def get_protocol(protocol_name: str) -> ProtocolEntry | None:
    return PROTOCOLS.get(protocol_name)

def get_protocol_parser(protocol_name: str):
    protocol = get_protocol(protocol_name)
    if not protocol:
        return None
    return protocol.parser

def get_dlt(dlt: str | int) -> DltEntry | None:
    if isinstance(dlt, str):
        entry = next((v for v in DLT.values() if v.name == dlt), None)
    return DLT.get(dlt)

def get_dlt_parser(dlt: str | int):
    return get_dlt(dlt).parser
