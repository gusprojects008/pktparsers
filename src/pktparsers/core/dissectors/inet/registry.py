# dissectors/inet/registry.py

from pktparsers.core.definitions.entries import DissectorEntry
from pktparsers.core.definitions import dlt as dlt
from pktparsers.core.definitions import protocol as proto

DISSECTORS: dict[[int | str], DissectorEntry] = {
    dlt.DLT_RAW: DissectorEntry(...),
    proto.IP: DissectorEntry(
        description="Internet Protocol",
        layer=L3,
        parser=ip.parse,
        summarizer=ip_summary.summarizer,
        analyzer=ip_summary.analyzer,
        config=ip.definitions.config,
    ),

    proto.IPV4: DissectorEntry(
        description="Internet Protocol Version 4",
        parser=ipv4.parse,
        layer=L3,
        summarizer=ipv4_summary.summarizer,
        analyzer=ipv4_summary.analyzer,
        config=ipv4.definitions.config,
    ),

    proto.IPV6: DissectorEntry(
        layer=L3,
        description="Internet Protocol Version 6",
        parser=ipv6.parse,
        summarizer=ipv6_summary.summarizer,
        analyzer=ipv6_summary.analyzer,
        config=ipv6.definitions.config,
    ),

    proto.ICMP: DissectorEntry(
        description="Internet Control Message Protocol",
        parser=icmp.parse,
        summarizer=icmp_summary.summarizer,
        analyzer=icmp_summary.analyzer,
        config=icmp.definitions.config,
    ),

    proto.ICMPV6: DissectorEntry(
        description="Internet Control Message Protocol Version 6",
        parser=icmpv6.parse,
        summarizer=icmpv6_summary.summarizer,
        analyzer=icmpv6_summary.analyzer,
        config=icmpv6.definitions.config,
    ),

    proto.TCP: DissectorEntry(
        description="Transmission Control Protocol",
        layer=L4,
        parser=tcp.parse,
        summarizer=tcp_summary.summarizer,
        analyzer=tcp_summary.analyzer,
        config=tcp.definitions.config,
    ),

    proto.UDP: DissectorEntry(
        description="User Datagram Protocol",
        parser=udp.parse,
        layer=L4,
        summarizer=udp_summary.summarizer,
        analyzer=udp_summary.analyzer,
        config=udp.definitions.config,
    ),
}
