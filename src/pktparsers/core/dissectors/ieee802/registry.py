from pktparsers.core.definitions import dlt as dlt
from pktparsers.core.definitions import protocol as proto
from pktparsers.core.definitions.entries import (DissectorEntry, L2, L3)

DLT = {
    dlt.DLT_IEEE802_11_RADIO: DissectorEntry(
        name="DLT_IEEE802_11_RADIO",
        parser=dot11_radio.parse,
        layer=L2,
        summarizer=dot11_radio.analyzers.summary.summarizer,
        analyzer=dot11_radio.analyzers.summary.analyzer,
        config=dot11_radio.definitions.config,
    ),

    dlt.DLT_IEEE802_11: DissectorEntry(
        name="DLT_IEEE802_11",
        parser=dot11.parse,
        layer=L2,
        summarizer=dot11_summary.summarizer,
        analyzer=dot11_summary.analyzer,
        config=dot11.definitions.config,
    ),

    dlt.DLT_EN10MB: DissectorEntry(
        name="DLT_EN10MB",
        parser=dot3.parse,
        layer=L2,
        summarizer=dot3_summary.summarizer,
        analyzer=dot3_summary.analyzer,
        config=dot3.definitions.config,
    ),
}

PROTOCOL = {
    proto.IEEE802_11: DissectorEntry(
        description="IEEE 802.11",
        parser=dot11.parse,
        layer=L2,
        summarizer=dot11_summary.summarizer,
        analyzer=dot11_summary.analyzer,
        config=dot11.definitions.config,
    ),

    proto.IEEE802_3: DissectorEntry(
        description="IEEE 802.3 Ethernet",
        parser=dot3.parse,
        layer=L2,
        summarizer=dot3_summary.summarizer,
        analyzer=dot3_summary.analyzer,
        config=dot3.definitions.config,
    ),

    proto.IEEE802_1X: DissectorEntry(
        layer=L2,
        description="IEEE 802.1X",
        config=dot1x.definitions.config,
    ),

    proto.IEEE802_LLC: DissectorEntry(
        layer=L2,
        description="Logical Link Control",
        parser=llc.parse,
        summarizer=llc_summary.summarizer,
        analyzer=llc_summary.analyzer,
        config=llc.definitions.config,
    ),

    proto.IEEE802_EAPOL: DissectorEntry(
        description="EAP over LAN",
        layer=L2,
        parser=eapol.parse,
        summarizer=eapol_summary.summarizer,
        analyzer=eapol_summary.analyzer,
        config=eapol.definitions.config,
    ),

    proto.IEEE802_EAP: DissectorEntry(
        description="Extensible Authentication Protocol",
        layer=L2,
        parser=eap.parse,
        summarizer=eap_summary.summarizer,
        analyzer=eap_summary.analyzer,
        config=eap.definitions.config,
    ),

    proto.IEEE802_RADIUS: DissectorEntry(
        description="Remote Authentication Dial-In User Service",
        parser=radius.parse,
        summarizer=radius_summary.summarizer,
        analyzer=radius_summary.analyzer,
        layer=L2,
        config=radius.definitions.config,
    ),
}
