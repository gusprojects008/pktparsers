# core/layers/l2/ieee802/definitions.py

from pktparsers.core.layers.l2.ieee802.dot3.definitions import *
from pktparsers.core.definitions import *

ASSUME_FCS = "assume_fcs"

ETHERTYPE_DISPATCH = {
    ETHERTYPE_IPV4: IPV4,
    ETHERTYPE_ARP: ARP,
    ETHERTYPE_IPV6: IPV6,
    ETHERTYPE_EAPOL: EAPOL,
    ETHERTYPE_MESH_CTRL: MESH_CTRL,
    ETHERTYPE_TDLS: TDLS,
    ETHERTYPE_WAPI: WAPI,
    ETHERTYPE_FAST_BSS_TRANSITION: FAST_BSS_TRANSITION,
    ETHERTYPE_DLS: DLS,
    ETHERTYPE_RAS: RAS,
    ETHERTYPE_WMM: WMM,
    ETHERTYPE_QOS_NULL: QOS_NULL,
}
