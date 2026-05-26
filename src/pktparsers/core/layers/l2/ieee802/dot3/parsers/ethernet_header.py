# dot3/parse.py
from logging import getLogger
from pktparsers.common.parse.utils import unpack, read_mac
from pktparsers.core.layers.l2.ieee802.dot3.definitions import *
from pktparsers.core.layers.l3.ip.parse import parse as ip_parse
from pktparsers.core.layers.l3.arp.parse import parse as arp_parse
from pktparsers.core.layers.l2.ieee802.dot1x.parsers.eapol import parser as eapol_parse
from pktparsers.core.layers.l2.ieee802.dot2.parse import PAYLOAD_DISPATCH

logger = getLogger(__name__)

def parse(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        dst, src, ethertype = value

        payload_name = entry.get("name")
        payload_description = entry.get("description")

        return {
            "dst": dst,
            "src": src,
            "ethertype"  ethertype,
            "name": entry.get("name"),
            "description": entry.get("description"),
        }

    return unpack(f"!{MAC_ADDRESS_LENGTH}s{MAC_ADDRESS_LENGTH}sH", parser=_parser)
