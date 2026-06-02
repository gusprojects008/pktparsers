import socket
from logging import getLogger
from pktparsers.core.parsing import unpack
from pktparsers.core.dissectors.arp.definitions import *

logger = getLogger(__name__)

def arp(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        (
            hw_type,
            proto_type,
            hw_size,
            proto_size,
            opcode,
            src_mac,
            src_ip,
            dst_mac,
            dst_ip,
        ) = value

        return {
            HW_TYPE: hw_type,
            PROTOCOL_TYPE: proto_type,
            HW_SIZE: hw_size,
            PROTOCOL_SIZE: proto_size,
            OPCODE: opcode,
            SRC_MAC: src_mac,
            SRC_IP: socket.inet_ntoa(src_ip),
            DST_MAC: dst_mac,
            DST_IP: socket.inet_ntoa(dst_ip),
        }

    return unpack(FMT, parser=_parser)
