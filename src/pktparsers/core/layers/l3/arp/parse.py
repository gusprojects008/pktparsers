# l3/parsers/parsers.py — versão correta
import socket
from logging import getLogger
from pktparsers.common.parse.utils import unpack

logger = getLogger(__name__)

def arp(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        hw_type, proto_type, hw_size, proto_size, opcode, src_mac, src_ip, dst_mac, dst_ip = value
        return {
            "hw_type":       hw_type,
            "protocol_type": proto_type,
            "hw_size":       hw_size,
            "protocol_size": proto_size,
            "opcode":        opcode,
            "src_mac":       src_mac,
            "src_ip":        socket.inet_ntoa(src_ip),
            "dst_mac":       dst_mac,
            "dst_ip":        socket.inet_ntoa(dst_ip),
        }
    return unpack("!HHBBH6s4s6s4s", parser=_parser)

