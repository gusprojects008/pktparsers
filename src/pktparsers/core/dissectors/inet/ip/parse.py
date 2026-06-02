import socket
from logging import getLogger
from pktparsers.common.parse.utils import unpack, ParseContext
from pktparsers.core.layers.l3.ip.definitions import *

logger = getLogger(__name__)

def ip(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        version_ihl, tos, total_length, identification, flags_frag, ttl, protocol, checksum, src, dst = value
        version = version_ihl >> 4
        ihl = version_ihl & 0x0F

        result = {
            VERSION: version,
            IHL: ihl,
            TOS: tos,
            TOTAL_LENGTH: total_length,
            IDENTIFICATION: identification,
            FLAGS: (flags_frag >> 13) & 0x7,
            FRAGMENT_OFFSET: flags_frag & 0x1FFF,
            TTL: ttl,
            PROTOCOL: protocol,
            HEADER_CHECKSUM: checksum,
            SRC: socket.inet_ntoa(src),
            DST: socket.inet_ntoa(dst),
        }

        ctx = ParseContext.current()
        payload_len = total_length - (ihl * 4)
        if payload_len > 0 and ctx.offset + payload_len <= len(ctx.frame):
            result[PAYLOAD] = unpack(f"{payload_len}s")

        return result

    return unpack(FMT, parser=_parser)
