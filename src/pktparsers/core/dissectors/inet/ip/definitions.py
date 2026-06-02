# pktparsers/core/layers/l3/ip/definitions.py

from pktparsers.common.parse.definitions import (IPV4_FMT)

IHL = "ihl"
TOS = "tos"
TOTAL_LENGTH = "total_length"
IDENTIFICATION = "identification"
FRAGMENT_OFFSET = "fragment_offset"
TTL = "ttl"
PROTOCOL = "protocol"
HEADER_CHECKSUM = "header_checksum"

VERSION_FMT = "B"
IHL_FMT = "B"
TOS_FMT = "B"
TOTAL_LENGTH_FMT = "H"
IDENTIFICATION_FMT = "H"
FLAGS_FRAGMENT_FMT = "H"
TTL_FMT = "B"
PROTOCOL_FMT = "B"
HEADER_CHECKSUM_FMT = "H"

FMT = (
    "!" +
    VERSION_FMT +
    IHL_FMT +
    TOS_FMT +
    TOTAL_LENGTH_FMT +
    IDENTIFICATION_FMT +
    FLAGS_FRAGMENT_FMT +
    TTL_FMT +
    PROTOCOL_FMT +
    HEADER_CHECKSUM_FMT +
    IPV4_FMT +
    IPV4_FMT
)
