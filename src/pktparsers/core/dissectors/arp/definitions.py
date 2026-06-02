from pktparsers.common.parse.definitions import (
    EUI48_FMT,
    IPV4_FMT,
)

HW_TYPE = "hw_type"
PROTOCOL_TYPE = "protocol_type"
HW_SIZE = "hw_size"
PROTOCOL_SIZE = "protocol_size"
OPCODE = "opcode"
SRC_MAC = "src_mac"
SRC_IP = "src_ip"
DST_MAC = "dst_mac"
DST_IP = "dst_ip"

HW_TYPE_FMT = "H"
PROTOCOL_TYPE_FMT = "H"
HW_SIZE_FMT = "B"
PROTOCOL_SIZE_FMT = "B"
OPCODE_FMT = "H"

FMT = (
    "!" +
    HW_TYPE_FMT +
    PROTOCOL_TYPE_FMT +
    HW_SIZE_FMT +
    PROTOCOL_SIZE_FMT +
    OPCODE_FMT +
    EUI48_FMT +
    IPV4_FMT +
    EUI48_FMT +
    IPV4_FMT
)
