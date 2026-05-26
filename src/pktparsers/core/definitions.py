# pktparsers/common/parse/defintions.py

# Contains dataclasses or global constants of the project, used by parsing functions or related to parsing. Constants such as: names of keys from parser result dictionaries.
# Stores standard struct formats and generic key constants used by parsers.

from dataclasses import dataclass

DLT_EN10MB = 1
DLT_ATM_RFC1483 = 11
DLT_RAW = 12
DLT_HDLC = 104
DLT_IEEE802_11_RADIO = 127
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_BLUETOOTH_HCI_H4 = 187
DLT_BLUETOOTH_HCI_H4_PHDR = 201

ERF_TYPE_LEGACY  = 0
ERF_TYPE_HDLC_POS = 2
ERF_TYPE_ETH = 3
ERF_TYPE_ATM = 4
ERF_TYPE_AAL5 = 5
ERF_TYPE_MC_HDLC = 7
ERF_TYPE_MC_RAW = 8
ERF_TYPE_MC_ATM = 9
ERF_TYPE_MC_AAL5 = 10
ERF_TYPE_COLOR_HDLC_POS = 16
ERF_TYPE_COLOR_ETH = 17
ERF_TYPE_MC_AAL2 = 19
ERF_TYPE_IP_COUNTER = 20
ERF_TYPE_IPV4 = 21
ERF_TYPE_IPV6 = 22
ERF_TYPE_RESERVED_23 = 23
ERF_TYPE_RAW_LINK = 24
ERF_TYPE_INFINIBAND = 25
ERF_TYPE_IPC = 26
ERF_TYPE_TUNNEL_IP = 27
ERF_TYPE_CLASSIFICATION = 28
ERF_TYPE_PASSIVE_CONTAINER = 29
ERF_TYPE_ETHERNET_SGMII = 30
ERF_TYPE_PROVENANCE = 31
ERF_TYPE_FIBRE_CHANNEL = 32
ERF_TYPE_I2C = 33
ERF_TYPE_LORA = 34
ERF_TYPE_COEX = 35
ERF_TYPE_GENERIC_METADATA = 36
ERF_TYPE_UTMI = 37
ERF_TYPE_MISC_METADATA = 38
ERF_TYPE_AAL5_INTERLEAVE = 39
ERF_TYPE_P2P_DECAP = 40
ERF_TYPE_EPON_ONU = 41
ERF_TYPE_EPON_OLT = 42
ERF_TYPE_EMULATED_CHANNEL = 43
ERF_EXTENSION_MASK = 0x80

ERF_TYPE_TO_DLT = {
    ERF_TYPE_HDLC_POS: DLT_HDLC,
    ERF_TYPE_ETH: DLT_EN10MB,
    ERF_TYPE_ATM: DLT_ATM_RFC1483,
    ERF_TYPE_AAL5: DLT_ATM_RFC1483,
    ERF_TYPE_MC_HDLC: DLT_HDLC,
    ERF_TYPE_MC_RAW: DLT_RAW,
    ERF_TYPE_MC_ATM: DLT_ATM_RFC1483,
    ERF_TYPE_MC_AAL5: DLT_ATM_RFC1483,
    ERF_TYPE_COLOR_HDLC_POS: DLT_HDLC,
    ERF_TYPE_COLOR_ETH: DLT_EN10MB,
    ERF_TYPE_IPV4: DLT_IPV4,
    ERF_TYPE_IPV6: DLT_IPV6,
    ERF_TYPE_RAW_LINK: DLT_RAW,
    ERF_TYPE_TUNNEL_IP: DLT_RAW,
    ERF_TYPE_ETHERNET_SGMII: DLT_EN10MB,
}

EUI48_FMT = "6s"
EUI64_FMT = "8s"
OUI_FMT = "3s"
IPV4_FMT = "4s"
IPV6_FMT = "16s"

PARSED = "parsed"
COUNTER = "counter"
SUMMARY = "summary"
VALUE = "value"
METADATA = "_metadata_"
RAW = "raw"
TOKENS = "tokens"
OUI = "oui"
MAC = "mac"
NAME = "name"
DESCRIPTION = "description"
PAYLOAD = "payload"
VENDOR = "vendor"
ADDRESS = "addr"
SOURCE = "src"
DESTINATION = "dst"
FLAGS = "flags"
VERSION = "version"

L2 = "l2"
L3 = "l3"
L4 = "l4"
L7 = "l7"

DEVICES = "devices"
ANNOTATIONS = "annotations"
RELATIONSHIPS = "relationships"

IEEE802_11 = "ieee802_11"
IEEE802_3 = "ieee802_3"
IEEE802_1X = "ieee802_1x"
ARP = "arp"
IP = "ip"
IPV4 = "ipv4"
IPV6 = "ipv6"
ICMP = "icmp"
ICMPV6 = "icmpv6"
TCP = "tcp"
UDP = "udp"
LLC = "llc"
SNAP = "snap"
EAPOL = "eapol"
EAP = "eap"
RADIUS = "radius"
MESH_CTRL = "mesh_ctrl"
TDLS = "tdls"
WAPI = "wapi"
FAST_BSS_TRANSITION = "fast_bss_transition"
DLS = "dls"
RAS = "robust_av_streaming"
WMM = "wmm"
QOS_NULL = "qos_null"
TLS = "tls"
IPSEC = "ipsec"
