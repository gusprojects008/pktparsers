from pktparsers.core.dissectors.ieee802.dot11.parsers.management import definitions as mgmt_defs
from pktparsers.core.dissectors.ieee802.dot11.parsers.control import definitions as ctrl_defs
from pktparsers.core.dissectors.ieee802.dot11.parsers.data import definitions as data_defs

FCS_LEN = 4

MGMT = 0
CTRL = 1
DATA = 2

FRAME_TYPES = {
    MGMT: "Management",
    CTRL: "Control",
    DATA: "Data",
}

FRAME_SUBTYPES = {
    MGMT: mgmt_defs.SUBTYPES,
    CTRL: ctrl_defs.SUBTYPES,
    DATA: data_defs.SUBTYPES
}

RSN_CIPHER_WEP40 = 1
RSN_CIPHER_TKIP = 2
RSN_CIPHER_CCMP = 4
RSN_CIPHER_WEP104 = 5
RSN_CIPHER_GCMP = 8
RSN_CIPHER_GCMP_256 = 9
RSN_CIPHER_CCMP_256 = 10
RSN_CIPHER_BIP_GMAC_128 = 11
RSN_CIPHER_BIP_GMAC_256 = 12
RSN_CIPHER_BIP_CMAC_256 = 13
RSN_AKM_8021X = 1
RSN_AKM_PSK = 2
RSN_AKM_FT_8021X = 3
RSN_AKM_FT_PSK = 4
RSN_AKM_8021X_SHA256 = 5
RSN_AKM_PSK_SHA256 = 6
RSN_AKM_TDLS = 7
RSN_AKM_SAE = 8
RSN_AKM_FT_SAE = 9
RSN_AKM_AP_PEERKEY = 10
RSN_AKM_SUITE_B_8021X = 11
RSN_AKM_SUITE_B_192_8021X = 12
RSN_AKM_FILS_SHA256 = 14
RSN_AKM_FILS_SHA384 = 15
RSN_AKM_OWE = 18

RSN_MIN_LEN = 2
RSN_GROUP_CIPHER_LEN = 4
RSN_SUITE_LEN = 4
