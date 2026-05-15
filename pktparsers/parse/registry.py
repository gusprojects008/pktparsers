from pktparsers.layers import l2 import parse, parse_radio
from pktparsers.common.constants.parsers import *

DLT_DISPATCH = {
    "DLT_EN10MB": {
        "value": DLT_EN10MB,
        "parser": None
    },
    "DLT_IEEE802_11": {
        "value": DLT_IEEE802_11,
        "parser": l2.ieee802.dot11.parse
    },
    "DLT_IEEE802_11_RADIO": {
        "value": DLT_IEEE802_11_RADIO,
        "parser": l2.ieee802.dot11.radio.parse
    },
    "DLT_RAW": {
        "value": DLT_RAW,
        "parser": l3.parse("ip")
    },
    "DLT_BLUETOOTH_HCI_H4": {
        "value": DLT_BLUETOOTH_HCI_H4,
        "parser": None. 
    },
    "DLT_BLUETOOTH_HCI_H4_PHDR": {
        "value": DLT_BLUETOOTH_HCI_H4_PHDR,
        "parser": None
    }
}

def get_parser(dlt: str | int):
    config = DLT_DISPATCH.get(dlt if isinstance(str, dlt) else next((k for k, v in DLT_DISPATCH.items()) if v.get("value") == dlt))
    if not config or not config["parser"]:
        raise ValueError(f"Parser not available or not implemented for: {dlt_name}")
    return config["parser"]

def get_dlt_value(dlt_name: str):
    config = DLT_DISPATCH.get(dlt_name)
    if not config:
        raise ValueError(f"Unknown DLT: {dlt_name}")
    return config["value"]

def list_supported_dlts():
    return [k for k, v in DLT_DISPATCH.items() if v["parser"] is not None]
