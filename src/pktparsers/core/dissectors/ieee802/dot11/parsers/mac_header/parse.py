from logging import getLogger
from pktparsers.core.parsing import (unpack, read_mac)
from pkparsers.core.dissectors.ieee802.dot11.parsers.mac_header.definitions import *
from pkparsers.core.dissectors.ieee802.dot11.definitions import dot11_defs
from pktparsers.core.dissectors.ieee802.dot11.parsers.management import definitions as mgmt_defs
from pktparsers.core.dissectors.ieee802.dot11.parsers.control import definitions as ctrl_defs
from pktparsers.core.dissectors.ieee802.dot11.parsers.data import definitions as data_defs

logger = getLogger(__name__)

def parse(**kwargs) -> dict:
    logger.debug("MAC Header parse")

    def _parser(fc_val: int, **k) -> dict:
        protocol_version = fc_val & 0b11
        ftype = (fc_val >> 2) & 0b11
        fsubtype = (fc_val >> 4) & 0b1111
        to_ds = (fc_val >> 8) & 1
        from_ds = (fc_val >> 9) & 1
        protected = bool(fc_val & 0x4000)
        
        type_name = dot11_defs.FRAME_TYPES.get(ftype)
        subtype_name = dot11_defs.FRAME_SUBTYPES.get(ftype, {}).get(fsubtype)
        is_qos = ftype == dot11_defs.DATA and bool(fsubtype & 0b1000)

        duration = unpack(DURATION_FMT)
        
        addr1 = read_mac()
        
        addr2 = addr3 = addr4 = fs = qos = None

        if ftype == dot11_defs.CTRL:
            if fsubtype in (ctrl_defs.BLOCK_ACK_REQUEST, ctrl_defs.BLOCK_ACK, ctrl_defs.PS_POLL, 
                             ctrl_defs.RTS, ctrl_defs.CF_END, ctrl_defs.CF_END_ACK):
                addr2 = read_mac() 
        else:
            addr2 = read_mac() 
            addr3 = read_mac() 
            fs = unpack(FS_FMT, parser=lambda v, **k: v >> 4) # fragment number + sequence number

            if to_ds and from_ds:
                addr4 = read_mac() 

        ra = addr1
        ta = addr2 if addr2 else None
        a3 = addr3 if addr3 else None
        a4 = addr4 if addr4 else None

        sa = da = bssid = None
        if to_ds == 0 and from_ds == 0:
            sa, da, bssid = ta, ra, a3
        elif to_ds == 0 and from_ds == 1:
            sa, da, bssid = a3, ra, ta
        elif to_ds == 1 and from_ds == 0:
            sa, da, bssid = ta, a3, ra
        elif to_ds == 1 and from_ds == 1:
            sa, da, bssid = a4, a3, None

        # QoS Control
        if is_qos:
            qos = unpack(QOS_CONTROL_FMT)

        return {
            FC: {
                PROTOCOL_VERSION: protocol_version,
                TYPE: ftype,
                TYPE_NAME: type_name,
                SUBTYPE: fsubtype,
                SUBTYPE_NAME: subtype_name,
                TO_DS: to_ds,
                FROM_DS: from_ds,
                PROTECTED: protected,
            },
            DURATION_ID: duration,
            RA: ra,
            TA: ta,
            SA: sa,
            DA: da,
            BSSID: bssid,
            SEQUENCE_NUMBER: fs,
            QOS_CONTROL: qos,
        }

    result = {}

    try:
        result = unpack(FMT, parser=_parser)
    except Exception as e:
        logger.debug(f"MAC Header parser error: {e}")

    return result
