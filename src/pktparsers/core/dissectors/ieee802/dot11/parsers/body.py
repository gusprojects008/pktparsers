# pktparsers/core/layers/l2/ieee802/dot11/parsers/body.py
from logging import getLogger
from pktparsers.core.parsing import ParseContext, unpack, run_dispatch
from pktparsers.core.filter_engine import get_nested
from pktparsers.core.dissectors.ieee802.dot11.parsers import management, control, data
from pktparsers.core.dissectors.ieee802.dot11.definitions import *
from pktparsers.core.dissectors.ieee802.dot11.parsers.mac_header import definitions as mac_hdr_defs
from pktparsers.core.definitions.protocol import IEEE802_11

logger = getLogger(__name__)

BODY_DISPATCH = {
    MGMT: management.parser,
    CTRL: control.parser,
    DATA: data.parser,
}

def parser(**kwargs):
    result = {}
    ctx = ParseContext.current()
    fc = get_nested(f"{IEEE802_11}.{mac_hdr_defs.MAC_HDR}.{mac_hdr_defs.FC}", ctx.result)
    logger.debug(f"{mac_hdr_defs.FC}={fc}") 
    frame_type = fc.get(mac_hdr_defs.TYPE)
    frame_subtype = fc.get(mac_hdr_defs.SUBTYPE)
    protected = fc.get(mac_hdr_defs.PROTECTED, False)
    if protected:
        return unpack()
    logger.debug(f"frametype={frame_type}") 
    try:
        result = run_dispatch(BODY_DISPATCH, frame_type, subtype=frame_subtype)
    except Exception as e:
        logger.debug(f"Body parser error: {e}")
    return result
