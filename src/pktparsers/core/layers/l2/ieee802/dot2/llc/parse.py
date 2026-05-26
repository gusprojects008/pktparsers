# l2/ieee802/llc/parser.py

from logging import getLogger
from pktparsers.common.parse.utils import (unpack, run_dispatch, bytes_for_oui) 
from pktparsers.core.registry import get_protocol
from pktparsers.core.layers.l2 import (OUI, OUI_FMT)
from pktparsers.core.layers.l2.ieee802.definitions import ETHERTYPE_DISPATCH
from pktparsers.core.layers.l2.ieee802.dot2.llc.definitions import *

logger = getLogger(__name__)

def parser(**kwargs) -> dict:
    logger.debug(f"LLC parse")

    def _parser(value: tuple, **kwargs) -> dict:
        dsap, ssap, ctrl, oui, pid = value
        
        oui = bytes_for_oui(oui)

        pid_name = ETHERTYPE_DISPATCH.get(pid)
        entry: ProtocolEntry = get_protocol(pid_name)
        pid_desc = entry.description

        payload = entry.parser(**kwargs)
        
        result = {
            DSAP: dsap,
            SSAP: ssap,
            CONTROL_FIELD: ctrl,
            OUI: oui,
            PID: pid,
            NAME: pid_name,
            DESCRIPTION: pid_desc,
            PAYLOAD: payload
        }
        
        return result

    fmt = f"!{DSAP_FMT}{SSAP_FMT}{CONTROL_FMT}{OUI_FMT}{PID_FMT}"
    return unpack(fmt, parser=_parser)
