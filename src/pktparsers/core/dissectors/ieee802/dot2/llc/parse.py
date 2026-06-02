# l2/ieee802/llc/parser.py

from logging import getLogger
from pktparsers.parsing import (unpack, bytes_for_oui) 
from pktparsers.core.registry import get_protocol
from pktparsers.core.dissectors.ieee802.dot3.ethernet.definitions import ETHERTYPE_DISPATCH
from pktparsers.core.definitions.parsing import OUI_FMT
from pktparsers.core.definitions.result import (OUI, PAYLOAD, NAME, DESCRIPTION)
from pktparsers.core.dissectors.ieee802.dot2.llc.definitions import (DSAP, SSAP, CONTROL_FIELD, OUI, PID, FMT)

logger = getLogger(__name__)

def parser(**kwargs) -> dict:
    logger.debug("LLC parse")

    def _parser(value: tuple, **kwargs) -> dict:
        dsap, ssap, ctrl, oui, pid = value
        
        oui = bytes_for_oui(oui)

        pid_name = ETHERTYPE_DISPATCH.get(pid)
        entry: DissectorEntry = get_protocol(pid_name)
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

    return unpack(FMT, parser=_parser)
