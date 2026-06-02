from logging import getLogger
from pktparsers.core.parsing import (ParseContext, insert_item, detect_fcs)
from pktparsers.core.definitions import parsing as (FCS, BODY)
from pktparsers.core.dissectors.ieee802.dot3.parsers import (ethernet_header, body)
from pktparsers.core.dissectors.ieee802.dot3.definitions import (DOT3, ETHER_HDR, FCS_LEN, VLAN_STRIPPING)

logger = getLogger(__name__)

def parse() -> dict:
    ctx = ParseContext.current()
    if ctx is None:
        raise RuntimeError("parse() called without active ParseContext")

    insert_item(ctx.result, DOT3, {})
    insert_item(ctx.result[DOT3], FCS, detect_fcs(FCS_LEN))

    if ctx.offset >= len(ctx.frame):
        logger.debug("Empty dot3 frame body")
        return ctx.result[DOT3]

    insert_item(ctx.result[DOT3], ETHER_HDR, ethernet_header.parser())
    insert_item(ctx.result[BODY], BODY, body.parser())

    return ctx.result[DOT3]

def make_config(vlan_stripping: bool = True):
    return {
        VLAN_STRIPPING: True,
    }

