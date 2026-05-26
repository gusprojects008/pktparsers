# pktparsers/core/layers/l2/ieee802/dot11/parse.py
from logging import getLogger
from pktparsers.common.parse.utils import (ParseContext, insert_item, detect_fcs)
from pktparsers.core.layers.l2.ieee802.dot11.parsers import (mac_header, body)
from pktparsers.core.layers.l2.ieee802.dot11.definitions import *

logger = getLogger(__name__)

def parse() -> dict:
    ctx = ParseContext.current()
    if ctx is None:
        raise RuntimeError("parse() called without active ParseContext")

    insert_item(ctx.result, DOT11, {})
    insert_item(ctx.result[DOT11], FCS, detect_fcs(FCS_LEN))

    if ctx.offset >= len(ctx.buffer):
        logger.debug("Empty dot11 buffer body")
        return ctx.result[DOT11]

    insert_item(ctx.result[DOT11], MAC_HDR, mac_header.parser())
    insert_item(ctx.result[BODY], BODY, body.parser())

    return ctx.result[DOT11]
