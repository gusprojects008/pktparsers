from logging import getLogger
from pktparsers.layers.l2.ieee802.dot11.radio.radiotap_header.parse import parse_radiotap
from pktparsers.layers.l2.ieee802.dot11.parse import parse_dot11
from core.common.parser import (ParseContext, detect_fcs)
from core.layers.l2.ieee802.dot11.constants import *

logger = getLogger(__name__)

def parse(frame: bytes, offset: int = 0) -> dict:
    logger.debug("Frame parse")
    try:
        with ParseContext(frame, offset) as ctx:
            insert_item(ctx.result, "rt_hdr", radiotap_header.parser())
            rt_hdr = ctx.result.get("rt_hdr")
            if rt_hdr is None or {}:
                logger.debug("Unexpected radiotap header error")
                return ctx.result
            rt_flags = rt_hdr.get("parsed", {}).get("flags", {})
            bad_fcs = rt_flags.get("bad_fcs")
            if bad_fcs:
                logger.debug("Dropping frame: bad_fcs indicated by radiotap")
                return ctx.result
            ctx.result.update(parse_dot11(ctx.frame, ctx.offset))
            insert_item(ctx.result, "summary", ctx.summary)
            dissection_ctx = DissectContext.current()
            if dissection_ctx:
                dissection_ctx.add_summary("dot11", ctx.summary)
    except Exception as e:
        logger.debug(f"Frames parser error: {e}")
    return ctx.result
