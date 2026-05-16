from logging import getLogger
from core.common.parser import (ParseContext, detect_fcs)
from core.layers.l2.ieee802.dot11.parsers import (mac_header, body)
from core.layers.l2.ieee802.dot11.constants import *

logger = getLogger(__name__)

def parse(frame: bytes, offset: int = 0) -> dict:
    logger.debug("Frame parse")
    try:
        with ParseContext(frame, offset) as ctx:
            insert_item(ctx.result, "fcs", detect_fcs())
            if ctx.offset >= len(ctx.frame):
                logger.debug("Empty 802.11 frame after radiotap, skipping")
                return ctx.result
            insert_item(ctx.result, "mac_hdr", mac_header.parser())
            insert_item(ctx.result, "body", body.parser())
            """
            summary = summarizer_dot11(ctx.result) # não vai ser necessário pois summary foi gerado dinâmicamente por subparsers.
            ctx.set("summary", summary)
            dissection_ctx = DissectContext.current()
            if dissection_ctx:
                dissection_ctx.add_summary("dot11", summary)
            """
            ctx.set("summary", ctx.summary)
            dissection_ctx = DissectContext.current()
            if dissection_ctx:
                dissection_ctx.add_summary("dot11", ctx.summary)
    except Exception as e:
        logger.debug(f"Frames parser error: {e}")
    return ctx.result
