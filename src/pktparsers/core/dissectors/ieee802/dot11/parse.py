# pktparsers/core/layers/l2/ieee802/dot11/parse.py
from logging import getLogger
from pktparsers.core.parsing import (ParseContext, insert_item, detect_fcs)
from pktparsers.core.dissectors.ieee802.dot11.parsers import (mac_header, body)
from pktparsers.core.dissectors.ieee802.dot11.definitions import (FCS_LEN, MAC_HDR)
from pktparsers.core.definitions.protocol import IEEE802_11
from pktparsers.core.definitions.result import (BODY, FCS, SUMMARY)

logger = getLogger(__name__)

def parse() -> dict:
    ctx = ParseContext.current()
    if ctx is None:
        raise RuntimeError("parse() called without active ParseContext")

    insert_item(ctx.result, IEEE802_11, {})
    insert_item(ctx.result[IEEE802_11], FCS, detect_fcs(FCS_LEN))

    if ctx.offset >= len(ctx.buffer):
        logger.debug("Empty dot11 buffer body")
        return ctx.result[IEEE802_11]

    insert_item(ctx.result[IEEE802_11], MAC_HDR, mac_header.parser())
    insert_item(ctx.result[IEEE802_11], BODY, body.parser())

    traffic_ctx = TrafficContext.current()

    if traffic_ctx:
        summary = summarizer(ctx.result[IEEE802_11))
        insert_item(ctx.result[IEEE802_11], SUMMARY, summary)
        analyzer(ctx.result[IEEE802_11], summary)

    return ctx.result[IEEE802_11]
