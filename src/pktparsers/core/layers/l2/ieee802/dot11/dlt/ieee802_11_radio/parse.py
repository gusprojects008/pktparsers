from logging import getLogger
from pktparsers.core.layers.l2.ieee802.dot11.dlt.ieee802_11_radio.definitions import BAD_FCS, RT_HDR
from pktparsers.core.layers.l2.ieee802.dot11.parse import parse_dot11
from pktparsers.core.definitions import (FLAGS, SUMMARY, PARSED)
from pktparsers.core.layers.l2.ieee802.dot11.definitions import *

logger = getLogger(__name__)

def parse() -> dict:
    logger.debug("Frame parse")
    ctx = ParseContext.current()
    insert_item(ctx.result, RT_HDR, radiotap_header.parser())
    rt_hdr = ctx.result.get(RT_HDR)
    if not rt_hdr:
        logger.debug("Unexpected radiotap header error")
        return ctx.result
    rt_flags = rt_hdr.get(PARSED, {}).get(FLAGS, {})
    bad_fcs = rt_flags.get(BAD_FCS)
    if bad_fcs:
        logger.debug(f"Dropping frame: {BAD_FCS} indicated by radiotap")
        return ctx.result
    parse_dot11()
    if traffic_ctx:
        summary = summarizer(ctx.result[RT_HDR))
        insert_item(ctx.result[RT_HDR], SUMMARY, summary)
        analyzer(ctx.result[RT_HDR], summary)
    return ctx.result

def make_config(assume_fcs: bool = False, include_radiotap_raw: bool = False):
    return {
        ASSUME_FCS: assume_fcs,
        INCLUDE_RADIOTAP_RAW: include_radiotap_raw,
    }
