from logging import getLogger
from pktparsers.core.layers.l2.ieee802.dot11.dlt.ieee802_11_radio.parsers.radiotap_header import parse as parse_radiotap
from pktparsers.core.layers.l2.ieee802.dot11.dlt.ieee802_11_radio.definitions import BAD_FCS, RT_HDR
from pktparsers.core.layers.l2.ieee802.dot11.parse import parse_dot11
from pktparsers.core.parsing import ParseContext, detect_fcs
from pktparsers.core.definitions import (FLAGS, SUMMARY, PARSED)
from pktparsers.core.layers.l2.ieee802.dot11.definitions import *

logger = getLogger(__name__)

def parse(frame: bytes, offset: int = 0) -> dict:
    logger.debug("Frame parse")
    result = None
    try:
        with ParseContext(frame, offset) as ctx:
            insert_item(ctx.result, RT_HDR, radiotap_header.parser())
            rt_hdr = ctx.result.get(RT_HDR)
            if not rt_hdr is None or {}:
                logger.debug("Unexpected radiotap header error")
                return ctx.result
            rt_flags = rt_hdr.get(PARSED, {}).get(FLAGS, {})
            bad_fcs = rt_flags.get(BAD_FCS)
            if bad_fcs:
                logger.debug(f"Dropping frame: {BAD_FCS} indicated by radiotap")
                return ctx.result
            parse_dot11()
            summary = summary.summarize(ctx.result)
            insert_item(ctx.result, SUMMARY, summary)
            analyzer(ctx.result, summary)
            result = ctx.result
    except Exception as e:
        logger.debug(f"Frames parser error: {e}")
    return result

def make_config(assume_fcs: bool = False, INCLUDE_RADIOTAP_RAW: bool = False):
    return {
        ASSUME_FCS: assume_fcs,
        INCLUDE_RADIOTAP_RAW: include_radiotap_raw,
    }
