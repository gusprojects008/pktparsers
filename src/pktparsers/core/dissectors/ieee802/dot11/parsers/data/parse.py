from logging import getLogger
from core.dissectors.ieee802.dot2.llc.parse import parse as llc_parse
from core.dissectors.ieee802.dot2.llc import definitions as llc_defs
from core.dissectors.ieee802.dot11.mac_header import definitions as mac_hdr_defs
from core.dissectors.ieee802.dot11.parsers.data import definitions as data_defs

logger = getLogger(__name__)

def parser(**kwargs) -> dict:
    subtype = kwargs.get(mac_hdr_defs.SUBTYPE)
    logger.debug(f"DATA Parser - Subtype: {subtype}")
    
    body = {}

    if subtype in data_defs.NULL_DATA_SUBTYPES:
        logger.debug("Null Data frame detected: skipping LLC parser")
        return body
    
    try:
        body[llc_defs.LLC] = llc_parser()
    except Exception as e:
        logger.warning(f"Could not parse LLC on data frame: {e}")
    
    return body
