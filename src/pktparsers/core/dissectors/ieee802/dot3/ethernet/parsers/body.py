# dot3/parse.py
from logging import getLogger
from pktparsers.core.parsing import unpack
from pktparsers.core.filter_engine import get_nested
from pktparsers.core.dissectors.ieee802.dot3.definitions import (DOT3, ETHER_HDR, ETHERTYPE)
from pktparsers.core.dissectors.ieee802.dot2.parse import PAYLOAD_DISPATCH

logger = getLogger(__name__)

def parse(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        ctx = ParseContext.current()
        ethertype = get_nested(f"{DOT3}.{ETHER_HDR}.{ETHERTYPE}", ctx.result)

        payload = run_dispatch(PAYLOAD_DISPATCH, ethertype, **kwargs)

        return {
            "payload": payload,
        }

    return unpack(parser=_parser)
