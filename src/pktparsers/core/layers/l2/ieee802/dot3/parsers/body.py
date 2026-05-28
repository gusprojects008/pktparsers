# dot3/parse.py
from logging import getLogger
from pktparsers.common.parse.utils import unpack
from pktparsers.common.parse.filter_engine import get_nested
from pktparsers.core.layers.l2.ieee802.dot3.definitions import *
from pktparsers.core.layers.l2.ieee802.dot2.parse import PAYLOAD_DISPATCH

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
