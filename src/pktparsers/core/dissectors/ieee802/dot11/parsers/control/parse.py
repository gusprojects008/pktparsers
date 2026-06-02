from core.core.parsing import (unpack, run_dispatch)
from core.dissectors.ieee802.dot11.parsers.control import definitions as ctrl_defs
from core.dissectors.ieee802.dot11.parsers.mac_hdr import definitions as mac_hdr_defs

def ctrl_block_ack_request(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        ctrl, start_seq = value
        return {
            ctrl_defs.BLOCK_ACK_CTRL: ctrl,
            ctrl_defs.BLOCK_ACK_START_SEQ: start_seq
        }
    return unpack("<HH", parser=_parser)

def ctrl_block_ack(**kwargs) -> dict:
    return unpack("<Q", parser=lambda v: {ctrl_defs.BLOCK_ACK_BITMAP: v})

def ctrl_ps_poll(**kwargs) -> dict:
    return unpack("<H", parser=lambda v: {ctrl_defs.AID: v & 0x3FFF})

def ctrl_ack(**kwargs) -> dict:
    return unpack()

def ctrl_cf_end(**kwargs) -> dict:
    return unpack()

def ctrl_cf_end_ack(**kwargs) -> dict:
    return unpack()

DISPATCH_TABLE = {
    ctrl_defs.BLOCK_ACK_REQUEST: ctrl_block_ack_request,
    ctrl_defs.BLOCK_ACK: ctrl_block_ack,
    ctrl_defs.PS_POLL: ctrl_ps_poll,
    ctrl_defs.ACK: ctrl_ack,
    ctrl_defs.CF_END: ctrl_cf_end,
    ctrl_defs.CF_END_ACK: ctrl_cf_end_ack,
}

def parser(**kwargs):
    return run_dispatch(DISPATCH_TABLE, kwargs.get(mac_hdr_defs.SUBTYPE))
