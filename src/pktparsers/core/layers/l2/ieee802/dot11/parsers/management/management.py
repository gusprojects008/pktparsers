from pktparsers.common.parse.utils import (ParseContext, unpack, run_dispatch)
from pktparsers.core.layers.l2.ieee802.dot11.parsers.common import (fixed_parameters, tagged_parameters)
from pktparsers.core.layers.l2.ieee802.dot11.definitions import *

def mgmt_beacon(**kwargs) -> dict:
    fp = fixed_parameters()
    tp = tagged_parameters()
    return {
        FIXED_PARAMETERS: fp,
        TAGGED_PARAMETERS: tp
    }

def mgmt_probe_response(**kwargs) -> dict:
    fp = fixed_parameters()
    tp = tagged_parameters()
    return {
        FIXED_PARAMETERS: fp,
        TAGGED_PARAMETERS: tp
    }

def mgmt_atim(**kwargs) -> dict:
    return unpack("<H", parser=lambda v: {AID: v & 0x3FFF})

def mgmt_disassociation(**kwargs) -> dict:
    return unpack("<H", parser=lambda v: {REASON_CODE: v})

def mgmt_deauthentication(**kwargs) -> dict:
    return mgmt_disassociation()

def mgmt_authentication(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        alg, seq, status = value
        
        ctx = ParseContext.current()

        res = {
            AUTH_ALGORITHM: alg,
            AUTH_SEQUENCE: seq,
            STATUS_CODE: status,
        }

        if ctx.offset < len(ctx.frame):
            res[TAGGED_PARAMETERS] = tagged_parameters()
            
        return res

    return unpack("<HHH", parser=_parser)

def mgmt_action(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        cat, act = value
        ctx = ParseContext.current()
        
        res = {"category": cat, "action": act}
        
        remaining = len(ctx.frame) - ctx.offset
        if remaining > 0:
            res["body"] = unpack(f"{remaining}s")
        
        return res
    return unpack("BB", parser=_parser)

DISPATCH_TABLE = {
    MGMT_BEACON: mgmt_beacon,
    MGMT_PROBE_RESPONSE: mgmt_probe_response,
    MGMT_ATIM: mgmt_atim,
    MGMT_DISASSOCIATION: mgmt_disassociation,
    MGMT_DEAUTHENTICATION: mgmt_deauthentication,
    MGMT_AUTHENTICATION: mgmt_authentication,
    MGMT_ACTION: mgmt_action
}

def parser(**kwargs):
    return run_dispatch(DISPATCH_TABLE, kwargs.get("subtype"))
