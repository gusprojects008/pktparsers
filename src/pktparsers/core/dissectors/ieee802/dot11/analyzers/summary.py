# dot11/analyzers/summary.py

from pktparsers.core.definitions.protocol import IEEE802_11
from pktparsers.core.definitions.analysis import  (RELATIONSHIPS, ANNOTATIONS)
from pktparsers.core.dissectors.ieee802.dot11.analyzers.definitions import (ROLE, SSIDS, CHANNELS_SEEN, FRAMES_SENT, FRAMES_RECEIVED, RETRY_COUNT)

def make_dot11_device(role: str = UNKNOWN, ) -> dict: # precisa receber os argumentos para montar o dict
    return {
        ROLE: role,
        SSIDS: [],
        CHANNELS_SEEN: [],
        FRAMES_SENT: 0,
        FRAMES_RECEIVED: 0,
        RETRY_COUNT: 0,
        RELATIONSHIPS: {}, # {peer_mac: {"sent": int, "recv": int, "retry": int}}
        ANNOTATIONS: {}
    }

def summarizer(parsed: dict): # dot11 parse result dict
    summary = {} 
    pass

def analyzer(parsed: dict, summary: dict):
    dot11_device = {}
    dot11_device_annotations = {}
    traffic_ctx = TrafficContext.current()
    traffic_summary = traffic_ctx.summary
    summary = summary or dot11.get(SUMMARY)
    pass
