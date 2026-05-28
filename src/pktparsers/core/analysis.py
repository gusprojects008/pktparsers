from pktparsers.core.definitions.analysis import *

def make_config(traffic_summary: bool = True):
    return {
        TRAFFIC_SUMMARY: traffic_summary,
    }
