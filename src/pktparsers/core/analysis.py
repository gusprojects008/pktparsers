from pktparsers.core.definitions.result import TRAFFIC_SUMMARY

def make_config(traffic_summary: bool = True):
    return {
        TRAFFIC_SUMMARY: traffic_summary,
    }
