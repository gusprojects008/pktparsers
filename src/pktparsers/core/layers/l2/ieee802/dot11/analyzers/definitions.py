# core/layers/l2/ieee802/dot11/analyzers/definitions.py

def make_dot11_device() -> dict:
    return {
        "role": "unknown",
        "ssids": [],
        "channels_seen": [],
        "frames_sent": 0,
        "frames_received": 0,
        "retry_count": 0,
        "relationships": {}, # {peer_mac: {"sent": int, "recv": int, "retry": int}}
        "annotations": {}
    }
