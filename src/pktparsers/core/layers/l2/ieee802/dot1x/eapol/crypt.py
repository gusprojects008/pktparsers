# pktparsers/core/layers/l2/ieee802/dot1x/eapol/crypt.py
#
# EAPOL-specific cryptographic operations.
#
# Responsibilities:
#   - MIC computation and verification for EAPOL Key frames
#   - Extracting nonces (ANonce, SNonce) from EAPOL Key frames to enable PTK derivation
#   - Generating hashcat 22000 (WPA-PBKDF2-PMKID+EAPOL) output for offline cracking
#
# NOT responsible for:
#   - PTK/PMK derivation (→ dot11/crypt.py)
#   - Frame decryption (→ dot11/crypt.py)
#   - Persistent credential storage (→ DissectConfig.credentials)
#
# The EAPOL analyzer calls extract_handshake_material() as Key frames arrive,
# and populates DissectConfig.credentials["dot11"][bssid]["clients"][sta] with
# the nonces needed by dot11/crypt.py for PTK derivation.

import hmac
import hashlib
import struct
import logging
from typing import Optional

from pktparsers.core.crypt import hmac_sha1, hmac_md5

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# EAPOL Key descriptor version → MIC algorithm mapping
# (IEEE 802.11-2020 Table 12-7)
# ---------------------------------------------------------------------------

_MIC_ALGO = {
    1: "hmac_md5",    # WPA (TKIP)
    2: "hmac_sha1",   # WPA2 (CCMP)
    3: "hmac_sha256", # WPA3 / AES-128-CMAC (simplified — use aes_cmac for real)
}

def compute_eapol_mic(kck: bytes, eapol_frame: bytes, descriptor_version: int) -> Optional[bytes]:
    """
    Compute MIC over an EAPOL Key frame.

    The MIC field inside the frame must be zeroed before calling this
    (use clear_mic() first).

    Args:
        kck:               16-byte Key Confirmation Key (ptk_kck(ptk))
        eapol_frame:       full EAPOL Key frame with MIC zeroed
        descriptor_version: from Key Information bits [0:3]

    Returns:
        MIC bytes (16 bytes for MD5/SHA1, 16 bytes for AES-CMAC), or None.
    """
    algo = _MIC_ALGO.get(descriptor_version)
    if algo == "hmac_md5":
        return hmac_md5(kck, eapol_frame)[:16]
    elif algo == "hmac_sha1":
        return hmac_sha1(kck, eapol_frame)[:16]
    elif algo == "hmac_sha256":
        import hmac as _hmac
        return _hmac.new(kck, eapol_frame, hashlib.sha256).digest()[:16]
    else:
        logger.debug(f"Unknown descriptor version {descriptor_version}")
        return None

def verify_eapol_mic(
    kck: bytes,
    eapol_frame: bytes,
    received_mic: bytes,
    descriptor_version: int,
) -> bool:
    """
    Verify MIC of an EAPOL Key frame.

    Args:
        kck:               Key Confirmation Key
        eapol_frame:       raw EAPOL Key frame (MIC field must be zeroed)
        received_mic:      16-byte MIC extracted from the original frame
        descriptor_version: Key Information bits [0:3]

    Returns:
        True if MIC matches.
    """
    computed = compute_eapol_mic(kck, eapol_frame, descriptor_version)
    if computed is None:
        return False
    return hmac.compare_digest(computed, received_mic[:len(computed)])

# ---------------------------------------------------------------------------
# Handshake material extraction
# ---------------------------------------------------------------------------

def extract_handshake_material(eapol_parsed: dict) -> dict:
    """
    Extract nonces and MIC from a parsed EAPOL Key frame dict (as produced
    by dot1x/eapol/parse.py).

    Returns a dict with the fields that are present:
        {
            "anonce": "hex...",    # from msg 1/4 or 3/4 (key_ack=True)
            "snonce": "hex...",    # from msg 2/4 or 4/4 (key_ack=False, mic=True)
            "mic":    "hex...",    # from msg 2/4+
            "replay_counter": int,
            "msg": 1|2|3|4,       # inferred EAPOL message number
        }

    The caller (EAPOL analyzer) is responsible for storing nonces under
    DissectConfig.credentials["dot11"][bssid]["clients"][sta].
    """
    result = {}

    ki = eapol_parsed.get("key_information", {})
    key_ack  = ki.get("key_ack", False)
    key_mic  = ki.get("key_mic", False)
    secure   = ki.get("key_secure", False)
    install  = ki.get("key_install", False)

    nonce_raw = eapol_parsed.get("key_nonce")
    mic_raw   = eapol_parsed.get("key_mic")
    replay    = eapol_parsed.get("key_replay_counter")

    if nonce_raw:
        nonce_bytes = nonce_raw if isinstance(nonce_raw, bytes) else bytes.fromhex(nonce_raw)
        if any(nonce_bytes):  # non-zero nonce
            if key_ack:
                result["anonce"] = nonce_bytes.hex()
            else:
                result["snonce"] = nonce_bytes.hex()

    if mic_raw:
        mic_bytes = mic_raw if isinstance(mic_raw, bytes) else bytes.fromhex(mic_raw)
        if any(mic_bytes):
            result["mic"] = mic_bytes.hex()

    if replay is not None:
        result["replay_counter"] = replay

    # Infer message number
    if key_ack and not key_mic:
        result["msg"] = 1
    elif key_mic and not key_ack and not secure:
        result["msg"] = 2
    elif key_ack and key_mic and secure:
        result["msg"] = 3
    elif key_mic and not key_ack and secure:
        result["msg"] = 4

    return result
