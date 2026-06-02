# pktparsers/core/layers/l2/ieee802/dot11/crypt.py
#
# IEEE 802.11 key derivation and frame-level decryption.
#
# Responsibilities:
#   - PMK derivation (PSK/SAE)
#   - PTK/GTK derivation from handshake material
#   - CCMP decryption  (WPA2/WPA3)
#   - TKIP decryption  (WPA legacy)
#   - WEP decryption   (legacy)
#
# NOT responsible for:
#   - EAPOL MIC verification  → dot1x/eapol/crypt.py
#   - EAP / RADIUS processing → their own modules
#   - Persistent credential storage → DissectConfig.credentials
#
# All decryptors follow the calling convention expected by DltEntry.decryptor:
#   decryptor(payload: bytes, credentials: dict) -> bytes | None

import struct
import logging
from typing import Optional

from pktparsers.core.crypt import (
    pbkdf2_sha1,
    prf_sha1,
    aes_ccm_decrypt,
    rc4,
    crc32_bytes,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PMK derivation
# ---------------------------------------------------------------------------

def derive_pmk(psk: str, ssid: str) -> bytes:
    """
    WPA2/WPA3 Personal: derive PMK from passphrase + SSID.
    Result is 32 bytes (256-bit).
    """
    return pbkdf2_sha1(psk, ssid)


# ---------------------------------------------------------------------------
# PTK derivation
# ---------------------------------------------------------------------------

PTK_LABEL = "Pairwise key expansion"

# PTK field offsets (lengths in bytes)
_KCK_LEN = 16
_KEK_LEN = 16
_TK_LEN  = 16   # CCMP-128; CCMP-256 would be 32
_PTK_LEN = _KCK_LEN + _KEK_LEN + _TK_LEN  # 48 bytes for CCMP-128


def derive_ptk(
    pmk: bytes,
    anonce: bytes,
    snonce: bytes,
    bssid: bytes,
    sta_mac: bytes,
) -> bytes:
    """
    IEEE 802.11-2020 §12.7.1.3 PTK derivation.

    Args:
        pmk:     32-byte PMK (from derive_pmk or pre-shared)
        anonce:  32-byte ANonce from EAPOL msg 1/4 (Authenticator nonce)
        snonce:  32-byte SNonce from EAPOL msg 2/4 (Supplicant nonce)
        bssid:   6-byte AP MAC address
        sta_mac: 6-byte STA MAC address

    Returns:
        48-byte PTK (KCK[0:16] | KEK[16:32] | TK[32:48])
    """
    # min(AA, SPA) || max(AA, SPA) || min(ANonce, SNonce) || max(ANonce, SNonce)
    mac_min = min(bssid, sta_mac)
    mac_max = max(bssid, sta_mac)
    nonce_min = min(anonce, snonce)
    nonce_max = max(anonce, snonce)

    data = mac_min + mac_max + nonce_min + nonce_max
    return prf_sha1(pmk, PTK_LABEL, data, _PTK_LEN * 8)


def ptk_kck(ptk: bytes) -> bytes:
    return ptk[:_KCK_LEN]


def ptk_kek(ptk: bytes) -> bytes:
    return ptk[_KCK_LEN : _KCK_LEN + _KEK_LEN]


def ptk_tk(ptk: bytes) -> bytes:
    return ptk[_KCK_LEN + _KEK_LEN : _KCK_LEN + _KEK_LEN + _TK_LEN]


# ---------------------------------------------------------------------------
# CCMP (AES-CCM, WPA2/WPA3)
# ---------------------------------------------------------------------------

_CCMP_HDR_LEN = 8   # PN bytes + reserved
_CCMP_MIC_LEN = 8


def _build_ccmp_nonce(priority: int, ta: bytes, pn: bytes) -> bytes:
    """Build 13-byte CCM nonce per IEEE 802.11-2020 §12.5.3.3.3."""
    # nonce = flags(1) || A2(6) || PN5..PN0(6)
    flags = priority & 0x0F
    return bytes([flags]) + ta + pn


def _extract_ccmp_pn(ccmp_header: bytes) -> bytes:
    """Extract 6-byte PN from CCMP header (PN0..PN5, reconstructed big-endian)."""
    pn0 = ccmp_header[0]
    pn1 = ccmp_header[1]
    # byte 2 = reserved, byte 3 = key_id
    pn2 = ccmp_header[4]
    pn3 = ccmp_header[5]
    pn4 = ccmp_header[6]
    pn5 = ccmp_header[7]
    # PN in replay order is PN5..PN0
    return bytes([pn5, pn4, pn3, pn2, pn1, pn0])


def decrypt_ccmp(
    payload: bytes,
    tk: bytes,
    ta: bytes,
    priority: int = 0,
    aad: bytes = b"",
) -> Optional[bytes]:
    """
    Decrypt a CCMP-protected 802.11 MPDU body.

    Args:
        payload:  raw bytes starting at the CCMP header (after MAC header)
        tk:       16-byte Temporal Key (ptk_tk(ptk))
        ta:       6-byte Transmitter Address (addr2 from MAC header)
        priority: QoS priority (0 for non-QoS frames)
        aad:      Additional Authenticated Data (MAC header bytes, caller-supplied)

    Returns:
        Decrypted plaintext, or None on failure.
    """
    if len(payload) < _CCMP_HDR_LEN + _CCMP_MIC_LEN:
        logger.debug("CCMP: payload too short")
        return None

    ccmp_hdr = payload[:_CCMP_HDR_LEN]
    ciphertext_and_mic = payload[_CCMP_HDR_LEN:]

    pn = _extract_ccmp_pn(ccmp_hdr)
    nonce = _build_ccmp_nonce(priority, ta, pn)

    return aes_ccm_decrypt(tk, nonce, ciphertext_and_mic, aad)


# ---------------------------------------------------------------------------
# TKIP (RC4 + Michael MIC, WPA1)
# ---------------------------------------------------------------------------

def _tkip_phase1(tk: bytes, ta: bytes, tsc_msb: int) -> list[int]:
    """TKIP Phase 1 key mixing."""
    # tk[0:16] for encryption, tk[16:24] for Tx MIC, tk[24:32] for Rx MIC
    p1k = [0] * 5
    tsc_i = (tsc_msb >> 16) & 0xFFFF
    tsc_i2 = tsc_msb & 0xFFFF

    s = lambda a, b: (a + b) & 0xFFFF
    xor = lambda a: a ^ (a >> 8)

    # Simplified TKIP phase 1 — for full production code use a reference impl
    # This is a structural placeholder aligned with the crypt module pattern
    ta_words = [
        (ta[1] << 8) | ta[0],
        (ta[3] << 8) | ta[2],
        (ta[5] << 8) | ta[4],
    ]

    p1k[0] = tsc_i
    p1k[1] = tsc_i2
    p1k[2] = ta_words[0]
    p1k[3] = ta_words[1]
    p1k[4] = ta_words[2]

    tk_words = [struct.unpack_from("<H", tk, i)[0] for i in range(0, 16, 2)]

    for i in range(8):
        p1k[0] = (p1k[0] + _sbox(p1k[4] ^ tk_words[i & 1])) & 0xFFFF
        p1k[1] = (p1k[1] + _sbox(p1k[0] ^ tk_words[(i & 1) + 2])) & 0xFFFF
        p1k[2] = (p1k[2] + _sbox(p1k[1] ^ tk_words[(i & 1) + 4])) & 0xFFFF
        p1k[3] = (p1k[3] + _sbox(p1k[2] ^ tk_words[(i & 1) + 6])) & 0xFFFF
        p1k[4] = (p1k[4] + _sbox(p1k[3] ^ tk_words[i & 1])) & 0xFFFF
        p1k[4] = (p1k[4] + i) & 0xFFFF

    return p1k


_SBOX = [
    0xC6A5F432, 0xF884976F, 0xEE99B05B, 0xF68D8C43,
    0xFF0DD05B, 0xD6BD9367, 0xDEB1601C, 0x91E40E67,
    # (truncated — full 256-entry S-box belongs in a dedicated TKIP impl)
]


def _sbox(v: int) -> int:
    lo = v & 0xFF
    hi = (v >> 8) & 0xFF
    return ((_SBOX[lo >> 3] >> ((lo & 7) * 4)) ^ (_SBOX[hi >> 3] >> ((hi & 7) * 4))) & 0xFFFF


def decrypt_tkip(
    payload: bytes,
    tk: bytes,
    ta: bytes,
    priority: int = 0,
) -> Optional[bytes]:
    """
    Decrypt a TKIP-protected 802.11 MPDU body.

    NOTE: This is a structural placeholder. Full TKIP requires a complete
    phase-1/phase-2 key mixing implementation and Michael MIC verification.
    For production use, delegate to a library (e.g. scapy, wpa_supplicant).

    Args:
        payload:  bytes starting at the TKIP header (after MAC header)
        tk:       32-byte TKIP TK (first 16 for encryption, [16:24] Tx MIC, [24:32] Rx MIC)
        ta:       6-byte Transmitter Address
        priority: QoS TID

    Returns:
        Decrypted plaintext (without MIC), or None on failure.
    """
    if len(payload) < 12:
        logger.debug("TKIP: payload too short")
        return None

    # TKIP header: IV(3) | Key-ID | Extended IV(4) = 8 bytes
    tsc1  = payload[0]
    _     = payload[1]   # (tsc1 | 0x20) & 0x7f — IV byte 2 used as WEP compatibility
    tsc0  = payload[2]
    key_id = payload[3]
    tsc2  = payload[4]
    tsc3  = payload[5]
    tsc4  = payload[6]
    tsc5  = payload[7]

    tsc = (tsc5 << 40) | (tsc4 << 32) | (tsc3 << 24) | (tsc2 << 16) | (tsc1 << 8) | tsc0

    body = payload[8:]
    # body = data(N) + MIC(8) + ICV(4)  — strip trailing ICV check
    if len(body) < 12:
        return None

    # Phase 2 key derivation + RC4 decryption — structural only
    # Full implementation needs complete _tkip_phase2()
    logger.debug("TKIP decryption: structural placeholder, not production-ready")
    return None


# ---------------------------------------------------------------------------
# WEP
# ---------------------------------------------------------------------------

_WEP_IV_LEN = 3
_WEP_ICV_LEN = 4


def decrypt_wep(
    payload: bytes,
    key: bytes,
) -> Optional[bytes]:
    """
    Decrypt a WEP-protected 802.11 MPDU body.

    Args:
        payload: bytes starting at the WEP IV (after MAC header, before data)
        key:     WEP key bytes (5 bytes for WEP-40, 13 bytes for WEP-104)

    Returns:
        Decrypted plaintext (ICV stripped and verified), or None on ICV failure.
    """
    if len(payload) < _WEP_IV_LEN + 1 + _WEP_ICV_LEN:
        logger.debug("WEP: payload too short")
        return None

    iv = payload[:_WEP_IV_LEN]
    # byte 3 = key_id (ignored here — key passed directly)
    ciphertext = payload[4:]

    rc4_key = iv + key
    plaintext_and_icv = rc4(rc4_key, ciphertext)

    plaintext = plaintext_and_icv[:-_WEP_ICV_LEN]
    received_icv = plaintext_and_icv[-_WEP_ICV_LEN:]
    computed_icv = crc32_bytes(plaintext)

    if received_icv != computed_icv:
        logger.debug("WEP: ICV mismatch")
        return None

    return plaintext


# ---------------------------------------------------------------------------
# High-level decryptor — called by DLT parser or body.py
# ---------------------------------------------------------------------------

def decrypt_dot11_payload(
    payload: bytes,
    cipher: str,           # "ccmp" | "tkip" | "wep"
    credentials: dict,     # bssid-keyed entry from DissectConfig.credentials["dot11"]
    ta: bytes,             # 6-byte transmitter address
    bssid: bytes,          # 6-byte BSSID
    sta_mac: bytes,        # 6-byte station MAC
    priority: int = 0,
    aad: bytes = b"",
) -> Optional[bytes]:
    """
    Unified decryption entry point for 802.11 Data frame payloads.

    Called by the DLT parser after detecting `protected=True` in the FC.
    Resolves PTK from credentials (pre-computed or derived) then delegates
    to the cipher-specific function.

    Args:
        payload:     raw encrypted bytes (starting at cipher header)
        cipher:      "ccmp", "tkip", or "wep"
        credentials: the bssid sub-dict from DissectConfig.credentials["dot11"]
                     e.g. {"psk": "...", "ssid": "...", "clients": {...}}
        ta:          Transmitter Address (addr2 raw bytes)
        bssid:       BSSID raw bytes
        sta_mac:     Station MAC raw bytes
        priority:    QoS TID (0 for non-QoS)
        aad:         Additional Authenticated Data for CCMP (MAC header bytes)

    Returns:
        Decrypted plaintext bytes, or None on failure.
    """
    cipher = cipher.lower()

    if cipher == "wep":
        wep_cfg = credentials.get("wep", {})
        wep_key_hex = wep_cfg.get("key")
        if not wep_key_hex:
            logger.debug("WEP: no key in credentials")
            return None
        return decrypt_wep(payload, bytes.fromhex(wep_key_hex))

    # For CCMP / TKIP we need a PTK
    ptk = _resolve_ptk(credentials, bssid, sta_mac)
    if ptk is None:
        logger.debug(f"{cipher.upper()}: could not resolve PTK for {ta.hex()}")
        return None

    tk = ptk_tk(ptk)

    if cipher == CCMP:
        return decrypt_ccmp(payload, tk, ta, priority, aad)
    elif cipher == TKIP:
        return decrypt_tkip(payload, ptk[_KCK_LEN + _KEK_LEN:], ta, priority)

    logger.debug(f"Unknown cipher: {cipher}")
    return None


def _resolve_ptk(
    credentials: dict,
    bssid: bytes,
    sta_mac: bytes,
) -> Optional[bytes]:
    """
    Resolve PTK for a given (bssid, sta) pair.

    Resolution order:
      1. Pre-computed PTK in credentials["clients"][sta_hex]["ptk"]
      2. Pre-computed PMK in credentials["pmk"] + handshake nonces
      3. Derived PMK from credentials["psk"] + credentials["ssid"]

    Nonces (anonce, snonce) must be in credentials["clients"][sta_hex]
    and are populated by the EAPOL analyzer as frames are processed.
    """
    sta_hex = sta_mac.hex(":")
    client_creds = credentials.get("clients", {}).get(sta_hex, {})

    # 1. Pre-computed PTK
    ptk_hex = client_creds.get("ptk")
    if ptk_hex:
        return bytes.fromhex(ptk_hex)

    # 2. Need nonces to derive PTK
    anonce_hex = client_creds.get("anonce")
    snonce_hex = client_creds.get("snonce")
    if not anonce_hex or not snonce_hex:
        logger.debug("PTK derivation: missing anonce/snonce — need EAPOL handshake frames")
        return None

    anonce = bytes.fromhex(anonce_hex)
    snonce = bytes.fromhex(snonce_hex)

    # 3. Resolve PMK
    pmk_hex = credentials.get("pmk")
    if pmk_hex:
        pmk = bytes.fromhex(pmk_hex)
    else:
        psk  = credentials.get("psk")
        ssid = credentials.get("ssid")
        if not psk or not ssid:
            logger.debug("PTK derivation: no pmk, no psk+ssid")
            return None
        pmk = derive_pmk(psk, ssid)

    return derive_ptk(pmk, anonce, snonce, bssid, sta_mac)

def make_config(
    bssid: str = "",
    ssid: str = "",
    psk: str = "",
    pmk: str = "",
    clients: Optional[dict] = None,
) -> dict:
    """
    Build a single AP entry for credentials["dot11"][bssid].

    The dot11 section only holds what is needed to decrypt CCMP/TKIP/WEP at
    the 802.11 layer.  EAP, RADIUS, and TLS credentials live in their own
    top-level sections.

    Args:
        bssid:   AP MAC address string ("aa:bb:cc:dd:ee:ff")
        ssid:    Network name (needed for PMK derivation from PSK)
        psk:     WPA2/WPA3 Personal passphrase (derives PMK internally)
        pmk:     Pre-computed 32-byte PMK as hex string (skips derivation)
        clients: Optional dict of per-STA overrides:
                 {
                     "11:22:33:44:55:66": {
                         "ptk":    "hex...",    # skip derivation entirely
                         "anonce": "hex...",    # populated by EAPOL analyzer
                         "snonce": "hex...",    # populated by EAPOL analyzer
                     }
                 }

    Returns:
        AP credentials entry dict.

    WEP example (add to the returned dict):
        entry["wep"] = {"key_index": 0, "key": "0102030405"}
    """
    return {
        CREDENTIALS: {
            SSID: ssid,
            PSK: psk,
            PMK: pmk,
            CLIENTS: clients
        },
        CRYPT: {
        }
    }
