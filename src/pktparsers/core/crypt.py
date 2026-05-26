# pktparsers/core/crypt.py
#
# Generic cryptographic primitives shared by protocol-specific crypt modules.
# Nothing here knows about 802.11, EAPOL, or any protocol.
# Protocol-specific key derivation and decryption live in their own modules.

import hmac
import hashlib
import struct
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from typing import Optional

# ---------------------------------------------------------------------------
# PRF / KDF
# ---------------------------------------------------------------------------

def prf_sha1(key: bytes, label: str, data: bytes, length_bits: int) -> bytes:
    """
    IEEE 802.11 PRF-SHA1 (used for PTK/GTK derivation).
    Produces `length_bits` of pseudo-random keying material.
    """
    result = b""
    counter = 0
    label_bytes = label.encode() + b"\x00"
    while len(result) * 8 < length_bits:
        result += hmac.new(
            key,
            label_bytes + data + bytes([counter]),
            hashlib.sha1,
        ).digest()
        counter += 1
    return result[: length_bits // 8]


def pbkdf2_sha1(password: str, ssid: str, iterations: int = 4096, length: int = 32) -> bytes:
    """PBKDF2-HMAC-SHA1 — used for PSK → PMK derivation (WPA2 Personal)."""
    return hashlib.pbkdf2_hmac(
        "sha1",
        password.encode(),
        ssid.encode(),
        iterations,
        dklen=length,
    )


def hmac_sha1(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha1).digest()


def hmac_md5(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.md5).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

# ---------------------------------------------------------------------------
# AES-CCM (CCMP)
# ---------------------------------------------------------------------------

def aes_ccm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> Optional[bytes]:
    """
    AES-CCM decryption used by CCMP (802.11i).
    Returns plaintext on success, None on MIC failure.

    Requires `cryptography` (pip install cryptography).
    Uses 8-byte MIC (M=8) and 2-byte length field (L=2), per 802.11 CCMP spec.
    """
    try:
        aesccm = AESCCM(key, tag_length=8)
        return aesccm.decrypt(nonce, ciphertext, aad)
    except Exception:
        return None

# ---------------------------------------------------------------------------
# RC4 (TKIP / WEP)
# ---------------------------------------------------------------------------

def rc4(key: bytes, data: bytes) -> bytes:
    """Raw RC4 stream cipher. Used by TKIP and WEP."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)


# ---------------------------------------------------------------------------
# Michael MIC (TKIP integrity)
# ---------------------------------------------------------------------------

def _michael_b(l: int, r: int) -> tuple[int, int]:
    r = r ^ ((l << 17) | (l >> 15)) & 0xFFFFFFFF
    l = (l + r) & 0xFFFFFFFF
    r = r ^ ((l & 0x00FF00FF) << 8 | (l & 0xFF00FF00) >> 8)
    l = (l + r) & 0xFFFFFFFF
    r = r ^ ((l << 3) | (l >> 29)) & 0xFFFFFFFF
    l = (l + r) & 0xFFFFFFFF
    r = r ^ ((l >> 2) | (l << 30)) & 0xFFFFFFFF
    l = (l + r) & 0xFFFFFFFF
    return l, r


def michael_mic(key: bytes, da: bytes, sa: bytes, priority: int, data: bytes) -> bytes:
    """
    TKIP Michael MIC. Key is 8 bytes (KCK[16:24] for Tx MIC or [24:32] for Rx MIC).
    """
    kl, kr = struct.unpack_from("<II", key)
    msg = da + sa + bytes([priority, 0, 0, 0]) + data

    # Pad to multiple of 4
    pad_len = (4 - len(msg) % 4) % 4
    msg += bytes([0x5a]) + bytes(pad_len)

    l, r = kl, kr
    for i in range(0, len(msg), 4):
        word = struct.unpack_from("<I", msg, i)[0]
        l ^= word
        l, r = _michael_b(l, r)

    mic_bytes = struct.pack("<II", l, r)
    return mic_bytes


# ---------------------------------------------------------------------------
# CRC-32 (WEP ICV)
# ---------------------------------------------------------------------------

def crc32_bytes(data: bytes) -> bytes:
    """CRC-32 as little-endian 4 bytes (WEP ICV)."""
    crc = binascii.crc32(data) & 0xFFFFFFFF
    return struct.pack("<I", crc)
