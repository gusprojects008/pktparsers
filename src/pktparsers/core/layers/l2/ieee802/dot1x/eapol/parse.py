# core/layers/l2/ieee802/dot1x/eapol/parse.py

from pktparsers.common.parse.definitions import (VALUE, DESCRIPTION)

from pktparsers.core.layers.l2.ieee802.dot1x.eapol.definitions import *

logger = getLogger(__name__)

def parse(**kwargs) -> dict:
    def _parser(value: tuple, **kwargs) -> dict:
        logger.debug("EAPOL _parser")

        (
            auth_ver,
            eapol_type,
            length,
            desc_type,
            key_info,
            key_len,
            replay,
            nonce,
            iv,
            rsc,
            key_id,
            mic,
            key_data_len,
        ) = value

        version_map = {
            0: "reserved(0)",
            1: "HMAC_MD5_ARC4_WPA1",
            2: "HMAC_SHA1_128_AES_WPA2_RSN",
            3: "AES_128_CMAC_AES_128_GCMP_WPA3",
            **{i: f"reserved({i})" for i in range(4, 8)},
        }

        descriptor_version_value = key_info & 0x0007

        descriptor_version = {
            VALUE: descriptor_version_value,
            DESCRIPTION: version_map.get(descriptor_version_value),
        }

        key_type_bit = (key_info >> 3) & 0x01

        key_type = {
            VALUE: key_type_bit,
            DESCRIPTION: GROUP_SMK if key_type_bit else PAIRWISE,
        }

        key_index = (key_info >> 4) & 0x03

        install_bit = bool((key_info >> 6) & 0x01)
        ack_bit = bool((key_info >> 7) & 0x01)
        mic_bit = bool((key_info >> 8) & 0x01)
        secure_bit = bool((key_info >> 9) & 0x01)
        error_bit = bool((key_info >> 10) & 0x01)
        request_bit = bool((key_info >> 11) & 0x01)
        encrypted_key_data = bool((key_info >> 12) & 0x01)
        smk_message = bool((key_info >> 13) & 0x01)

        result = {
            DOT1X_VERSION: auth_ver,
            DOT1X_TYPE: eapol_type,
            DOT1X_HEADER_LEN: length,
            KEY_DESCRIPTOR_TYPE: desc_type,
            KEY_INFORMATION: {
                KEY_DESCRIPTOR_VERSION: descriptor_version,
                KEY_TYPE: key_type,
                KEY_INDEX: key_index,
                KEY_INSTALL: install_bit,
                KEY_ACK: ack_bit,
                KEY_MIC: mic_bit,
                KEY_SECURE: secure_bit,
                KEY_ERROR: error_bit,
                KEY_REQUEST: request_bit,
                ENCRYPTED_KEY_DATA: encrypted_key_data,
                SMK_MESSAGE: smk_message,
            },
            KEY_LENGTH: key_len,
            KEY_REPLAY_COUNTER: replay,
            KEY_NONCE: nonce,
            KEY_IV: iv,
            KEY_RSC: rsc,
            KEY_ID: key_id,
            KEY_MIC: mic,
            KEY_DATA_LENGTH: key_data_len,
        }

        if key_data_len > 0:
            fmt = f"{key_data_len}s"

            if not encrypted_key_data:
                result[KEY_DATA] = unpack(
                    fmt,
                    parser=tagged_parameters,
                )
            else:
                result[KEY_DATA] = unpack(fmt)

        return result

    logger.debug("EAPOL Parser")

    result = {}

    try:
        result = unpack(
            FMT,
            parser=_parser,
        )

    except Exception as e:
        logger.debug(f"EAPOL Parser error: {e}")

    return result
