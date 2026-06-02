## O que está faltando? para corrigir / adicionar

Preciso: 
Substituir todos os hardcodes de tamanhos, struct formats e nomes de chaves de resultado de parsers, por constantes. Atualizar todos os formats de struct, para utilizarem valores de constantes definidas, dessa forma irá eliminar boa parte dos hardcodes, irá melhorar a legibilidade, e significativamente a escalabilidade.

Com base no arquivo definitions.py atualize o parse.py com uso das constantes e dicionários de definitions.py .
Defina novas constantes caso encontre strings hardcoded que se repetem e que são usadas como chaves em dicionários.
Não é necessário constantizar valores para operações de bitmasking como 0x0001 ou 0x0002 .

Veja o arquivo repomix que possui o contexto de alguns módulos globais de constantes.

Siga esse padrão exemplo:
eapol/definitions.py:
from pktparsers.core.definitions.parsing import (
    VALUE,
    DESCRIPTION,
)

DOT1X_VERSION = "dot1x_version"
DOT1X_TYPE = "dot1x_type"
DOT1X_HEADER_LEN = "dot1x_header_length"

KEY_DESCRIPTOR_TYPE = "key_descriptor_type"
KEY_INFORMATION = "key_information"
KEY_DESCRIPTOR_VERSION = "key_descriptor_version"
KEY_TYPE = "key_type"
KEY_INDEX = "key_index"
KEY_INSTALL = "key_install"
KEY_ACK = "key_ack"
KEY_MIC = "key_mic"
KEY_SECURE = "key_secure"
KEY_ERROR = "key_error"
KEY_REQUEST = "key_request"
ENCRYPTED_KEY_DATA = "encrypted_key_data"
SMK_MESSAGE = "smk_message"

KEY_LENGTH = "key_length"
KEY_REPLAY_COUNTER = "key_replay_counter"
KEY_NONCE = "key_nonce"
KEY_IV = "key_iv"
KEY_RSC = "key_rsc"
KEY_ID = "key_id"
KEY_DATA = "key_data"
KEY_DATA_LENGTH = "key_data_length"

PAIRWISE = "pairwise"
GROUP_SMK = "group_smk"

DOT1X_VERSION_FMT = "B"
DOT1X_TYPE_FMT = "B"
DOT1X_HEADER_LEN_FMT = "H"

KEY_DESCRIPTOR_TYPE_FMT = "B"
KEY_INFORMATION_FMT = "H"
KEY_LENGTH_FMT = "H"

KEY_REPLAY_COUNTER_FMT = "8s"
KEY_NONCE_FMT = "32s"
KEY_IV_FMT = "16s"
KEY_RSC_FMT = "8s"
KEY_ID_FMT = "8s"
KEY_MIC_FMT = "16s"
KEY_DATA_LENGTH_FMT = "H"

FMT = (
    "!" +
    DOT1X_VERSION_FMT +
    DOT1X_TYPE_FMT +
    DOT1X_HEADER_LEN_FMT +
    KEY_DESCRIPTOR_TYPE_FMT +
    KEY_INFORMATION_FMT +
    KEY_LENGTH_FMT +
    KEY_REPLAY_COUNTER_FMT +
    KEY_NONCE_FMT +
    KEY_IV_FMT +
    KEY_RSC_FMT +
    KEY_ID_FMT +
    KEY_MIC_FMT +
    KEY_DATA_LENGTH_FMT
)



eapol/parse.py:
# core/dissectors/ieee802/dot1x/eapol/parse.py

from pktparsers.core.parsing.definitions import (VALUE, DESCRIPTION)

from pktparsers.core.dissectors.ieee802.dot1x.eapol.definitions import *

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




Preciso aplicar esse padrão em:

from logging import getLogger
from pktparsers.core.parsing import (unpack, read_mac)
from pkparsers.core.dissectors.ieee802.dot11.definitions import *

logger = getLogger(__name__)

def parse(**kwargs) -> dict:
    logger.debug("MAC Header parse")

    def _parser(fc_val: int, **k) -> dict:
        protocol_version = fc_val & 0b11
        f_type = (fc_val >> 2) & 0b11
        f_subtype = (fc_val >> 4) & 0b1111
        to_ds = (fc_val >> 8) & 1
        from_ds = (fc_val >> 9) & 1
        protected = bool(fc_val & 0x4000)
        
        type_name = FRAME_TYPES.get(f_type)
        subtype_name = FRAME_SUBTYPES.get(f_type, {}).get(f_subtype)
        is_qos = f_type == DATA and bool(f_subtype & 0b1000)

        duration = unpack(DURATION_FMT)
        
        addr1 = read_mac()
        
        addr2 = addr3 = addr4 = seq = qos = None

        if f_type == CTRL:
            if f_subtype in (CTRL_BLOCK_ACK_REQUEST, CTRL_BLOCK_ACK, CTRL_PS_POLL, 
                             CTRL_RTS, CTRL_CF_END, CTRL_CF_END_ACK):
                addr2 = read_mac() 
        else:
            addr2 = read_mac() 
            addr3 = read_mac() 
            fs = unpack(FS_FMT, parser=lambda v, **k: v >> 4) # fragment number + sequence number

            if to_ds and from_ds:
                addr4 = read_mac() 

        ra = addr1
        ta = addr2 if addr2 else None
        a3 = addr3 if addr3 else None
        a4 = addr4 if addr4 else None

        sa = da = bssid = None
        if to_ds == 0 and from_ds == 0:
            sa, da, bssid = ta, ra, a3
        elif to_ds == 0 and from_ds == 1:
            sa, da, bssid = a3, ra, ta
        elif to_ds == 1 and from_ds == 0:
            sa, da, bssid = ta, a3, ra
        elif to_ds == 1 and from_ds == 1:
            sa, da, bssid = a4, a3, None

        # QoS Control
        if is_qos:
            qos = unpack("<H")

        return {
            "fc": {
                "protocol_version": protocol_version,
                "type": f_type,
                "type_name": type_name,
                "subtype": f_subtype,
                "subtype_name": subtype_name,
                "tods": to_ds,
                "fromds": from_ds,
                "protected": protected,
            },
            "duration_id": duration,
            "ra": ra, "ta": ta, "sa": sa, "da": da, "bssid": bssid,
            "sequence_number": seq,
            "qos_control": qos
        }

    result = {}

    try:
        result = unpack("<H", parser=_parser)
    except Exception as e:
        logger.debug(f"MAC Header parser error: {e}")

    return result
