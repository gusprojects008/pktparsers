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
