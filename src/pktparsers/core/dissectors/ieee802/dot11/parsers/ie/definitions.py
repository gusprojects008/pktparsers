from pktparsers.core.dissectors.ieee802.dot1x.eapol.definitions import EAPOL_PMKID_FMT

MIN_IE_LEN = 2

TAG_SSID = 0
TAG_SUPPORTED_RATES = 1
TAG_CURRENT_CHANNEL = 3
TAG_TIM = 5
TAG_COUNTRY = 7
TAG_QBSS_LOAD = 11
TAG_POWER_CONSTRAINT = 32
TAG_TPC_REPORT = 35
TAG_ERP = 42
TAG_HT_CAPABILITIES = 45
TAG_RM_ENABLED_CAPABILITIES = 70
TAG_RSN_INFORMATION = 48
TAG_EXTENDED_SUPPORTED_RATES = 50
TAG_EXTENDED_CAPABILITIES = 127
TAG_VENDOR_SPECIFIC = 221
TAG_EXTENDED_HE = 255

TAG_SSID_NAME = "ssid"
TAG_SUPPORTED_RATES_NAME = "supported_rates"
TAG_CURRENT_CHANNEL_NAME = "current_channel"
TAG_TIM_NAME = "tim"
TAG_COUNTRY_NAME = "country"
TAG_QBSS_LOAD_NAME = "qbss_load"
TAG_POWER_CONSTRAINT_NAME = "power_constraint"
TAG_TPC_REPORT_NAME = "tpc_report"
TAG_ERP_NAME = "erp"
TAG_EXTENDED_SUPPORTED_RATES_NAME = "extended_supported_rates"
TAG_VENDOR_SPECIFIC_NAME = "vendor_specific"
TAG_HT_CAPABILITIES_NAME = "ht_capabilities"
TAG_RM_ENABLED_CAPABILITIES_NAME = "rm_enabled_capabilities"
TAG_RSN_INFORMATION_NAME = "rsn_information"
TAG_EXTENDED_CAPABILITIES_NAME = "extended_capabilities"
TAG_EXTENDED_HE_NAME = "extended_he"

OUI_MICROSOFT = "00:50:f2"
OUI_IEEE_80211 = "00:0f:ac"
OUI_WFA = "50:6f:9a"
OUI_MEDIATEK = "00:0c:43"
OUI_BROADCOM = "00:10:18"
OUI_ATHEROS = "00:03:7f"

MS_VENDOR_WPA = 1
MS_VENDOR_WPS = 4
MS_VENDOR_WMM_WME = 2

RSN_VENDOR_RSN_IE = 1
RSN_VENDOR_RSN_IE_ALT = 2
RSN_VENDOR_PMKID = 4

WFA_VENDOR_WPS = 4
WFA_VENDOR_P2P = 9
WFA_VENDOR_HS20 = 16
WFA_VENDOR_OSEN = 18

# ===========================
# Constantes de formato (struct)
# ===========================
OUI_FMT = "3s"
BYTE_FMT = "B"
WORD_FMT = "<H"
DWORD_FMT = "<I"
SHORT_FMT = ">H"   # big-endian short (para WPS attr type/length)
WPS_ATTR_FMT = ">HH"                # usado em _wps_extension
WMM_WME_FMT = "<BBH"                # usado em _wmm_wme_extension
RSN_CAPS_FMT = "<H"                 # usado em _rsn_capabilities
VENDOR_SPECIFIC_FMT = OUI_FMT + "B" # "3sB"
TIM_FMT = "<BBB"                    # tim_info
COUNTRY_FMT = "3sB"                 # country_code (básico)
COUNTRY_SUB_FMT = "<BBB"            # sub-elementos do country
ERP_FMT = "B"                       # erp_info
HT_CAPS_FMT = "<HB10sHBBBHIBB"      # ht_capabilities
RM_CAPS_FMT = "BB"                  # rm_enable_capabilities
QBSS_LOAD_FMT = "<HBH"              # qbss_load_element
TPC_REPORT_FMT = "BB"               # tcp_report
RSN_VERSION_FMT = "<H"              # rsn_information version
RSN_CIPHER_FMT = "3sB"              # group_cipher, pairwise_cipher
RSN_AKM_FMT = "3sB"                 # akm_suite
RSN_PMKID_FMT = EAPOL_PMKID_FMT  # 16s

# ===========================
# Constantes para tamanhos de campos
# ===========================
HT_CAPABILITIES_LEN = 26
RM_CAPABILITIES_LEN = 2
QBSS_LOAD_LEN = 5
TIM_MIN_LEN = 4
COUNTRY_MIN_LEN = 4
RSN_MIN_LEN = 2
EXTENDED_HE_MIN_LEN = 2

# ===========================
# Constantes de nomes de chaves (keys)
# ===========================
# Gerais
ATTR_TYPE = "attr_type"
ATTR_LENGTH = "attr_length"
FIELDS = "fields"
VENDOR_TYPE = "vendor_type"
VENDOR_ID = "vendor_id"
TAG_NUMBER = "tag_number"
TAG_LENGTH = "tag_length"
EXTENSION_ID = "extension_id"
EXTENSION_NAME = "extension_name"
PARSED_BYTE0 = "byte0"
PARSED_BYTE1 = "byte1"
PARSED_BYTE2 = "byte2"
PARSED_BYTE3 = "byte3"

# WPS
WPS_VERSION = "version"
WPS_STATE = "wps_state"
WPS_STATE_VALUE = "wps_state_value"
WPS_RESPONSE_TYPE = "response_type"
WPS_RESPONSE_TYPE_VALUE = "response_type_value"
WPS_UUID = "uuid"
WPS_MANUFACTURER = "manufacturer"
WPS_MODEL = "model"
WPS_MODEL_NUMBER = "model_number"
WPS_SERIAL_NUMBER = "serial_number"
WPS_DEVICE_NAME = "device_name"
WPS_PRIMARY_DEVICE_TYPE = "primary_device_type"
WPS_PRIMARY_DEVICE_TYPE_CATEGORY = "primary_device_type_category"
WPS_PRIMARY_DEVICE_TYPE_SUBCATEGORY = "primary_device_type_subcategory"
WPS_CONFIG_METHODS = "config_methods"
WPS_CONFIG_METHODS_VALUE = "config_methods_value"
WPS_RF_BANDS = "rf_bands"
WPS_RF_BANDS_VALUE = "rf_bands_value"
WPS_VENDOR_EXTENSION = "vendor_extension"
WPS_VERSION2 = "version2"
WPS_REQUEST_TO_ENROLL = "request_to_enroll"

# ===========================
# Constantes para WPS Vendor Extension subelements
# ===========================
WPS_VENDOR_EXT_VERSION2 = 0
WPS_VENDOR_EXT_REQUEST_TO_ENROLL = 1


# WMM/WME
WME_SUBTYPE = "wme_subtype"
WME_VERSION = "wme_version"
WME_QOS_INFO = "qos_info"
WME_AC_PARAMETERS = "ac_parameters"
WME_AC_INDEX = "ac_index"
WME_AIFSN = "aifsn"
WME_ECW_MIN = "ecw_min"
WME_ECW_MAX = "ecw_max"
WME_TXOP_LIMIT = "txop_limit"

# RSN capabilities (primeira versão, usada em vendor_specific)
RSN_CAPS_PRE_AUTH = "pre_auth"
RSN_CAPS_NO_PAIRWISE = "no_pairwise"
RSN_CAPS_PTKSA_REPLAY_COUNTER_LIMIT = "ptksa_replay_counter_limit"
RSN_CAPS_GTKSA_REPLAY_COUNTER_LIMIT = "gtksa_replay_counter_limit"
RSN_CAPS_MFP_REQUIRED = "management_frame_protection_required"
RSN_CAPS_MFP_CAPABLE = "management_frame_protection_capable"
RSN_CAPS_OCVC = "ocvc"

# Rates
RATE_VALUE = "value"
RATE_BASIC = "basic"

# TIM
DTIM_COUNT = "dtim_count"
DTIM_PERIOD = "dtim_period"
DTIM_BITMAP_CONTROL = "bitmap_control"
DTIM_PARTIAL_VIRTUAL_BITMAP = "partial_virtual_bitmap"
DTIM_MULTICAST = "multicast"
DTIM_BITMAP_OFFSET = "bitmap_offset"

# Country
COUNTRY_CODE = "country_code"
COUNTRY_ENVIRONMENT = "environment"
COUNTRY_SUB_ELEMENTS = "sub_elements"

# Constantes para nomes de campos do country sub-element
COUNTRY_FIRST_CHANNEL = "first_channel"
COUNTRY_NUM_CHANNELS = "num_channels"
COUNTRY_MAX_TX_POWER = "max_tx_power"

# ERP
ERP_NON_ERP_PRESENT = "non_erp_present"
ERP_USE_PROTECTION = "use_protection"
ERP_BARKER_PREAMBLE_MODE = "barker_preamble_mode"

# HT Capabilities
HT_CAPS_INFO = "ht_caps_info"
HT_LDPC_CODING_CAPABLE = "ldpc_coding_capable"
HT_SUPPORTED_CHANNEL_WIDTH = "supported_channel_width"
HT_SM_POWER_SAVE = "sm_power_save"
HT_GREEN_FIELD = "green_field"
HT_SHORT_GI_20MHZ = "short_gi_20mhz"
HT_SHORT_GI_40MHZ = "short_gi_40mhz"
HT_TX_STBC = "tx_stbc"
HT_RX_STBC = "rx_stbc"
HT_DELAYED_BLOCK_ACK = "delayed_block_ack"
HT_MAX_AMSDU_LENGTH = "max_amsdu_length"
HT_DSSS_CCK_40MHZ = "dsss_cck_40mhz"
HT_FORTY_MHZ_INTOLERANT = "forty_mhz_intolerant"
HT_LSIG_TXOP_PROTECTION = "lsig_txop_protection"
HT_AMPDU_PARAMS = "ampdu_params"
HT_MAX_RX_AMPDU_LENGTH_EXPONENT = "max_rx_ampdu_length_exponent"
HT_MIN_MPDU_START_SPACING = "min_mpdu_start_spacing"
HT_RX_MCS_BITMASK = "rx_mcs_bitmask"
HT_HIGHEST_SUPPORTED_RATE = "highest_supported_rate"
HT_TX_MCS_INFO = "tx_mcs_info"
HT_TX_MCS_SET_DEFINED = "tx_mcs_set_defined"
HT_TX_RX_MCS_SET_EQUAL = "tx_rx_mcs_set_equal"
HT_MAX_TX_SPATIAL_STREAMS = "max_tx_spatial_streams"
HT_UNEQUAL_MODULATION = "unequal_modulation"
HT_EXT_CAPS = "ht_ext_caps"
HT_PCO_SUPPORT = "pco_support"
HT_PCO_TRANSITION_TIME = "pco_transition_time"
HT_MCS_FEEDBACK = "mcs_feedback"
HT_HTC_SUPPORT = "htc_support"
HT_REVERSE_DIRECTION_RESPONDER = "reverse_direction_responder"
HT_TXBF_CAPS = "txbf_caps"
HT_IMPLICIT_BF_RX = "implicit_bf_rx"
HT_RX_STAGGERED_SOUNDING = "rx_staggered_sounding"
HT_TX_STAGGERED_SOUNDING = "tx_staggered_sounding"
HT_RX_NDP = "rx_ndp"
HT_TX_NDP = "tx_ndp"
HT_ASEL_CAPS = "asel_caps"
HT_ASEL_CAPABLE = "asel_capable"
HT_EXPLICIT_CSI_FEEDBACK_TX_ASEL = "explicit_csi_feedback_tx_asel"
HT_ANTENNA_INDICES_FEEDBACK_TX_ASEL = "antenna_indices_feedback_tx_asel"
HT_EXPLICIT_CSI_FEEDBACK = "explicit_csi_feedback"
HT_ANTENNA_INDICES_FEEDBACK = "antenna_indices_feedback"
HT_RX_ASEL = "rx_asel"

# RM Enabled Capabilities
RM_BYTE0 = "byte0"
RM_BYTE1 = "byte1"
RM_LINK_MEASUREMENT = "link_measurement"
RM_NEIGHBOR_REPORT = "neighbor_report"
RM_PARALLEL_MEASUREMENTS = "parallel_measurements"
RM_REPEATED_MEASUREMENTS = "repeated_measurements"
RM_BEACON_PASSIVE_MEASUREMENT = "beacon_passive_measurement"
RM_BEACON_ACTIVE_MEASUREMENT = "beacon_active_measurement"
RM_BEACON_TABLE_MEASUREMENT = "beacon_table_measurement"
RM_BEACON_MEASUREMENT_REPORTING = "beacon_measurement_reporting"
RM_FRAME_MEASUREMENT = "frame_measurement"
RM_CHANNEL_LOAD_MEASUREMENT = "channel_load_measurement"
RM_NOISE_HISTOGRAM_MEASUREMENT = "noise_histogram_measurement"
RM_STATISTICS_MEASUREMENT = "statistics_measurement"
RM_LCI_MEASUREMENT = "lci_measurement"
RM_LCI_AZIMUTH = "lci_azimuth"
RM_TX_STREAM_CATEGORY_MEASUREMENT = "tx_stream_category_measurement"
RM_TRIGGERED_TX_STREAM_MEASUREMENT = "triggered_tx_stream_measurement"

# Extended Capabilities
EXT_CAPS_BSS_COEXISTENCE = "bss_coexistence"
EXT_CAPS_EXTENDED_CHANNEL_SWITCHING = "extended_channel_switching"
EXT_CAPS_PSMP_CAPABILITY = "psmp_capability"
EXT_CAPS_BSS_TRANSITION = "bss_transition"
EXT_CAPS_INTERWORKING = "interworking"

# QBSS Load
QBSS_LOAD_STATION_COUNT = "station_count"
QBSS_LOAD_CHANNEL_UTILIZATION = "channel_utilization"
QBSS_LOAD_AVAILABLE_ADMISSION_CAPACITY = "available_admission_capacity"

# TPC Report
TCP_REPORT_TX_POWER = "tx_power"
TCP_REPORT_RESERVED = "reserved"

# RSN Information
RSN_INFO_RSN_VERSION = "version"
RSN_INFO_GROUP_CIPHER = "group_cipher"
RSN_INFO_PAIRWISE_CIPHERS = "pairwise_ciphers"
RSN_INFO_AKM_SUITES = "akm_suites"
RSN_INFO_AKM_SUITE_COUNT = "akm_suite_count"
RSN_INFO_CAPABILITIES = "capabilities"
RSN_INFO_PMKIDS = "pmkids"
RSN_INFO_PMKID_COUNT = "pmkid_count"
RSN_INFO_CIPHER_TYPE = "cipher_type"
RSN_INFO_AKM_TYPE = "akm_type"
RSN_INFO_JOINT_MULTI_BAND_RSNA = "joint_multi_band_rsna"
RSN_INFO_PEERKEY_ENABLED = "peerkey_enabled"
RSN_INFO_SPP_AMSDU_CAPABLE = "spp_amsdu_capable"
RSN_INFO_SPP_AMSDU_REQUIRED = "spp_amsdu_required"
RSN_INFO_PBAC = "pbac"
RSN_INFO_EXTENDED_KEY_ID = "extended_key_id"
RSN_INFO_RESERVED_BIT = "reserved"
RSN_INFO_PRE_AUTH = "pre_auth"
RSN_INFO_NO_PAIRWISE = "no_pairwise"
RSN_INFO_PTKSA_REPLAY_COUNTER = "ptksa_replay_counter"
RSN_INFO_GTKSA_REPLAY_COUNTER = "gtksa_replay_counter"
RSN_INFO_MFP_REQUIRED = "mgmt_frame_protection_required"
RSN_INFO_MFP_CAPABLE = "mgmt_frame_protection_capable"
RSN_INFO_OCVC = "ocvc"

# Extended HE
EXT_HE_CAPABILITIES = 35
EXT_HE_OPERATION = 36
EXT_HE_UORA_PARAMETER_SET = 39
EXT_HE_SHORT_BEACON_INTERVAL = 59
EXT_HE_EHT_CAPABILITIES = 108

EXT_HE_CAPABILITIES_NAME = "HE_CAPABILITIES"
EXT_HE_OPERATION_NAME = "HE_OPERATION"
EXT_HE_UORA_PARAMETER_SET_NAME = "UORA_PARAMETER_SET"
EXT_HE_SHORT_BEACON_INTERVAL_NAME = "SHORT_BEACON_INTERVAL"
EXT_HE_EHT_CAPABILITIES_NAME = "EHT_CAPABILITIES"

WPS_ATTRIBUTE_IDS = {
    "version": 0x104A,
    "device_name": 0x1012,
    "device_password_id": 0x1011,
    "config_methods": 0x1008,
    "manufacturer": 0x1021,
    "model_name": 0x1023,
    "model_number": 0x1024,
    "wps_state": 0x1044,
    "uuid_e": 0x1047,
    "rf_bands": 0x103C,
    "vendor_extension": 0x1049,
    "primary_device_type": 0x1054,
    "response_type": 0x103B,
    "serial_number": 0x1022,
}

WPS_CONFIGURATION_STATES = {
    "not_configured": 0x01,
    "configured": 0x02,
}

WPS_RESPONSE_TYPES = {
    "enrollee_info": 0x00,
    "enrollee": 0x01,
    "registrar": 0x02,
    "ap": 0x03,
}

WPS_RF_BANDS = {
    "2.4ghz": 0x01,
    "5ghz": 0x02,
    "2.4ghz_and_5ghz": 0x03,
}

WPS_CONFIG_METHODS = {
    "usb": 0x0001,
    "ethernet": 0x0002,
    "label": 0x0004,
    "display": 0x0008,
    "external_nfc_token": 0x0010,
    "integrated_nfc_token": 0x0020,
    "nfc_interface": 0x0040,
    "push_button": 0x0080,
    "keypad": 0x0100,
}

WPS_DEVICE_CATEGORIES = {
    "computer": 0x0001,
    "input_device": 0x0002,
    "print_scan_fax_copy": 0x0003,
    "camera": 0x0004,
    "storage": 0x0005,
    "network_infrastructure": 0x0006,
    "display": 0x0007,
    "multimedia": 0x0008,
    "gaming": 0x0009,
    "telephone": 0x000a,
    "audio": 0x000b,
    "other": 0x000f,
}

WPS_ATTRIBUTE_NAMES = {v: k for k, v in WPS_ATTRIBUTE_IDS.items()}
WPS_CONFIGURATION_STATE_NAMES = {v: k for k, v in WPS_CONFIGURATION_STATES.items()}
WPS_RESPONSE_TYPE_NAMES = {v: k for k, v in WPS_RESPONSE_TYPES.items()}
WPS_RF_BAND_NAMES = {v: k for k, v in WPS_RF_BANDS.items()}
WPS_CONFIG_METHOD_NAMES = {v: k for k, v in WPS_CONFIG_METHODS.items()}
WPS_DEVICE_CATEGORY_NAMES = {v: k for k, v in WPS_DEVICE_CATEGORIES.items()}
