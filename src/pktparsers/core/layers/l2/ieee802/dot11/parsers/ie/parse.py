# pktparser/core/layers/l2/ieee802/dot11/parsers/ie/parse.py

import struct
from uuid import UUID
from logging import getLogger
from core.common.parse.utils import (ParseContext, unpack, run_dispatch, bytes_for_oui)
from core.common.parse.definitions import (NAME, VALUE, RAW, DESCRIPTION, PARSED, OUI_FMT)
from pktparsers.core.layers.l2.ieee802.dot11.parsers.ie.definitions import *

logger = getLogger(__name__)

OUI_LENGTH = struct.calcsize(OUI_FMT)

def _parse_wps_attribute(attr_type: int, attr_data: bytes) -> dict:
    result = {}

    if attr_type == WPS_ATTRIBUTE_IDS.get(WPS_VERSION):
        if len(attr_data) >= 1:
            version_byte = attr_data[0]
            version_major = version_byte >> 4
            version_minor = version_byte & 0x0F
            result[WPS_VERSION] = f"{version_major}.{version_minor}"

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_STATE):
        if len(attr_data) >= 1:
            state_hex = attr_data[0]
            state_desc = WPS_CONFIGURATION_STATE_NAMES.get(state_hex, f"unknown_{state_hex:02x}")
            result[WPS_STATE] = state_desc
            result[WPS_STATE_VALUE] = state_hex

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_RESPONSE_TYPE):
        if len(attr_data) >= 1:
            resp_type = attr_data[0]
            resp_desc = WPS_RESPONSE_TYPE_NAMES.get(resp_type, f"unknown_{resp_type:02x}")
            result[WPS_RESPONSE_TYPE] = resp_desc
            result[WPS_RESPONSE_TYPE_VALUE] = resp_type

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_UUID):
        if len(attr_data) == 16:
            result[WPS_UUID] = str(UUID(bytes=attr_data))
        else:
            result[WPS_UUID] = attr_data

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_MANUFACTURER):
        result[WPS_MANUFACTURER] = attr_data.decode('utf-8', errors='ignore').strip('\x00')

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_MODEL):
        result[WPS_MODEL] = attr_data.decode('utf-8', errors='ignore').strip('\x00')

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_MODEL_NUMBER):
        result[WPS_MODEL_NUMBER] = attr_data.decode('utf-8', errors='ignore').strip('\x00')

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_SERIAL_NUMBER):
        result[WPS_SERIAL_NUMBER] = attr_data.decode('utf-8', errors='ignore').strip('\x00')

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_DEVICE_NAME):
        result[WPS_DEVICE_NAME] = attr_data.decode('utf-8', errors='ignore').strip('\x00')

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_PRIMARY_DEVICE_TYPE):
        if len(attr_data) >= 8:
            category = int.from_bytes(attr_data[0:2], 'big')
            oui = bytes_for_oui(attr_data[2:6]).get("oui")
            subtype = int.from_bytes(attr_data[6:8], 'big')
            result[WPS_PRIMARY_DEVICE_TYPE] = f"{category}-{oui}-{subtype}"
            category_desc = WPS_DEVICE_CATEGORY_NAMES.get(category, f"unknown_{category:04x}")
            result[WPS_PRIMARY_DEVICE_TYPE_CATEGORY] = category_desc
            result[WPS_PRIMARY_DEVICE_TYPE_SUBCATEGORY] = subtype

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_CONFIG_METHODS):
        if len(attr_data) >= 2:
            config_mask = int.from_bytes(attr_data[0:2], 'big')
            methods = [
                k.replace('_', ' ').title()
                for k, bit in WPS_CONFIG_METHODS.items()
                if config_mask & bit
            ]
            result[WPS_CONFIG_METHODS] = ", ".join(methods)
            result[WPS_CONFIG_METHODS_VALUE] = config_mask

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_RF_BANDS):
        if len(attr_data) >= 1:
            band_hex = attr_data[0]
            band_desc = WPS_RF_BAND_NAMES.get(band_hex, f"unknown_{band_hex:02x}")
            result[WPS_RF_BANDS] = band_desc
            result[WPS_RF_BANDS_VALUE] = band_hex

    elif attr_type == WPS_ATTRIBUTE_IDS.get(WPS_VENDOR_EXTENSION):
        if len(attr_data) >= 3:
            vendor_id = int.from_bytes(attr_data[0:3], 'big')
            result[VENDOR_ID] = vendor_id

            sub_offset = 3
            while sub_offset + 2 <= len(attr_data):
                subelement_id = attr_data[sub_offset]
                subelement_len = attr_data[sub_offset + 1]
                sub_offset += 2

                if sub_offset + subelement_len > len(attr_data):
                    break

                subelement_data = attr_data[sub_offset:sub_offset + subelement_len]
                sub_offset += subelement_len

                if subelement_id == WPS_VENDOR_EXT_VERSION2:
                    if len(subelement_data) >= 1:
                        version_major = subelement_data[0] >> 4
                        version_minor = subelement_data[0] & 0x0F
                        result[WPS_VERSION2] = f"{version_major}.{version_minor}"
                elif subelement_id == WPS_VENDOR_EXT_REQUEST_TO_ENROLL:
                    if len(subelement_data) >= 1:
                        result[WPS_REQUEST_TO_ENROLL] = bool(subelement_data[0] & 0x01)

    return result

def _wps_extension(tag_length: int, **kwargs) -> dict:
    ctx = ParseContext.current()
    end_offset = ctx.offset + (tag_length - 4)  # 4 = len(OUI) + 1 (vendor type)
    
    attributes = {}
    idx = 1

    while ctx.offset + 4 <= end_offset:
        def _attr_parser(value: tuple, **k) -> dict:
            attr_type, attr_len = value
            
            data_res = unpack(f"{attr_len}s")
            raw_data = data_res[VALUE]
            
            fields = _parse_wps_attribute(attr_type, raw_data)
            
            return {
                ATTR_TYPE: attr_type,
                ATTR_LENGTH: attr_len,
                FIELDS: fields
            }

        attr_entry = unpack(WPS_ATTR_FMT, parser=_attr_parser)
        attributes[idx] = attr_entry
        idx += 1

    return attributes

def _wmm_wme_extension(tag_length: int, **kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        subtype, version, qos_info, reserved = value
        
        ctx = ParseContext.current()
        end_offset = ctx.offset + (tag_length - 8)
        
        ac_params = {}
        idx = 0

        while ctx.offset + 4 <= end_offset:
            def _ac_parser(ac_val: tuple, **ak) -> dict:
                aci_aifsn, ecw, txop = ac_val
                
                ac_id = (aci_aifsn >> 5) & 0x03
                aifsn = aci_aifsn & 0x0F
                ecw_min = ecw & 0x0F
                ecw_max = (ecw >> 4) & 0x0F
                
                return {
                    WME_AC_INDEX: ac_id,
                    WME_AIFSN: aifsn,
                    WME_ECW_MIN: ecw_min,
                    WME_ECW_MAX: ecw_max,
                    WME_TXOP_LIMIT: txop
                }

            ac_entry = unpack(WMM_WME_FMT, parser=_ac_parser)
            key = ac_entry.get(PARSED, {}).get(WME_AC_INDEX, idx)
            ac_params[key] = ac_entry
            idx += 1

        return {
            WME_SUBTYPE: subtype,
            WME_VERSION: version,
            WME_QOS_INFO: qos_info,
            WME_AC_PARAMETERS: ac_params
        }

    return unpack("BBBB", parser=_parser)

def _rsn_capabilities(tag_length: int, **kwargs) -> dict:
    def _parser(value: int, **k) -> dict:
        pre_auth = bool(value & 0x0001)
        no_pairwise = bool(value & 0x0002)
        ptksa_replay = (value >> 2) & 0x03
        gtksa_replay = (value >> 4) & 0x03
        mfp_required = bool(value & 0x0040)
        mfp_capable = bool(value & 0x0080)
        ocvc = bool(value & 0x4000)

        return {
            RSN_CAPS_PRE_AUTH: pre_auth,
            RSN_CAPS_NO_PAIRWISE: no_pairwise,
            RSN_CAPS_PTKSA_REPLAY_COUNTER_LIMIT: ptksa_replay,
            RSN_CAPS_GTKSA_REPLAY_COUNTER_LIMIT: gtksa_replay,
            RSN_CAPS_MFP_REQUIRED: mfp_required,
            RSN_CAPS_MFP_CAPABLE: mfp_capable,
            RSN_CAPS_OCVC: ocvc
        }

    return unpack(RSN_CAPS_FMT, parser=_parser)

SPECIFIC_VENDOR_DISPATCH = {
    OUI_MICROSOFT: {
        MS_VENDOR_WPS: {DESCRIPTION: "Wi-Fi Alliance WPS (Microsoft)", PARSER: _wps_extension},
        MS_VENDOR_WMM_WME: {DESCRIPTION: "Microsoft WMM/WME", PARSER: _wmm_wme_extension},
        MS_VENDOR_WPA: {DESCRIPTION: "Microsoft WPA", PARSER: None}
    },
    OUI_IEEE_80211: {
        RSN_VENDOR_RSN_IE: {DESCRIPTION: "RSN Information", PARSER: _rsn_capabilities},
        RSN_VENDOR_RSN_IE_ALT: {DESCRIPTION: "RSN Information (Alt)", PARSER: _rsn_capabilities},
        RSN_VENDOR_PMKID: {DESCRIPTION: "PMKID", PARSER: None}
    },
    OUI_WFA: {
        WFA_VENDOR_WPS: {DESCRIPTION: "Wi-Fi Alliance WPS", PARSER: None},
        WFA_VENDOR_P2P: {DESCRIPTION: "Wi-Fi Alliance P2P", PARSER: None},
        WFA_VENDOR_HS20: {DESCRIPTION: "Wi-Fi Alliance Hotspot 2.0", PARSER: None},
        WFA_VENDOR_OSEN: {DESCRIPTION: "Wi-Fi Alliance OSEN", PARSER: None}
    },
    OUI_MEDIATEK: {DESCRIPTION: "MediaTek Inc", PARSER: None},
    OUI_BROADCOM: {DESCRIPTION: "Broadcom", PARSER: None},
    OUI_ATHEROS: {DESCRIPTION: "Atheros", PARSER: None}
}

def vendor_specific(tag_length: int, **kwargs) -> dict:
    fmt = f"{OUI_FMT}B"

    def _parser(value: tuple, **kwargs) -> dict:
        oui, vtype = value
        oui = bytes_for_oui(oui)
        
        vendor_sub_table = SPECIFIC_VENDOR_DISPATCH.get(oui["oui"], {})
        entry = vendor_sub_table.get(vtype, {})
        description = entry.get(DESCRIPTION, "Generic Vendor Specific")
        
        remaining_len = tag_length - struct.calcsize(fmt)

        def _fallback(**k):
            return unpack(f"{remaining_len}s")

        data = run_dispatch(
            dispatch_table=vendor_sub_table,
            dispatch_id=vtype,
            fallback=_fallback,
            tag_length=tag_length
        )

        result = {
            **oui,
            VENDOR_TYPE: vtype,
            DESCRIPTION: description,
            DATA: data
        }
        return result

    return unpack(fmt, parser=_parser)

def ssid(tag_length: int, **kwargs) -> dict:
    return unpack(f"{tag_length}s", parser=lambda value: value.decode(errors="ignore"))

def rates(tag_length: int, **kwargs) -> dict:
    ctx = ParseContext.current()
    end = ctx.offset + tag_length

    result = {}
    i = 1

    while ctx.offset < end:
        rate_result = unpack(
            BYTE_FMT,
            parser=lambda value: {
                RATE_VALUE: (value & 0x7F) / 2,
                RATE_BASIC: bool(value & 0x80)
            }
        )
        result[i] = rate_result
        i += 1

    return result

def tim_info(tag_length: int, **kwargs) -> dict:
    if tag_length < TIM_MIN_LEN:
        return {}
    
    def _parser(values: tuple, **kwargs) -> dict:
        dtim_count, dtim_period, bitmap_control = values
        
        multicast = bool(bitmap_control & 0x01)
        bitmap_offset = (bitmap_control >> 1) & 0x7F
        
        ctx = ParseContext.current()
        end = ctx.offset + (tag_length - 3)
        
        partial_virtual_bitmap = b""
        if ctx.offset < end:
            pvb_result = unpack(f"{end - ctx.offset}s")
            partial_virtual_bitmap = pvb_result
        
        return {
            DTIM_COUNT: dtim_count,
            DTIM_PERIOD: dtim_period,
            DTIM_BITMAP_CONTROL: {
                RAW: bitmap_control,
                DTIM_MULTICAST: multicast,
                DTIM_BITMAP_OFFSET: bitmap_offset
            },
            DTIM_PARTIAL_VIRTUAL_BITMAP: partial_virtual_bitmap
        }
    
    return unpack(TIM_FMT, parser=_parser)

def country_code(tag_length: int, **kwargs) -> dict:
    def _parser(value: tuple, **kwargs) -> dict:
        country_str, environment = value
        country_str = country_str.decode(errors="ignore")

        ctx = ParseContext.current()
        end = ctx.offset + (tag_length - COUNTRY_MIN_LEN)

        sub_elements = {}
        i = 0
        while ctx.offset + 3 <= end:
            sub_result = unpack(COUNTRY_SUB_FMT, parser=lambda v, **k: {
                COUNTRY_FIRST_CHANNEL: v[0],
                COUNTRY_NUM_CHANNELS: v[1],
                COUNTRY_MAX_TX_POWER: v[2]
            })
            sub_elements[i] = sub_result
            i += 1

        remaining = end - ctx.offset
        if remaining > 0:
            unpack(f"{remaining}s")

        result = {COUNTRY_CODE: country_str, COUNTRY_ENVIRONMENT: environment}
        if sub_elements:
            result[COUNTRY_SUB_ELEMENTS] = sub_elements
        return result

    if tag_length < COUNTRY_MIN_LEN:
        return unpack(COUNTRY_FMT, parser=lambda v, **k: {
            COUNTRY_CODE: v[0].decode(errors="ignore"),
            COUNTRY_ENVIRONMENT: v[1]
        })

    return unpack(COUNTRY_FMT, parser=_parser)

def erp_info(tag_length: int, **kwargs) -> dict:
    if tag_length < 1:
        return {}
    
    def _parser(value: int, **kwargs) -> dict:
        non_erp_present = bool(value & 0x01)
        use_protection = bool(value & 0x02)
        barker_preamble_mode = bool(value & 0x04)
        
        return {
            ERP_NON_ERP_PRESENT: non_erp_present,
            ERP_USE_PROTECTION: use_protection,
            ERP_BARKER_PREAMBLE_MODE: barker_preamble_mode
        }
    
    return unpack(ERP_FMT, parser=_parser)

def ht_capabilities(tag_length: int, **kwargs) -> dict:
    if tag_length < HT_CAPABILITIES_LEN:
        return {}
    
    def _parser(values: tuple, **kwargs) -> dict:
        (ht_caps_info, ampdu_params, rx_mcs_bitmask, highest_supported_rate, 
                 tx_mcs_info, _reserved1, _reserved2, ht_ext_caps, 
                 txbf_caps, asel_caps, _pad) = values
        
        # HT Capabilities Info
        ldpc_coding_capable = bool(ht_caps_info & 0x0001)
        supported_channel_width = bool(ht_caps_info & 0x0002)
        sm_power_save = (ht_caps_info >> 2) & 0x03
        green_field = bool(ht_caps_info & 0x0010)
        short_gi_20mhz = bool(ht_caps_info & 0x0020)
        short_gi_40mhz = bool(ht_caps_info & 0x0040)
        tx_stbc = bool(ht_caps_info & 0x0080)
        rx_stbc = (ht_caps_info >> 8) & 0x03
        delayed_block_ack = bool(ht_caps_info & 0x0400)
        max_amsdu_length = bool(ht_caps_info & 0x0800)
        dsss_cck_40mhz = bool(ht_caps_info & 0x1000)
        forty_mhz_intolerant = bool(ht_caps_info & 0x4000)
        lsig_txop_protection = bool(ht_caps_info & 0x8000)
        
        # AMPDU Params
        max_rx_ampdu_length_exponent = ampdu_params & 0x03
        min_mpdu_start_spacing = (ampdu_params >> 2) & 0x07
        
        # TX MCS Info
        tx_mcs_set_defined = bool(tx_mcs_info & 0x01)
        tx_rx_mcs_set_equal = bool(tx_mcs_info & 0x02)
        max_tx_spatial_streams = (tx_mcs_info >> 2) & 0x03
        unequal_modulation = bool(tx_mcs_info & 0x10)
        
        # HT Extended Capabilities
        pco_support = bool(ht_ext_caps & 0x0001)
        pco_transition_time = (ht_ext_caps >> 1) & 0x03
        mcs_feedback = (ht_ext_caps >> 4) & 0x03
        htc_support = bool(ht_ext_caps & 0x0400)
        reverse_direction_responder = bool(ht_ext_caps & 0x0800)
        
        # TXBF Capabilities
        implicit_bf_rx = bool(txbf_caps & 0x00000001)
        rx_staggered_sounding = bool(txbf_caps & 0x00000002)
        tx_staggered_sounding = bool(txbf_caps & 0x00000004)
        rx_ndp = bool(txbf_caps & 0x00000008)
        tx_ndp = bool(txbf_caps & 0x00000010)
        
        # ASEL Capabilities
        asel_capable = bool(asel_caps & 0x01)
        explicit_csi_feedback_tx_asel = bool(asel_caps & 0x02)
        antenna_indices_feedback_tx_asel = bool(asel_caps & 0x04)
        explicit_csi_feedback = bool(asel_caps & 0x08)
        antenna_indices_feedback = bool(asel_caps & 0x10)
        rx_asel = bool(asel_caps & 0x20)
        
        return {
            HT_CAPS_INFO: {
                HT_LDPC_CODING_CAPABLE: ldpc_coding_capable,
                HT_SUPPORTED_CHANNEL_WIDTH: supported_channel_width,
                HT_SM_POWER_SAVE: sm_power_save,
                HT_GREEN_FIELD: green_field,
                HT_SHORT_GI_20MHZ: short_gi_20mhz,
                HT_SHORT_GI_40MHZ: short_gi_40mhz,
                HT_TX_STBC: tx_stbc,
                HT_RX_STBC: rx_stbc,
                HT_DELAYED_BLOCK_ACK: delayed_block_ack,
                HT_MAX_AMSDU_LENGTH: max_amsdu_length,
                HT_DSSS_CCK_40MHZ: dsss_cck_40mhz,
                HT_FORTY_MHZ_INTOLERANT: forty_mhz_intolerant,
                HT_LSIG_TXOP_PROTECTION: lsig_txop_protection
            },
            HT_AMPDU_PARAMS: {
                HT_MAX_RX_AMPDU_LENGTH_EXPONENT: max_rx_ampdu_length_exponent,
                HT_MIN_MPDU_START_SPACING: min_mpdu_start_spacing
            },
            HT_RX_MCS_BITMASK: rx_mcs_bitmask,
            HT_HIGHEST_SUPPORTED_RATE: highest_supported_rate,
            HT_TX_MCS_INFO: {
                HT_TX_MCS_SET_DEFINED: tx_mcs_set_defined,
                HT_TX_RX_MCS_SET_EQUAL: tx_rx_mcs_set_equal,
                HT_MAX_TX_SPATIAL_STREAMS: max_tx_spatial_streams,
                HT_UNEQUAL_MODULATION: unequal_modulation
            },
            HT_EXT_CAPS: {
                HT_PCO_SUPPORT: pco_support,
                HT_PCO_TRANSITION_TIME: pco_transition_time,
                HT_MCS_FEEDBACK: mcs_feedback,
                HT_HTC_SUPPORT: htc_support,
                HT_REVERSE_DIRECTION_RESPONDER: reverse_direction_responder
            },
            HT_TXBF_CAPS: {
                HT_IMPLICIT_BF_RX: implicit_bf_rx,
                HT_RX_STAGGERED_SOUNDING: rx_staggered_sounding,
                HT_TX_STAGGERED_SOUNDING: tx_staggered_sounding,
                HT_RX_NDP: rx_ndp,
                HT_TX_NDP: tx_ndp
            },
            HT_ASEL_CAPS: {
                HT_ASEL_CAPABLE: asel_capable,
                HT_EXPLICIT_CSI_FEEDBACK_TX_ASEL: explicit_csi_feedback_tx_asel,
                HT_ANTENNA_INDICES_FEEDBACK_TX_ASEL: antenna_indices_feedback_tx_asel,
                HT_EXPLICIT_CSI_FEEDBACK: explicit_csi_feedback,
                HT_ANTENNA_INDICES_FEEDBACK: antenna_indices_feedback,
                HT_RX_ASEL: rx_asel
            }
        }
    
    return unpack(HT_CAPS_FMT, parser=_parser)

def rm_enable_capabilities(tag_length: int, **kwargs) -> dict:
    if tag_length < RM_CAPABILITIES_LEN:
        return {}
    
    def _parser(values: tuple, **kwargs) -> dict:
        byte0, byte1 = values
        
        byte0_parsed = {
            RM_LINK_MEASUREMENT: bool(byte0 & 0x01),
            RM_NEIGHBOR_REPORT: bool(byte0 & 0x02),
            RM_PARALLEL_MEASUREMENTS: bool(byte0 & 0x04),
            RM_REPEATED_MEASUREMENTS: bool(byte0 & 0x08),
            RM_BEACON_PASSIVE_MEASUREMENT: bool(byte0 & 0x10),
            RM_BEACON_ACTIVE_MEASUREMENT: bool(byte0 & 0x20),
            RM_BEACON_TABLE_MEASUREMENT: bool(byte0 & 0x40),
            RM_BEACON_MEASUREMENT_REPORTING: bool(byte0 & 0x80)
        }
        
        byte1_parsed = {
            RM_FRAME_MEASUREMENT: bool(byte1 & 0x01),
            RM_CHANNEL_LOAD_MEASUREMENT: bool(byte1 & 0x02),
            RM_NOISE_HISTOGRAM_MEASUREMENT: bool(byte1 & 0x04),
            RM_STATISTICS_MEASUREMENT: bool(byte1 & 0x08),
            RM_LCI_MEASUREMENT: bool(byte1 & 0x10),
            RM_LCI_AZIMUTH: bool(byte1 & 0x20),
            RM_TX_STREAM_CATEGORY_MEASUREMENT: bool(byte1 & 0x40),
            RM_TRIGGERED_TX_STREAM_MEASUREMENT: bool(byte1 & 0x80)
        }
        
        return {
            RM_BYTE0: byte0_parsed,
            RM_BYTE1: byte1_parsed
        }
    
    return unpack(RM_CAPS_FMT, parser=_parser)

def extended_capabilities(tag_length: int, **kwargs) -> dict:
    ctx = ParseContext.current()
    end = ctx.offset + tag_length
    
    def _parser_byte0(value: int, **kwargs) -> dict:
        bss_coexistence = bool(value & 0x01)
        extended_channel_switching = bool(value & 0x04)
        psmp_capability = bool(value & 0x10)
        
        return {
            EXT_CAPS_BSS_COEXISTENCE: bss_coexistence,
            EXT_CAPS_EXTENDED_CHANNEL_SWITCHING: extended_channel_switching,
            EXT_CAPS_PSMP_CAPABILITY: psmp_capability
        }
    
    def _parser_byte2(value: int, **kwargs) -> dict:
        return {EXT_CAPS_BSS_TRANSITION: bool(value & 0x08)}
    
    def _parser_byte3(value: int, **kwargs) -> dict:
        return {EXT_CAPS_INTERWORKING: bool(value & 0x80)}
    
    ext_caps = {}
    
    if tag_length >= 1:
        byte0 = unpack(BYTE_FMT, parser=_parser_byte0)
        ext_caps[PARSED_BYTE0] = byte0
    
    if tag_length >= 2:
        unpack(BYTE_FMT)  # Skip byte 1
    
    if tag_length >= 3:
        byte2 = unpack(BYTE_FMT, parser=_parser_byte2)
        ext_caps[PARSED_BYTE2] = byte2
    
    if tag_length >= 4:
        byte3 = unpack(BYTE_FMT, parser=_parser_byte3)
        ext_caps[PARSED_BYTE3] = byte3
    
    # Consume remaining bytes
    remaining = end - ctx.offset
    if remaining > 0:
        unpack(f"{remaining}s")
    
    return ext_caps

def qbss_load_element(tag_length: int, **kwargs) -> dict:
    if tag_length < QBSS_LOAD_LEN:
        return {}
    
    def _parser(values: tuple, **kwargs) -> dict:
        station_count, channel_utilization, available_admission_capacity = values
        
        return {
            QBSS_LOAD_STATION_COUNT: station_count,
            QBSS_LOAD_CHANNEL_UTILIZATION: channel_utilization,
            QBSS_LOAD_AVAILABLE_ADMISSION_CAPACITY: available_admission_capacity
        }
    
    return unpack(QBSS_LOAD_FMT, parser=_parser)

def power_constraint(tag_length: int, **kwargs) -> int:
    return unpack(BYTE_FMT)

def tcp_report(tag_length: int, **kwargs) -> dict:
    def _parser(values: tuple, **kwargs) -> dict:
        tx_power, reserved = values
        
        return {
            TCP_REPORT_TX_POWER: tx_power,
            TCP_REPORT_RESERVED: reserved
        }
    
    return unpack(TPC_REPORT_FMT, parser=_parser)

def current_channel(tag_length: int, **kwargs) -> int:
    return unpack(BYTE_FMT)

def rsn_information(tag_length: int, **kwargs) -> dict:
    if tag_length < RSN_MIN_LEN:
        return {}
    
    ctx = ParseContext.current()
    end = ctx.offset + tag_length
    result = {}
    
    if ctx.offset + 2 <= end:
        result[RSN_INFO_RSN_VERSION] = unpack(RSN_VERSION_FMT)
    
    if ctx.offset + 4 <= end:
        def _group_parser(value: tuple, **kwargs):
            oui, ctype = value
            oui = bytes_for_oui(oui)
            return {
                **oui, 
                RSN_INFO_CIPHER_TYPE: ctype
            }
        result[RSN_INFO_GROUP_CIPHER] = unpack(RSN_CIPHER_FMT, parser=_group_parser)
    
    if ctx.offset + 2 <= end:
        def _pairwise_parser(pairwise_count: int, **kwargs):
            def __parser(value: tuple, **kwargs):
                oui, ctype = value
                oui = bytes_for_oui(oui)
                return {
                    **oui,
                    RSN_INFO_CIPHER_TYPE: ctype
                }
                
            pairwise_ciphers = {}
            for i in range(pairwise_count):
                if ctx.offset + OUI_LENGTH + 1 <= end:
                    pairwise_cipher_result = unpack(RSN_CIPHER_FMT, parser=__parser)
                    pairwise_ciphers[i] = pairwise_cipher_result
            return pairwise_ciphers
            
        result[RSN_INFO_PAIRWISE_CIPHERS] = unpack(RSN_VERSION_FMT, parser=_pairwise_parser)
    
    if ctx.offset + 2 <= end:
        def _akm_parser(akm_count: int, **kwargs):
            def __akm_item_parser(value: tuple, **kwargs):
                oui, a_type = value
                oui = bytes_for_oui(oui)
                return {
                    **oui,
                    RSN_INFO_AKM_TYPE: a_type
                }
            
            akm_suites = {}
            for i in range(akm_count):
                if ctx.offset + 4 <= end:
                    akm_suite_result = unpack(RSN_AKM_FMT, parser=__akm_item_parser)
                    akm_suites[i] = akm_suite_result
            return akm_suites

        result[RSN_INFO_AKM_SUITES] = unpack(RSN_VERSION_FMT, parser=_akm_parser)
        if result[RSN_INFO_AKM_SUITES]:
            result[RSN_INFO_AKM_SUITE_COUNT] = len(result[RSN_INFO_AKM_SUITES])
    
    if ctx.offset + 2 <= end:
        result[RSN_INFO_CAPABILITIES] = unpack(RSN_CAPS_FMT, parser=_parse_rsn_capabilities)
    
    if ctx.offset + 2 <= end:
        def _pmkid_parser(pmkid_count: int, **kwargs):
            pmkids = {}
            for i in range(pmkid_count):
                if ctx.offset + EAPOL_PMKID_LENGTH <= end:
                    pmkid_result = unpack(RSN_PMKID_FMT)
                    pmkids[i] = pmkid_result
            return pmkids

        result[RSN_INFO_PMKIDS] = unpack(RSN_VERSION_FMT, parser=_pmkid_parser)
        if result[RSN_INFO_PMKIDS]:
            result[RSN_INFO_PMKID_COUNT] = len(result[RSN_INFO_PMKIDS])
            
    return result

def _parse_rsn_capabilities(value: int, **kwargs) -> dict:
    pre_auth = bool(value & 0x0001)
    no_pairwise = bool(value & 0x0002)
    ptksa_replay_counter = (value >> 2) & 0x03
    gtksa_replay_counter = (value >> 4) & 0x03
    mgmt_frame_protection_required = bool(value & 0x0040)
    mgmt_frame_protection_capable = bool(value & 0x0080)
    joint_multi_band_rsna = bool(value & 0x0100)
    peerkey_enabled = bool(value & 0x0200)
    spp_amsdu_capable = bool(value & 0x0400)
    spp_amsdu_required = bool(value & 0x0800)
    pbac = bool(value & 0x1000)
    extended_key_id = bool(value & 0x2000)
    ocvc = bool(value & 0x4000)
    reserved = bool(value & 0x8000)
    
    return {
        RSN_INFO_PRE_AUTH: pre_auth,
        RSN_INFO_NO_PAIRWISE: no_pairwise,
        RSN_INFO_PTKSA_REPLAY_COUNTER: ptksa_replay_counter,
        RSN_INFO_GTKSA_REPLAY_COUNTER: gtksa_replay_counter,
        RSN_INFO_MFP_REQUIRED: mgmt_frame_protection_required,
        RSN_INFO_MFP_CAPABLE: mgmt_frame_protection_capable,
        RSN_INFO_JOINT_MULTI_BAND_RSNA: joint_multi_band_rsna,
        RSN_INFO_PEERKEY_ENABLED: peerkey_enabled,
        RSN_INFO_SPP_AMSDU_CAPABLE: spp_amsdu_capable,
        RSN_INFO_SPP_AMSDU_REQUIRED: spp_amsdu_required,
        RSN_INFO_PBAC: pbac,
        RSN_INFO_EXTENDED_KEY_ID: extended_key_id,
        RSN_INFO_OCVC: ocvc,
        RSN_INFO_RESERVED_BIT: reserved
    }

def _get_extension_name(ext_id: int) -> str:
    extensions = {
        EXT_HE_CAPABILITIES: EXT_HE_CAPABILITIES_NAME,
        EXT_HE_OPERATION: EXT_HE_OPERATION_NAME,
        EXT_HE_UORA_PARAMETER_SET: EXT_HE_UORA_PARAMETER_SET_NAME,
        EXT_HE_SHORT_BEACON_INTERVAL: EXT_HE_SHORT_BEACON_INTERVAL_NAME,
        EXT_HE_EHT_CAPABILITIES: EXT_HE_EHT_CAPABILITIES_NAME
    }
    return extensions.get(ext_id)

def tag_extended_he(tag_length: int, **kwargs) -> dict:
    def _parser(value: tuple, **kwargs):
        ext_tag_id, data = value
        logger.debug(f"_parser tag_extended_he\n{value}")
        return {
            EXTENSION_ID: ext_tag_id,
            EXTENSION_NAME: _get_extension_name(ext_tag_id),
            DATA: data
        }

    if tag_length < EXTENDED_HE_MIN_LEN:
        return {}
    
    return unpack(f"{BYTE_FMT}{tag_length - 1}s", parser=_parser)

IE_DISPATCH = {
    TAG_SSID: {
        NAME: TAG_SSID_NAME,
        DESCRIPTION: "SSID (Service Set Identifier)",
        PARSER: ssid
    },
    TAG_SUPPORTED_RATES: {
        NAME: TAG_SUPPORTED_RATES_NAME,
        DESCRIPTION: "Supported Rates",
        PARSER: rates
    },
    TAG_CURRENT_CHANNEL: {
        NAME: TAG_CURRENT_CHANNEL_NAME,
        DESCRIPTION: "Current Channel",
        PARSER: current_channel
    },
    TAG_TIM: {
        NAME: TAG_TIM_NAME,
        DESCRIPTION: "Traffic Indication Map",
        PARSER: tim_info
    },
    TAG_COUNTRY: {
        NAME: TAG_COUNTRY_NAME,
        DESCRIPTION: "Country",
        PARSER: country_code
    },
    TAG_QBSS_LOAD: {
        NAME: TAG_QBSS_LOAD_NAME,
        DESCRIPTION: "QBSS (QoS Enhanced Basic Service Set) Load Element",
        PARSER: qbss_load_element
    },
    TAG_POWER_CONSTRAINT: {
        NAME: TAG_POWER_CONSTRAINT_NAME,
        DESCRIPTION: "Power Constraint",
        PARSER: power_constraint
    },
    TAG_TPC_REPORT: {
        NAME: TAG_TPC_REPORT_NAME,
        DESCRIPTION: "TPC (Transmit Power Control) Report",
        PARSER: tcp_report
    },
    TAG_ERP: {
        NAME: TAG_ERP_NAME,
        DESCRIPTION: "ERP (Extended Rate Physical Layer) Information",
        PARSER: erp_info
    },
    TAG_EXTENDED_SUPPORTED_RATES: {
        NAME: TAG_EXTENDED_SUPPORTED_RATES_NAME,
        DESCRIPTION: "Extended Supported Rates",
        PARSER: rates
    },
    TAG_VENDOR_SPECIFIC: {
        NAME: TAG_VENDOR_SPECIFIC_NAME,
        DESCRIPTION: "Vendor Specific",
        PARSER: vendor_specific
    },
    TAG_HT_CAPABILITIES: {
        NAME: TAG_HT_CAPABILITIES_NAME,
        DESCRIPTION: "HT (High Throughput) Capabilities",
        PARSER: ht_capabilities
    },
    TAG_RM_ENABLED_CAPABILITIES: {
        NAME: TAG_RM_ENABLED_CAPABILITIES_NAME,
        DESCRIPTION: "RM (Radio Measurement) Enabled Capabilities",
        PARSER: rm_enable_capabilities
    },
    TAG_RSN_INFORMATION: {
        NAME: TAG_RSN_INFORMATION_NAME,
        DESCRIPTION: "RSN (Robust Security Network) Information",
        PARSER: rsn_information
    },
    TAG_EXTENDED_CAPABILITIES: {
        NAME: TAG_EXTENDED_CAPABILITIES_NAME,
        DESCRIPTION: "Extended Capabilities",
        PARSER: extended_capabilities
    },
    TAG_EXTENDED_HE: {
        NAME: TAG_EXTENDED_HE_NAME,
        DESCRIPTION: "(Wifi 6) High Efficiency (HE)",
        PARSER: tag_extended_he
    }
}

def ie_dispatch(value: tuple, **kwargs) -> dict:
    def _fallback(tag_length: int, **k):
        return unpack(f"{tag_length}s")

    ie_result = {}
    tag_number, tag_length = value

    ctx = ParseContext.current()
    start_offset = ctx.offset
    expected_end = start_offset + tag_length

    try:
        entry = IE_DISPATCH.get(tag_number, {})
        ie_result = {
            TAG_NUMBER: tag_number,
            TAG_LENGTH: tag_length,
            NAME: entry.get(NAME),
            DESCRIPTION: entry.get(DESCRIPTION)
        }
        ie_result[DATA] = run_dispatch(
            IE_DISPATCH,
            tag_number,
            fallback=_fallback,
            tag_length=tag_length
        )

    except Exception as e:
        logger.debug(f"IE parser error for tag {tag_number} value={value} entry={entry} : {e}")

    finally:
        if ctx.offset != expected_end:
            logger.debug(
                f"IE tag {tag_number} offset drift: expected={expected_end} got={ctx.offset} "
                f"(drift={ctx.offset - expected_end:+d})"
            )
            ctx.offset = min(expected_end, len(ctx.frame))

    return ie_result
