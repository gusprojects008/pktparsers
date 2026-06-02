def make_eap_credentials(
    bssid: str = "",
    method: str = "",
    identity: str = "",
    password: str = "",
    ca_cert: str = "",
) -> dict:
    """
    Build an EAP/Enterprise credentials entry for credentials["eap"][bssid].

    Keyed by BSSID because EAP Enterprise is negotiated per-AP.
    The decrypted EAPOL payload is handed here after dot11/crypt.py removes
    the CCMP/TKIP wrapper.
    """
    return {
        METHOD: method,
        IDENTITY: identity,
        PASSWORD: password,
        CA_CERT: ca_cert
    }
