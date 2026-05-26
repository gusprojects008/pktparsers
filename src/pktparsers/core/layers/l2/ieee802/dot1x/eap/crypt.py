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
    entry: dict[str, Any] = {}
    if method:
        entry["method"] = method
    if identity:
        entry["identity"] = identity
    if password:
        entry["password"] = password
    if ca_cert:
        entry["ca_cert"] = ca_cert
    return entry
