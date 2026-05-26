def make_tls_credentials(
    keylog_file: str = "",
    session_keys: Optional[dict] = None,
) -> dict:
    """
    Build a TLS credentials entry for credentials["tls"].

    NSS Key Log format (compatible with Wireshark):
        CLIENT_RANDOM <client_random_hex> <master_secret_hex>

    Args:
        keylog_file:  path to NSS keylog file on disk
        session_keys: inline dict {"CLIENT_RANDOM hex": "master_secret hex"}
    """
    entry: dict[str, Any] = {}
    if keylog_file:
        entry["keylog_file"] = keylog_file
    if session_keys:
        entry["session_keys"] = session_keys
    return entry

