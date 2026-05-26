def make_ipsec_credentials(spi_hex: str = "", esp_key: str = "", auth_key: str = "") -> dict:
    """
    Build an IPsec credentials entry for credentials["ipsec"][spi_hex].
    """
    entry: dict[str, Any] = {}
    if esp_key:
        entry["esp_key"] = esp_key
    if auth_key:
        entry["auth_key"] = auth_key
    return entry

