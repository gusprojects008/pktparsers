def make_radius_credentials(server_ip: str = "", secret: str = "") -> dict:
    """
    Build a RADIUS shared secret entry for credentials["radius"][server_ip].

    Keyed by server IP — a given RADIUS server may serve multiple SSIDs.
    """
    entry: dict[str, Any] = {}
    if secret:
        entry["secret"] = secret
    return entry
