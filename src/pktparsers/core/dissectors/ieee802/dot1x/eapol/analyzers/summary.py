def summarizer(parser_result: dict) -> dict:
    def _classify_eapol_message(parser_result: dict) -> int:
        ki = eapol.get("key_information", {})
        ack  = ki.get("key_ack", False)
        mic  = ki.get("key_mic", False)
        inst = ki.get("install", False)
        sec  = ki.get("secure", False)
        enc  = ki.get("encrypted_key_data", False)
        klen = eapol.get("key_data_length", 0)
    
        if     ack and not mic and not sec:  return 1  # AP → STA, ANonce
        if not ack and     mic and not sec:  return 2  # STA → AP, SNonce + MIC
        if     ack and     mic and inst:     return 3  # AP → STA, GTK cifrado
        if not ack and     mic and sec:      return 4  # STA → AP, confirmação

        return 0

    eapol_msg = _classify_eapol_message(parser_result)

    """
    version_map = {
        0: "reserved(0)",
        1: "HMAC_MD5_ARC4_WPA1",
        2: "HMAC_SHA1_128_AES_WPA2_RSN",
        3: "AES_128_CMAC_AES_128_GCMP_WPA3",
        **{i: f"reserved({i})" for i in range(4, 8)},
    }

    key_description_version = parser_result.get()
    """

    ki = parser_result["key_information"]
    enc = "WPA3" if parser_result["authentication_version"] == 3 else \
          "WPA2/RSN" if parser_result["authentication_version"] == 2 else "WPA1"

    kd_ver = ki["key_descriptor_version"]["value"]
    cipher_desc = {
        1: "RC4 (WPA1/TKIP)",
        2: "AES-CCM (WPA2/CCMP)",
        3: "AES-GCM (WPA3/GCMP)"
    }.get(kd_ver, f"unknown({kd_ver})")

    msg_desc = {
        1: "AP → STA: ANonce (início do 4-way handshake)",
        2: "STA → AP: SNonce + MIC (resposta com credencial)",
        3: "AP → STA: GTK cifrado (instalação de chave)",
        4: "STA → AP: Confirmação (handshake completo)",
    }.get(eapol_msg, "Mensagem EAPOL desconhecida")

    flags = []
    if eapol_msg in (1, 2):
        flags.append("HANDSHAKE_CAPTURABLE")   # par M1+M2 → hashcat 22000
    if ki.get("encrypted_key_data"):
        flags.append("KEY_DATA_ENCRYPTED")
    if not ki.get("key_mic") and eapol_msg == 1:
        flags.append("NO_MIC")                 # esperado no msg1

    return {
        "summary": f"EAPOL Key (Message {eapol_msg} of 4) [{enc}]",
        "details": {
            "message": eapol_msg,
            "encryption": enc,
            "cipher_suite": cipher_desc,
            "direction": "AP→STA" if eapol_msg in (1, 3) else "STA→AP",
        },
        "flags": flags
    }
